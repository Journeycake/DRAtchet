use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;

/// DRAtchet Signaling & Presence Service (docs/SERVERS.md §1) — prekey
/// directory, WebRTC rendezvous, Tier 1 mailbox, and presence over one
/// WebSocket endpoint. See server/README.md for installation and operation.
#[derive(Parser, Debug)]
#[command(name = "dratchetd", version, about)]
struct Args {
    /// Address to bind the HTTP/WebSocket listener to.
    #[arg(long, default_value = "127.0.0.1:8787", env = "DRATCHETD_BIND")]
    bind: String,

    /// Where the directory (username#NNNN -> bundle) is persisted, so a
    /// restart doesn't forget every registration (ARCHITECTURE.md §6.1).
    /// Mailboxes/presence/subscriptions are never persisted here or
    /// anywhere else — see server/src/persistence.rs's module doc.
    /// Point this at a path on a volume that survives a restart/reschedule
    /// (a container's own ephemeral filesystem does not); the chart's own
    /// values.yaml does not mount one yet, so a Helm-deployed instance
    /// still loses its directory across a pod reschedule until it does.
    #[arg(
        long,
        default_value = "dratchetd-directory.redb",
        env = "DRATCHETD_DIRECTORY_DB"
    )]
    directory_db: PathBuf,

    /// Comma-separated CIDR ranges of reverse proxies in front of this
    /// server (e.g. an Ingress controller's pod range). Only connections
    /// from these addresses have their X-Forwarded-For header believed
    /// when applying per-address connection limits (DRA-0055). Leave empty
    /// when clients connect directly (NodePort, LoadBalancer without a
    /// proxy); the TCP peer address is then used and can't be spoofed.
    #[arg(long, default_value = "", env = "DRATCHETD_TRUSTED_PROXIES")]
    trusted_proxies: String,
}

/// How often the background pruning sweep (`dratchet_server::pruning`)
/// runs, and how long a `FetchRateLimiter` bucket must sit idle before
/// that sweep removes it. Not exposed as a setting (see `server/README.md`'s
/// Configuration section) — these are memory-hygiene internals with no
/// externally-observable correctness effect, the same category as
/// `abuse.rs`'s already-hardcoded rate-limit/PoW constants.
const PRUNING_SWEEP_INTERVAL: Duration = Duration::from_secs(300);
const RATE_LIMIT_BUCKET_STALE_AFTER: Duration = Duration::from_secs(600);

#[tokio::main]
async fn main() {
    // `RUST_LOG` when set and valid; "info" otherwise. Previously this
    // always layered an `INFO` floor on top of `RUST_LOG` via
    // `add_directive`, which (per `tracing_subscriber::EnvFilter`'s
    // last-directive-wins-at-equal-specificity rule) silently won out over
    // a bare `RUST_LOG=debug`/`trace` — making it impossible to ever see
    // below `INFO` no matter what `RUST_LOG` said.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    let trusted_proxies =
        dratchet_server::address::TrustedProxies::parse_list(&args.trusted_proxies)
            .unwrap_or_else(|e| panic!("invalid --trusted-proxies: {e}"));
    let (router, state) = dratchet_server::app_with_directory_db(&args.directory_db)
        .unwrap_or_else(|e| {
            panic!(
                "failed to open the directory database at {}: {e}",
                args.directory_db.display()
            )
        });
    if !trusted_proxies.is_empty() {
        tracing::info!(
            "per-address limits will read X-Forwarded-For from: {}",
            args.trusted_proxies
        );
    }
    *state.trusted_proxies.write().expect("trusted proxies lock") = trusted_proxies;
    dratchet_server::pruning::spawn_pruning_sweep(
        state,
        PRUNING_SWEEP_INTERVAL,
        RATE_LIMIT_BUCKET_STALE_AFTER,
    );

    let listener = tokio::net::TcpListener::bind(&args.bind)
        .await
        .unwrap_or_else(|e| panic!("failed to bind {}: {e}", args.bind));
    tracing::info!("dratchetd listening on {}", args.bind);
    tracing::info!("WebSocket endpoint: ws://{}/v1/ws", args.bind);

    // DRA-0055: connect info carries each connection's peer address to
    // `ws_handler` for the per-address limits.
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .expect("server error");
}

/// Waits for either Ctrl-C (`SIGINT`, local/interactive use) or `SIGTERM`
/// (what a container orchestrator sends on pod/container shutdown — `docker
/// stop`, a Kubernetes pod eviction or rolling update). Without the `SIGTERM`
/// arm, `axum::serve`'s graceful shutdown would never trigger under an
/// orchestrator: it would sit until the terminationGracePeriod elapsed and
/// then get force-killed, dropping in-flight WebSocket connections instead
/// of finishing them cleanly.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to listen for ctrl-c");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => tracing::info!("received SIGINT, shutting down"),
        _ = terminate => tracing::info!("received SIGTERM, shutting down"),
    }
}
