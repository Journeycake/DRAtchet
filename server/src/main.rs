use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;

/// DRAtchet Signaling & Presence Service (docs/SERVERS.md §1) — prekey
/// directory, WebRTC rendezvous, Tier 1 mailbox, and presence over one
/// WebSocket endpoint. See server/README.md for installation and operation.
#[derive(Parser, Debug)]
#[command(name = "dratchetd", version, about)]
struct Args {
    /// Settings file (TOML). Defaults to ./dratchet.cfg if it exists;
    /// naming one that doesn't exist is an error. Flags and environment
    /// variables override it.
    #[arg(long, env = "DRATCHETD_CONFIG")]
    config: Option<PathBuf>,

    /// Address to bind the HTTP/WebSocket listener to (default 127.0.0.1:8787).
    #[arg(long, env = "DRATCHETD_BIND")]
    bind: Option<String>,

    /// Where the directory (username#NNNN -> bundle) is persisted, so a
    /// restart doesn't forget every registration (ARCHITECTURE.md §6.1).
    /// Point this at a path on a volume that survives a restart/reschedule
    /// (a container's own ephemeral filesystem does not). Default
    /// dratchetd-directory.redb.
    #[arg(long, env = "DRATCHETD_DIRECTORY_DB")]
    directory_db: Option<PathBuf>,

    /// Comma-separated CIDR ranges of reverse proxies in front of this
    /// server (e.g. an Ingress controller's pod range). Only connections
    /// from these addresses have their X-Forwarded-For header believed
    /// when applying per-address connection limits (DRA-0055). Leave empty
    /// when clients connect directly (NodePort, LoadBalancer without a
    /// proxy); the TCP peer address is then used and can't be spoofed.
    #[arg(long, env = "DRATCHETD_TRUSTED_PROXIES")]
    trusted_proxies: Option<String>,

    /// Save queued mail to an encrypted, fragmented store on disk
    /// (docs/adr/0001). Off by default, except on hosts with under 2 GB
    /// of usable memory. Needs a key and at least two fragment directories.
    #[arg(long, env = "DRATCHETD_PERSIST_MAILBOXES")]
    persist_mailboxes: Option<bool>,

    /// A directory for mail store Fragments; give at least two, ideally on
    /// different volumes. Repeat the flag for each.
    #[arg(
        long = "fragment-dir",
        env = "DRATCHETD_FRAGMENT_DIRS",
        value_delimiter = ','
    )]
    fragment_dirs: Vec<PathBuf>,

    /// The mail store's encrypted index (default dratchetd-mailbox-index.redb).
    #[arg(long, env = "DRATCHETD_MAILBOX_INDEX_DB")]
    mailbox_index_db: Option<PathBuf>,

    /// Seconds between saves of queued mail, 0-15 (default 10; 0 saves on
    /// every write). A sender's checkmark waits for the next save.
    #[arg(long, env = "DRATCHETD_FLUSH_INTERVAL")]
    flush_interval: Option<u64>,

    /// Most bytes of unsaved queued mail held in memory (default a tenth
    /// of usable memory). Half of it triggers an early save.
    #[arg(long, env = "DRATCHETD_MEMORY_LIMIT")]
    memory_limit: Option<u64>,

    /// File holding the mail store key: 64 hex characters, readable only
    /// by its owner. DRATCHETD_MAILBOX_KEY takes precedence.
    #[arg(long, env = "DRATCHETD_MAILBOX_KEY_FILE")]
    mailbox_key_file: Option<PathBuf>,
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
    let file = dratchet_server::config::load_file(args.config.as_deref())
        .unwrap_or_else(|e| panic!("{e}"));
    let env_key = std::env::var(dratchet_server::config::KEY_ENV).ok();
    let settings = dratchet_server::config::resolve(
        dratchet_server::config::Overrides {
            bind: args.bind,
            directory_db: args.directory_db,
            trusted_proxies: args.trusted_proxies,
            persist_mailboxes: args.persist_mailboxes,
            fragment_dirs: args.fragment_dirs,
            mailbox_index_db: args.mailbox_index_db,
            flush_interval: args.flush_interval,
            memory_limit: args.memory_limit,
            mailbox_key_file: args.mailbox_key_file,
        },
        file,
        dratchet_server::config::usable_memory(),
        env_key.as_deref(),
    )
    .unwrap_or_else(|e| panic!("dratchetd cannot start: {e}"));

    let trusted_proxies =
        dratchet_server::address::TrustedProxies::parse_list(&settings.trusted_proxies)
            .unwrap_or_else(|e| panic!("invalid trusted_proxies: {e}"));
    let (router, state) = match &settings.persistence {
        Some(mail) => dratchet_server::app_with_mail_store(
            Some(&settings.directory_db),
            mail,
            settings.memory_limit,
        )
        .unwrap_or_else(|e| panic!("failed to open the mail store: {e}")),
        None => {
            let (router, state) = dratchet_server::app_with_directory_db(&settings.directory_db)
                .unwrap_or_else(|e| {
                    panic!(
                        "failed to open the directory database at {}: {e}",
                        settings.directory_db.display()
                    )
                });
            (router, state)
        }
    };
    if !trusted_proxies.is_empty() {
        tracing::info!(
            "per-address limits will read X-Forwarded-For from: {}",
            settings.trusted_proxies
        );
    }
    if settings.persistence.is_some() {
        tracing::info!(
            memory_limit = settings.memory_limit,
            "mailbox persistence on (docs/adr/0001)"
        );
    }
    *state.trusted_proxies.write().expect("trusted proxies lock") = trusted_proxies;
    dratchet_server::pruning::spawn_pruning_sweep(
        state.clone(),
        PRUNING_SWEEP_INTERVAL,
        RATE_LIMIT_BUCKET_STALE_AFTER,
    );

    let listener = tokio::net::TcpListener::bind(&settings.bind)
        .await
        .unwrap_or_else(|e| panic!("failed to bind {}: {e}", settings.bind));
    tracing::info!("dratchetd listening on {}", settings.bind);
    tracing::info!("WebSocket endpoint: ws://{}/v1/ws", settings.bind);

    // DRA-0055: connect info carries each connection's peer address to
    // `ws_handler` for the per-address limits.
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .expect("server error");
    // docs/adr/0001: a last save, and the clean-shutdown record that lets
    // the next start keep the same server epoch.
    dratchet_server::flush::shutdown(&state).await;
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
