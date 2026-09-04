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
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    let args = Args::parse();
    let (router, _state) = dratchet_server::app();

    let listener = tokio::net::TcpListener::bind(&args.bind)
        .await
        .unwrap_or_else(|e| panic!("failed to bind {}: {e}", args.bind));
    tracing::info!("dratchetd listening on {}", args.bind);
    tracing::info!("WebSocket endpoint: ws://{}/v1/ws", args.bind);

    axum::serve(listener, router)
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
