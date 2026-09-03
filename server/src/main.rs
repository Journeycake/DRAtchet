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

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to listen for ctrl-c");
    tracing::info!("shutting down");
}
