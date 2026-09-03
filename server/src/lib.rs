//! DRAtchet Signaling & Presence Service — `docs/SERVERS.md` §1.
//!
//! Exposes [`app`] (an [`axum::Router`] builder) so both the real binary
//! (`src/main.rs`) and integration tests can mount the same service, either
//! bound to a real port or driven in-process.

pub mod error;
pub mod protocol;
pub mod state;
pub mod ws;

use std::sync::Arc;

use axum::routing::get;
use axum::Router;

use state::AppState;

/// Build the service's router over a fresh, empty [`AppState`] — one
/// process, one in-memory store, per `docs/SERVERS.md` §1.4.
pub fn app() -> (Router, Arc<AppState>) {
    let state = AppState::new();
    let router = Router::new()
        .route("/v1/ws", get(ws::ws_handler))
        .route("/healthz", get(healthz))
        .with_state(state.clone());
    (router, state)
}

async fn healthz() -> &'static str {
    "ok"
}
