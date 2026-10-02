//! DRAtchet Signaling & Presence Service — `docs/SERVERS.md` §1.
//!
//! Exposes [`app`] (an [`axum::Router`] builder) so both the real binary
//! (`src/main.rs`) and integration tests can mount the same service, either
//! bound to a real port or driven in-process.

pub mod abuse;
pub mod address;
pub mod config;
pub mod error;
pub mod flush;
pub mod mailstore;
pub mod persistence;
pub mod protocol;
pub mod pruning;
pub mod state;
#[cfg(feature = "wizard")]
pub mod wizard;
pub mod ws;

use std::path::Path;
use std::sync::Arc;

use axum::routing::get;
use axum::Router;

use state::AppState;

/// Build the service's router over a fresh, empty [`AppState`] — one
/// process, one in-memory store, per `docs/SERVERS.md` §1.4. The
/// directory is not persisted; see [`app_with_directory_db`] for the
/// variant that closes `ARCHITECTURE.md` §6.1's restart/squatting gap.
/// Every existing test uses this constructor — none of their behavior
/// changes.
pub fn app() -> (Router, Arc<AppState>) {
    let state = AppState::new();
    let router = Router::new()
        .route("/v1/ws", get(ws::ws_handler))
        .route("/healthz", get(healthz))
        .with_state(state.clone());
    (router, state)
}

/// Like [`app`], but the directory (`username#NNNN` → bundle) is
/// recovered from `directory_db_path` at startup and every subsequent
/// registration/rotation/one-time-prekey-consumption is written through
/// to it — `persistence` for exactly what is and isn't durable here.
/// Only `src/main.rs`'s real binary calls this.
pub fn app_with_directory_db(
    directory_db_path: &Path,
) -> Result<(Router, Arc<AppState>), redb::DatabaseError> {
    let persistence = persistence::Persistence::open(directory_db_path)?;
    let state = AppState::with_persistence(persistence);
    let router = Router::new()
        .route("/v1/ws", get(ws::ws_handler))
        .route("/healthz", get(healthz))
        .with_state(state.clone());
    Ok((router, state))
}

async fn healthz() -> &'static str {
    "ok"
}

/// `docs/adr/0001`: like [`app_with_directory_db`] (or [`app`], without a
/// directory path), with queued mail persisted to an encrypted,
/// fragmented mail store, which is opened and rebuilt first. Starts the
/// save task, so it must be called inside a Tokio runtime.
pub fn app_with_mail_store(
    directory_db_path: Option<&Path>,
    mail: &config::MailPersistence,
    memory_limit: u64,
) -> Result<(Router, Arc<AppState>), String> {
    let directory = directory_db_path
        .map(persistence::Persistence::open)
        .transpose()
        .map_err(|e| format!("directory database: {e}"))?;
    let opened = mailstore::MailStore::open(&mail.index_db, &mail.fragment_dirs, &mail.key)
        .map_err(|e| e.to_string())?;
    let state = AppState::with_mail_store(directory, opened, mail.flush_interval, memory_limit);
    flush::spawn_flusher(state.clone());
    let router = Router::new()
        .route("/v1/ws", get(ws::ws_handler))
        .route("/healthz", get(healthz))
        .with_state(state.clone());
    Ok((router, state))
}
