//! Background driver for [`crate::Db::sweep_expired_messages`]. That
//! function's own doc comment has always said it's "for a caller, e.g. the
//! eventual Tauri shell, to call periodically" — this is that caller,
//! built now so it's ready as a one-line call once a real shell exists,
//! and tested independently of one. Mirrors
//! `dratchet_server::pruning::spawn_pruning_sweep`'s shape exactly (same
//! parameterized-interval-for-testability pattern).

use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinHandle;

use crate::db::Db;

/// Spawn a background task that calls `Db::sweep_expired_messages` every
/// `interval` for the life of the task. `interval` is a parameter (not a
/// baked-in constant) so tests can drive this with short durations instead
/// of whatever real-world interval a caller picks.
pub fn spawn_periodic_sweep(db: Arc<Db>, interval: Duration) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            match db.sweep_expired_messages() {
                Ok(swept) => {
                    tracing::debug!(messages_swept = swept, "pruning sweep completed");
                }
                Err(e) => {
                    tracing::warn!(error = %e, "pruning sweep failed");
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::Message;

    fn temp_db() -> Db {
        let dir = tempfile::tempdir().unwrap().keep();
        Db::create(dir.join("test.redb"), "pw").unwrap()
    }

    fn expired_message() -> Message {
        Message {
            id: vec![7u8; 16],
            sender_is_local: true,
            content: b"gone soon".to_vec(),
            timestamp: 100,
            expires_at: Some(0), // already in the past
        }
    }

    #[tokio::test]
    async fn a_message_that_is_never_read_is_still_pruned_by_the_periodic_sweep() {
        let db = Arc::new(temp_db());
        let conv = [3u8; 16];
        let message = expired_message();
        db.save_message(conv, &message).unwrap();

        let key = format!(
            "message:{}:{}",
            crate::db::hex(&conv),
            crate::db::hex(&message.id)
        );
        assert!(
            db.get_encrypted(&key).unwrap().is_some(),
            "sanity check: the message should be present immediately after the write"
        );

        spawn_periodic_sweep(db.clone(), Duration::from_millis(20));

        // Past several sweep intervals — and deliberately never calling
        // `list_messages` (that would trigger the *other*, already-tested
        // sweep-on-read path), so only the periodic sweep can be
        // responsible for this passing.
        tokio::time::sleep(Duration::from_millis(200)).await;

        assert!(
            db.get_encrypted(&key).unwrap().is_none(),
            "a message that's never read must still be pruned by the periodic sweep"
        );
    }
}
