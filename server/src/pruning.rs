//! Periodic background cleanup of state that grows purely from
//! implementation bookkeeping, not from anything `docs/SERVERS.md`/
//! `docs/ARCHITECTURE.md` documents as intentionally persistent.
//!
//! **Deliberately out of scope**: `presence`, `subscriptions`, and
//! `fetch_evidence` are never touched here. `docs/SERVERS.md` §1.3
//! documents that a disconnected identity's `last_seen` is retained, and
//! `subscriptions`/`fetch_evidence` are keyed by identity (not by
//! connection) specifically so a relationship survives the subscriber's
//! own reconnects — pruning either would be a real behavior change against
//! documented intent, not a bug fix. `directory` is a directory;
//! unbounded-but-intentional, not a pruning target. Nothing in this module
//! logs presence state or mailbox/envelope content — see `ws.rs`'s new
//! logging for the same constraint applied there.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::task::JoinHandle;

use crate::state::{prune_expired, AppState};

/// Counts from one [`sweep_once`] pass, for its summary log line.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SweepSummary {
    pub mailbox_entries_pruned: usize,
    pub mailboxes_emptied: usize,
    pub rate_limit_buckets_pruned: usize,
}

/// One pruning pass: expire mailbox entries past their TTL (reusing
/// `state::prune_expired`, the same logic `ws.rs`'s `MailboxFetch` already
/// runs lazily), remove any mailbox whose entry list is now empty, and
/// sweep stale `FetchRateLimiter` buckets. Takes the state write lock once
/// for the whole pass.
pub async fn sweep_once(state: &AppState, rate_limit_bucket_stale_after: Duration) -> SweepSummary {
    let mut inner = state.inner.write().await;

    let mut mailbox_entries_pruned = 0;
    let mut mailboxes_emptied = 0;
    inner.mailboxes.retain(|_, entries| {
        let before = entries.len();
        prune_expired(entries);
        mailbox_entries_pruned += before - entries.len();
        let keep = !entries.is_empty();
        if !keep {
            mailboxes_emptied += 1;
        }
        keep
    });

    let rate_limit_buckets_pruned = inner
        .fetch_rate_limiter
        .sweep_stale(rate_limit_bucket_stale_after, Instant::now());

    SweepSummary {
        mailbox_entries_pruned,
        mailboxes_emptied,
        rate_limit_buckets_pruned,
    }
}

/// Spawn a background task that calls [`sweep_once`] every `sweep_interval`
/// for the life of the process. `sweep_interval` and
/// `rate_limit_bucket_stale_after` are parameters (not baked-in constants)
/// so tests can drive this with short durations instead of the real
/// minutes-scale values `main.rs` uses in production.
pub fn spawn_pruning_sweep(
    state: Arc<AppState>,
    sweep_interval: Duration,
    rate_limit_bucket_stale_after: Duration,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(sweep_interval);
        loop {
            ticker.tick().await;
            let summary = sweep_once(&state, rate_limit_bucket_stale_after).await;
            tracing::debug!(
                mailbox_entries_pruned = summary.mailbox_entries_pruned,
                mailboxes_emptied = summary.mailboxes_emptied,
                rate_limit_buckets_pruned = summary.rate_limit_buckets_pruned,
                "pruning sweep completed"
            );
        }
    })
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use super::*;
    use crate::state::{MailboxEntry, PresenceState};

    fn entry(expires_in: Duration) -> MailboxEntry {
        MailboxEntry {
            entry_id: [1u8; 16],
            envelope: vec![1, 2, 3],
            expires_at: SystemTime::now() + expires_in,
        }
    }

    fn expired_entry() -> MailboxEntry {
        MailboxEntry {
            entry_id: [2u8; 16],
            envelope: vec![4, 5, 6],
            // Already in the past.
            expires_at: SystemTime::now() - Duration::from_secs(1),
        }
    }

    #[tokio::test]
    async fn sweep_once_prunes_expired_entries_and_removes_an_emptied_mailbox() {
        let state = AppState::new();
        {
            let mut inner = state.inner.write().await;
            inner
                .mailboxes
                .insert([1u8; 16], vec![expired_entry(), expired_entry()]);
        }

        let summary = sweep_once(&state, Duration::from_secs(600)).await;
        assert_eq!(summary.mailbox_entries_pruned, 2);
        assert_eq!(summary.mailboxes_emptied, 1);

        let inner = state.inner.read().await;
        assert!(
            !inner.mailboxes.contains_key(&[1u8; 16]),
            "an emptied mailbox key must be removed entirely, not left as an empty Vec"
        );
    }

    #[tokio::test]
    async fn sweep_once_leaves_a_mailbox_with_still_valid_entries_untouched() {
        let state = AppState::new();
        {
            let mut inner = state.inner.write().await;
            inner.mailboxes.insert(
                [1u8; 16],
                vec![entry(Duration::from_secs(600)), expired_entry()],
            );
        }

        let summary = sweep_once(&state, Duration::from_secs(600)).await;
        assert_eq!(summary.mailbox_entries_pruned, 1);
        assert_eq!(summary.mailboxes_emptied, 0);

        let inner = state.inner.read().await;
        assert_eq!(
            inner.mailboxes.get(&[1u8; 16]).map(Vec::len),
            Some(1),
            "the still-valid entry must survive; only the expired one is pruned"
        );
    }

    /// Regression guard: a sweep must never touch the maps this project has
    /// deliberately decided to leave alone (see this module's doc comment).
    #[tokio::test]
    async fn sweep_once_never_touches_presence_subscriptions_fetch_evidence_or_the_directory() {
        let state = AppState::new();
        let fp = [7u8; 32];
        let subscriber = [8u8; 32];
        {
            let mut inner = state.inner.write().await;
            inner.presence.insert(
                fp,
                PresenceState::Offline {
                    last_seen: crate::state::now_unix(),
                },
            );
            inner
                .subscriptions
                .entry(fp)
                .or_default()
                .insert(subscriber);
            inner
                .fetch_evidence
                .entry(subscriber)
                .or_default()
                .insert(fp);
            inner.otp_exhaustion_attempts.insert(fp, 3);
        }

        sweep_once(&state, Duration::from_secs(600)).await;

        let inner = state.inner.read().await;
        assert_eq!(inner.presence.len(), 1);
        assert_eq!(inner.subscriptions.get(&fp).map(|s| s.len()), Some(1));
        assert_eq!(
            inner.fetch_evidence.get(&subscriber).map(|s| s.len()),
            Some(1)
        );
        assert_eq!(inner.otp_exhaustion_attempts.get(&fp), Some(&3));
    }
}
