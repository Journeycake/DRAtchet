//! Periodic background cleanup of state that grows purely from
//! implementation bookkeeping, not from anything `docs/SERVERS.md`/
//! `docs/ARCHITECTURE.md` documents as intentionally persistent.
//!
//! **Deliberately out of scope**: `subscriptions` and `fetch_evidence`
//! are never touched here. Both are keyed by identity (not by connection)
//! specifically so a relationship survives the subscriber's own
//! reconnects — pruning either would be a real behavior change against
//! documented intent, not a bug fix. `directory` is a directory;
//! unbounded-but-intentional, not a pruning target. Nothing in this module
//! logs presence state or mailbox/envelope content — see `ws.rs`'s new
//! logging for the same constraint applied there.
//!
//! **Throwaway identities are swept** (DRA-0044,
//! `docs/DELIVERY_FAILURE_FINDINGS.md`). Three maps are keyed by
//! identity and, before this, only ever grew: `presence` (written on
//! every authentication and again on every disconnect),
//! `fetch_evidence` (written by every `FetchBundle`), and the subscriber
//! sets inside `subscriptions`. Authenticating costs an attacker nothing
//! beyond a locally generated keypair and one signature — no
//! registration, no proof-of-work, no directory entry — so an attacker
//! cycling fresh identities grew all three without bound until the
//! process restarted. DRA-0031's connection cap bounds concurrent
//! sockets, not sequential reconnects, and each new identity also gets
//! fresh per-identity rate-limit buckets.
//!
//! [`sweep_once`] therefore drops per-identity state for an identity
//! that is **neither a directory resident nor currently connected** —
//! see [`identity_is_durable`]. That keeps `docs/SERVERS.md` §1.3's
//! retained `last_seen`, and the "a relationship survives the
//! subscriber's own reconnects" intent above, intact for every real
//! account: a real client publishes its bundle on startup
//! (`app::publish_under_candidates`), so it is a directory resident, and
//! `directory` is itself never pruned. A throwaway that published
//! nothing has no such anchor — and its retained state was unreadable
//! anyway, since `PresenceSubscribe` requires `fetch_evidence`, which
//! only a successful `FetchBundle` against a *published* bundle records.

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
    pub new_mailbox_rate_limit_buckets_pruned: usize,
    /// DRA-0044: `Offline` presence entries dropped for non-durable
    /// identities.
    pub presence_entries_pruned: usize,
    /// DRA-0044: `fetch_evidence` entries dropped for non-durable
    /// identities.
    pub fetch_evidence_entries_pruned: usize,
    /// DRA-0044: individual subscribers dropped from `subscriptions`
    /// because the *subscriber* is non-durable. Counts subscribers, not
    /// targets.
    pub stale_subscribers_pruned: usize,
}

/// DRA-0044: whether per-identity state for `fingerprint` is worth
/// keeping across the identity's disconnection.
///
/// "Durable" means the identity has an anchor an attacker cannot mint for
/// free: it published a bundle (so it is in the never-pruned `directory`
/// and other accounts can fetch and subscribe to it), or it is connected
/// right now. Everything else is a throwaway whose retained state nothing
/// can read back.
fn identity_is_durable(
    fingerprint: &crate::state::Fingerprint,
    directory: &std::collections::HashMap<crate::state::Fingerprint, crate::state::StoredBundle>,
    connections: &std::collections::HashMap<
        crate::state::Fingerprint,
        crate::state::OutboundSender,
    >,
) -> bool {
    directory.contains_key(fingerprint) || connections.contains_key(fingerprint)
}

/// One pruning pass: expire mailbox entries past their TTL (reusing
/// `state::prune_expired`, the same logic `ws.rs`'s `MailboxFetch` already
/// runs lazily), remove any mailbox whose entry list is now empty, and
/// sweep stale `FetchRateLimiter` buckets, and drop per-identity state
/// left behind by throwaway identities (DRA-0044 — see this module's
/// doc). Takes the state write lock once for the whole pass.
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

    // DRA-0044. Destructured rather than calling `inner.presence.retain`
    // directly, so each closure can read `directory`/`connections` while
    // the map it filters is mutably borrowed — disjoint fields of the
    // same struct.
    let (presence_entries_pruned, fetch_evidence_entries_pruned, stale_subscribers_pruned) = {
        let crate::state::Inner {
            presence,
            fetch_evidence,
            subscriptions,
            directory,
            connections,
            ..
        } = &mut *inner;

        let presence_before = presence.len();
        presence.retain(|fingerprint, presence_state| {
            // Only a disconnected identity's retained `last_seen` is in
            // scope here at all; `Online`/`Away` belong to a live
            // connection.
            if !matches!(presence_state, crate::state::PresenceState::Offline { .. }) {
                return true;
            }
            identity_is_durable(fingerprint, directory, connections)
        });

        let evidence_before = fetch_evidence.len();
        fetch_evidence
            .retain(|fingerprint, _| identity_is_durable(fingerprint, directory, connections));

        // A subscriber set is filtered by the *subscriber's* durability,
        // not the target's: a real account's presence must not keep
        // fanning out to throwaway watchers, which is both dead weight
        // and a per-notification cost `ws.rs` pays on every presence
        // change by cloning the set.
        let mut stale_subscribers = 0;
        subscriptions.retain(|_target, watchers| {
            let before = watchers.len();
            watchers.retain(|subscriber| identity_is_durable(subscriber, directory, connections));
            stale_subscribers += before - watchers.len();
            !watchers.is_empty()
        });

        (
            presence_before - presence.len(),
            evidence_before - fetch_evidence.len(),
            stale_subscribers,
        )
    };

    let rate_limit_buckets_pruned = inner
        .fetch_rate_limiter
        .sweep_stale(rate_limit_bucket_stale_after, Instant::now());
    let new_mailbox_rate_limit_buckets_pruned = inner
        .new_mailbox_rate_limiter
        .sweep_stale(rate_limit_bucket_stale_after, Instant::now());

    SweepSummary {
        mailbox_entries_pruned,
        mailboxes_emptied,
        rate_limit_buckets_pruned,
        new_mailbox_rate_limit_buckets_pruned,
        presence_entries_pruned,
        fetch_evidence_entries_pruned,
        stale_subscribers_pruned,
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
                new_mailbox_rate_limit_buckets_pruned =
                    summary.new_mailbox_rate_limit_buckets_pruned,
                // A count only — never a fingerprint or a presence state,
                // per this module's no-presence-logging constraint.
                presence_entries_pruned = summary.presence_entries_pruned,
                fetch_evidence_entries_pruned = summary.fetch_evidence_entries_pruned,
                stale_subscribers_pruned = summary.stale_subscribers_pruned,
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
            written_by: [0u8; 32],
        }
    }

    fn expired_entry() -> MailboxEntry {
        MailboxEntry {
            entry_id: [2u8; 16],
            envelope: vec![4, 5, 6],
            // Already in the past.
            expires_at: SystemTime::now() - Duration::from_secs(1),
            written_by: [0u8; 32],
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

    /// A directory resident with a `StoredBundle` — what makes an
    /// identity "durable" for DRA-0044's purposes.
    fn directory_resident(username: &str) -> crate::state::StoredBundle {
        crate::state::StoredBundle {
            bundle: crate::protocol::PrekeyBundleWire {
                username: username.to_string(),
                discriminator: 1,
                identity_key: vec![0u8; 32],
                identity_dh_public: vec![0u8; 32],
                identity_dh_signature: vec![0u8; 64],
                signed_prekey_id: 1,
                signed_prekey: vec![0u8; 32],
                signed_prekey_sig: vec![0u8; 64],
                signed_prekey_expires_at: 0,
                one_time_prekeys: Vec::new(),
                registration_pow: None,
            },
            one_time_prekeys: std::collections::HashMap::new(),
        }
    }

    /// Regression guard: a sweep must never touch the per-identity state
    /// of a *durable* identity — one in the directory or currently
    /// connected — nor the directory itself, nor
    /// `otp_exhaustion_attempts` (see this module's doc comment).
    ///
    /// This used to assert that `presence`/`subscriptions`/
    /// `fetch_evidence` were never touched *at all*. DRA-0044 narrowed
    /// that deliberately: they are now swept for throwaway identities,
    /// which is what the companion test below pins down. What must still
    /// hold — `SERVERS.md` §1.3's retained `last_seen`, and a
    /// relationship surviving the subscriber's own reconnects — is the
    /// durable case asserted here.
    #[tokio::test]
    async fn sweep_once_never_touches_a_durable_identitys_state_or_the_directory() {
        let state = AppState::new();
        let fp = [7u8; 32];
        let subscriber = [8u8; 32];
        {
            let mut inner = state.inner.write().await;
            // Both sides are real accounts: they published bundles.
            inner.directory.insert(fp, directory_resident("watched"));
            inner
                .directory
                .insert(subscriber, directory_resident("watcher"));
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

        let summary = sweep_once(&state, Duration::from_secs(600)).await;
        assert_eq!(summary.presence_entries_pruned, 0);
        assert_eq!(summary.fetch_evidence_entries_pruned, 0);
        assert_eq!(summary.stale_subscribers_pruned, 0);

        let inner = state.inner.read().await;
        assert_eq!(inner.presence.len(), 1);
        assert_eq!(inner.subscriptions.get(&fp).map(|s| s.len()), Some(1));
        assert_eq!(
            inner.fetch_evidence.get(&subscriber).map(|s| s.len()),
            Some(1)
        );
        assert_eq!(inner.otp_exhaustion_attempts.get(&fp), Some(&3));
        assert_eq!(inner.directory.len(), 2, "the directory is never pruned");
    }

    /// DRA-0044: the same three maps, for identities that published
    /// nothing and are not connected, are swept — that is the whole
    /// point of the finding.
    #[tokio::test]
    async fn sweep_once_drops_per_identity_state_left_by_throwaway_identities() {
        let state = AppState::new();
        let watched = [7u8; 32];
        let throwaway = [9u8; 32];
        {
            let mut inner = state.inner.write().await;
            // A real account being watched...
            inner
                .directory
                .insert(watched, directory_resident("watched"));
            // ...by a throwaway that published nothing and has since
            // disconnected.
            inner.presence.insert(
                throwaway,
                PresenceState::Offline {
                    last_seen: crate::state::now_unix(),
                },
            );
            inner
                .subscriptions
                .entry(watched)
                .or_default()
                .insert(throwaway);
            inner
                .fetch_evidence
                .entry(throwaway)
                .or_default()
                .insert(watched);
        }

        let summary = sweep_once(&state, Duration::from_secs(600)).await;
        assert_eq!(summary.presence_entries_pruned, 1);
        assert_eq!(summary.fetch_evidence_entries_pruned, 1);
        assert_eq!(summary.stale_subscribers_pruned, 1);

        let inner = state.inner.read().await;
        assert!(!inner.presence.contains_key(&throwaway));
        assert!(!inner.fetch_evidence.contains_key(&throwaway));
        assert!(
            !inner.subscriptions.contains_key(&watched),
            "a subscriber set emptied by the sweep is removed, not left behind empty"
        );
        assert!(
            inner.directory.contains_key(&watched),
            "the watched account itself is untouched"
        );
    }

    /// An identity that is connected right now is durable even with no
    /// directory entry — it has an open socket, so its state is live, not
    /// abandoned.
    #[tokio::test]
    async fn a_currently_connected_identity_is_not_swept() {
        let state = AppState::new();
        let fp = [3u8; 32];
        let (tx, _rx) = tokio::sync::mpsc::channel(crate::state::MAX_QUEUED_OUTBOUND_FRAMES);
        {
            let mut inner = state.inner.write().await;
            inner.connections.insert(fp, tx);
            inner
                .fetch_evidence
                .entry(fp)
                .or_default()
                .insert([4u8; 32]);
        }

        let summary = sweep_once(&state, Duration::from_secs(600)).await;
        assert_eq!(summary.fetch_evidence_entries_pruned, 0);
        assert!(state.inner.read().await.fetch_evidence.contains_key(&fp));
    }
}
