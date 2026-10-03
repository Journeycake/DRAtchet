//! Directory abuse resistance — Phase 1.2, `ARCHITECTURE.md` §11.8 /
//! `SERVERS.md` §1.1's "abuse resistance is part of this job list, not an
//! afterthought." Two independent defenses:
//!
//! 1. **Prekey-fetch rate limiting** (`FetchRateLimiter`): a per-
//!    (requesting connection, target identity) token bucket, so repeatedly
//!    fetching one account's bundle to exhaust its one-time prekeys costs
//!    increasingly more wall-clock time instead of being free. Keyed by
//!    connection rather than by verified identity, since `FetchBundle`
//!    deliberately doesn't require authentication first (see `ws.rs`'s
//!    module doc) — a not-yet-authenticated connection still has no stable
//!    identity to rate-limit against, but it does have a stable connection
//!    for its own lifetime, which is what's actually reachable to limit.
//!    A known, accepted limitation: reconnecting resets the budget — this
//!    raises the cost of a burst (a fresh TCP/TLS/WebSocket handshake per
//!    attempt) without claiming to eliminate distributed abuse entirely.
//!
//! 2. **Registration proof-of-work**: claiming a brand-new `username#NNNN`
//!    that the publishing identity doesn't already own requires solving a
//!    small SHA-256 grinding puzzle over the exact username/discriminator/
//!    identity key being claimed — a PII-free, cost-based floor against
//!    mass registration to squat popular usernames, the same idea
//!    Bitmessage used at message-send time, applied here at registration
//!    time instead (`ARCHITECTURE.md` §11.8). Deliberately *not* bound to
//!    a per-connection nonce: the puzzle is "prove you spent CPU to claim
//!    this exact username for this exact identity," which needs no
//!    freshness once solved — after the username is claimed, `ws.rs`'s
//!    ownership check (same fingerprint = rotation, no proof-of-work
//!    required again; different fingerprint = rejected outright,
//!    regardless of proof-of-work) is what prevents a solved puzzle from
//!    being reused to steal it later.

use std::collections::HashMap;
use std::time::Instant;

use sha2::{Digest, Sha256};

use crate::state::Fingerprint;

/// Identifies one WebSocket connection for the lifetime of that connection
/// only (a fresh random value per connect, not persisted or tied to any
/// identity) — see the module doc for why the rate limiter is keyed by this
/// rather than by verified identity.
pub type ConnectionId = [u8; 16];

/// Token-bucket capacity — a legitimate client fetching a handful of
/// contacts' bundles in quick succession (e.g. opening several
/// conversations at once) never hits this; a script trying to burn through
/// one account's one-time-prekey pool does.
const FETCH_RATE_LIMIT_CAPACITY: f64 = 5.0;
/// Refill rate: one additional fetch allowance every 5 seconds.
const FETCH_RATE_LIMIT_REFILL_PER_SEC: f64 = 1.0 / 5.0;

struct RateBucket {
    tokens: f64,
    last_refill: Instant,
}

/// Per-(connection, target) token buckets gating `FetchBundle`. Lives in
/// `AppState::inner` alongside everything else — see `state.rs`.
#[derive(Default)]
pub struct FetchRateLimiter {
    buckets: HashMap<(ConnectionId, Fingerprint), RateBucket>,
}

impl FetchRateLimiter {
    /// Returns `true` (and consumes one token) if this
    /// (`requester`, `target`) pair is still within its allowance; `false`
    /// if the caller should reject the fetch without performing it.
    pub fn allow(&mut self, requester: ConnectionId, target: Fingerprint) -> bool {
        let now = Instant::now();
        let bucket = self
            .buckets
            .entry((requester, target))
            .or_insert_with(|| RateBucket {
                tokens: FETCH_RATE_LIMIT_CAPACITY,
                last_refill: now,
            });
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * FETCH_RATE_LIMIT_REFILL_PER_SEC)
            .min(FETCH_RATE_LIMIT_CAPACITY);
        bucket.last_refill = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Remove buckets idle longer than `older_than` — `ConnectionId` is a
    /// fresh random value per connection (module doc) that's never reused,
    /// so once a connection has gone quiet this long its bucket is pure
    /// bookkeeping garbage: it would have refilled to full capacity long
    /// before `older_than` given `FETCH_RATE_LIMIT_REFILL_PER_SEC`, so
    /// removing it changes no observable throttling behavior, only frees
    /// memory (a later request for the same key just lazily reinserts via
    /// `allow`'s `or_insert_with`). Called periodically by
    /// `crate::pruning::sweep_once`. Returns the number removed, for that
    /// sweep's summary log line.
    pub fn sweep_stale(&mut self, older_than: std::time::Duration, now: Instant) -> usize {
        let before = self.buckets.len();
        self.buckets
            .retain(|_, bucket| now.duration_since(bucket.last_refill) < older_than);
        before - self.buckets.len()
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.buckets.len()
    }
}

/// DRA-0018 (`docs/DELIVERY_FAILURE_FINDINGS.md`) — a per-writer token
/// bucket gating how fast one identity can bring *brand-new* mailbox ids
/// into existence via `MailboxWrite`, mirroring `FetchRateLimiter`'s
/// exact shape. `MailboxFetch`/`MailboxDelete`/`MailboxWrite`'s
/// per-mailbox caps (DRA-0015/DRA-0017) bound how much one *existing*
/// mailbox can hold; nothing bounded how many *distinct* mailbox ids
/// `Inner::mailboxes` could ever grow to, and `MailboxWrite` requires no
/// pre-existing relationship with the target id at all — a single
/// identity looping fresh random ids could make the server allocate an
/// unbounded number of `HashMap` entries, exhausting server memory for
/// every other client, not just one conversation.
///
/// Keyed by the caller's real, authenticated `Fingerprint` (unlike
/// `FetchRateLimiter`, `MailboxWrite` already requires authentication —
/// see `ws.rs`'s module doc — so there's a stable identity to key by
/// directly, no need for `ConnectionId`'s reconnect-resets-the-budget
/// compromise). Only consumed when the write's `mailbox_id` is not
/// already a key in `Inner::mailboxes` — ordinary traffic within an
/// already-existing conversation (the overwhelming majority of real
/// usage) never touches this budget at all, only the act of originating
/// a new mailbox address does.
#[derive(Default)]
pub struct NewMailboxRateLimiter {
    buckets: HashMap<Fingerprint, RateBucket>,
}

/// Burst capacity — generous for a real client adding several new
/// contacts in quick succession (each pairing needs at most one or two
/// brand-new mailbox ids: the bootstrap one, then the routing-id-derived
/// one once the exchange completes).
pub const NEW_MAILBOX_RATE_LIMIT_CAPACITY: f64 = 20.0;
/// Refill rate: one additional new-mailbox allowance every 30 seconds.
/// Deliberately much slower than `FETCH_RATE_LIMIT_REFILL_PER_SEC` — this
/// gates creating a whole new piece of server-side state, not just
/// reading already-published, bounded-size directory data.
const NEW_MAILBOX_RATE_LIMIT_REFILL_PER_SEC: f64 = 1.0 / 30.0;

impl NewMailboxRateLimiter {
    /// Returns `true` (and consumes one token) if `writer` may originate
    /// another brand-new mailbox right now; `false` if the caller should
    /// reject the write without creating one. Callers only invoke this
    /// when the target `mailbox_id` doesn't already exist — see the
    /// struct doc.
    pub fn allow(&mut self, writer: Fingerprint) -> bool {
        let now = Instant::now();
        let bucket = self.buckets.entry(writer).or_insert_with(|| RateBucket {
            tokens: NEW_MAILBOX_RATE_LIMIT_CAPACITY,
            last_refill: now,
        });
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * NEW_MAILBOX_RATE_LIMIT_REFILL_PER_SEC)
            .min(NEW_MAILBOX_RATE_LIMIT_CAPACITY);
        bucket.last_refill = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Same reasoning as `FetchRateLimiter::sweep_stale` — a bucket idle
    /// past `older_than` would already be back at full capacity, so
    /// removing it only frees memory, never changes throttling behavior.
    pub fn sweep_stale(&mut self, older_than: std::time::Duration, now: Instant) -> usize {
        let before = self.buckets.len();
        self.buckets
            .retain(|_, bucket| now.duration_since(bucket.last_refill) < older_than);
        before - self.buckets.len()
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.buckets.len()
    }
}

/// DRA-0045 (`docs/DELIVERY_FAILURE_FINDINGS.md`) — gates how fast one
/// identity may have the server relay `RendezvousOffer`/`RendezvousAnswer`
/// frames at other clients.
///
/// Unlike every other client-supplied payload this server handles, a
/// relayed rendezvous frame is pushed straight into *another* client's
/// outbound queue, so its cost lands on a third party rather than on the
/// sender. DRA-0026 bounded one frame's size; this bounds their rate.
/// Keyed by the *sender*, not by the (sender, target) pair, so an
/// attacker cannot buy fresh budget simply by spreading the flood across
/// many victims.
#[derive(Default)]
pub struct RendezvousRateLimiter {
    buckets: HashMap<Fingerprint, RateBucket>,
}

/// Burst capacity. A real WebRTC negotiation is one offer and one answer,
/// plus a retry or two if the first attempt is missed; this is generous
/// headroom for a user placing several calls in a row.
pub const RENDEZVOUS_RATE_LIMIT_CAPACITY: f64 = 10.0;
/// Refill rate: one additional relayed frame every 5 seconds. Calls are a
/// human-paced action, so this is far slower than `FetchBundle`'s budget
/// while still never getting in a real caller's way.
const RENDEZVOUS_RATE_LIMIT_REFILL_PER_SEC: f64 = 1.0 / 5.0;

impl RendezvousRateLimiter {
    /// Returns `true` (and consumes one token) if `sender` may have one
    /// more frame relayed on its behalf right now.
    pub fn allow(&mut self, sender: Fingerprint) -> bool {
        let now = Instant::now();
        let bucket = self.buckets.entry(sender).or_insert_with(|| RateBucket {
            tokens: RENDEZVOUS_RATE_LIMIT_CAPACITY,
            last_refill: now,
        });
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * RENDEZVOUS_RATE_LIMIT_REFILL_PER_SEC)
            .min(RENDEZVOUS_RATE_LIMIT_CAPACITY);
        bucket.last_refill = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Same reasoning as the other two limiters' `sweep_stale`.
    pub fn sweep_stale(&mut self, older_than: std::time::Duration, now: Instant) -> usize {
        let before = self.buckets.len();
        self.buckets
            .retain(|_, bucket| now.duration_since(bucket.last_refill) < older_than);
        before - self.buckets.len()
    }
}

/// DRA-0049 (`docs/DELIVERY_FAILURE_FINDINGS.md`) — gates how fast one
/// identity may issue `MailboxFetch`.
///
/// Every other client-driven handler was already metered — `MailboxWrite`
/// by [`NewMailboxRateLimiter`], `FetchBundle` by [`FetchRateLimiter`],
/// the rendezvous relay by [`RendezvousRateLimiter`] (DRA-0045). Fetch was
/// the one left open, and it is the most expensive call the server
/// serves: it takes the global write lock for its whole duration.
/// Polling for new mail is a normal, frequent client action, so this is
/// deliberately the most generous of the four.
#[derive(Default)]
pub struct MailboxFetchRateLimiter {
    buckets: HashMap<Fingerprint, RateBucket>,
}

/// Burst capacity, and deliberately the most generous of the four
/// limiters.
///
/// The primary fix for DRA-0049 is the O(1) ownership lookup
/// (`Inner::bootstrap_mailbox_index`), which removed the amplification
/// that made a fetch expensive in the first place. This limiter is a
/// backstop against sheer volume, not the load-bearing defence, so it is
/// tuned to sit well clear of real traffic rather than as close to it as
/// possible.
///
/// The number matters: an initial value of 60 broke
/// `app/tests/hundred_round_delivery_ack_exchange.rs`, a *legitimate*
/// 100-round bidirectional conversation, at round 68. A busy
/// conversation or a client draining a backlog after reconnecting really
/// does fetch this often, so the budget has to clear that by a wide
/// margin or it is a correctness bug wearing a security hat.
pub const MAILBOX_FETCH_RATE_LIMIT_CAPACITY: f64 = 600.0;
/// Refill rate: 50 fetches per second sustained — orders of magnitude
/// above `app`'s multi-second per-conversation poll cadence, while still
/// bounding what was previously an entirely unbounded handler.
const MAILBOX_FETCH_RATE_LIMIT_REFILL_PER_SEC: f64 = 50.0;

impl MailboxFetchRateLimiter {
    /// Returns `true` (and consumes one token) if `fetcher` may fetch
    /// again right now.
    pub fn allow(&mut self, fetcher: Fingerprint) -> bool {
        let now = Instant::now();
        let bucket = self.buckets.entry(fetcher).or_insert_with(|| RateBucket {
            tokens: MAILBOX_FETCH_RATE_LIMIT_CAPACITY,
            last_refill: now,
        });
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * MAILBOX_FETCH_RATE_LIMIT_REFILL_PER_SEC)
            .min(MAILBOX_FETCH_RATE_LIMIT_CAPACITY);
        bucket.last_refill = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Same reasoning as the other limiters' `sweep_stale`.
    pub fn sweep_stale(&mut self, older_than: std::time::Duration, now: Instant) -> usize {
        let before = self.buckets.len();
        self.buckets
            .retain(|_, bucket| now.duration_since(bucket.last_refill) < older_than);
        before - self.buckets.len()
    }
}

/// DRA-0050 (`docs/DELIVERY_FAILURE_FINDINGS.md`) — gates how fast one
/// identity may issue `MailboxDelete`.
///
/// DRA-0049 closed `MailboxFetch`'s gap but left this one open on
/// purpose, on the reasoning that a delete is far cheaper per call (no
/// pruning, no entry serialization, and it only ever removes the
/// caller's own reachable entries). That is true of the *work inside the
/// lock* — but the handler still takes `state.inner`'s global exclusive
/// write lock for its whole duration, same as fetch did, and nothing
/// bounded how often one identity could acquire it. Cheap-per-call and
/// unmetered still adds up to unbounded lock-contention volume.
#[derive(Default)]
pub struct MailboxDeleteRateLimiter {
    buckets: HashMap<Fingerprint, RateBucket>,
}

/// Burst capacity. A real client deletes one entry per message it just
/// finished processing — bursty only up to the size of a backlog drained
/// after reconnecting, the same shape `MailboxFetch`'s budget already
/// accommodates. Matches `MAILBOX_FETCH_RATE_LIMIT_CAPACITY` /
/// `..._REFILL_PER_SEC` deliberately: a client that fetches N entries in
/// a burst goes on to delete roughly N of them, so giving delete a
/// tighter budget than fetch would just move the false-positive risk
/// DRA-0049 already paid down once.
pub const MAILBOX_DELETE_RATE_LIMIT_CAPACITY: f64 = 600.0;
const MAILBOX_DELETE_RATE_LIMIT_REFILL_PER_SEC: f64 = 50.0;

impl MailboxDeleteRateLimiter {
    /// Returns `true` (and consumes one token) if `deleter` may delete
    /// again right now.
    pub fn allow(&mut self, deleter: Fingerprint) -> bool {
        let now = Instant::now();
        let bucket = self.buckets.entry(deleter).or_insert_with(|| RateBucket {
            tokens: MAILBOX_DELETE_RATE_LIMIT_CAPACITY,
            last_refill: now,
        });
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * MAILBOX_DELETE_RATE_LIMIT_REFILL_PER_SEC)
            .min(MAILBOX_DELETE_RATE_LIMIT_CAPACITY);
        bucket.last_refill = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Same reasoning as the other limiters' `sweep_stale`.
    pub fn sweep_stale(&mut self, older_than: std::time::Duration, now: Instant) -> usize {
        let before = self.buckets.len();
        self.buckets
            .retain(|_, bucket| now.duration_since(bucket.last_refill) < older_than);
        before - self.buckets.len()
    }
}

/// How many leading zero bits a solution's hash must have. ~2^12 average
/// hash attempts to find one — sub-millisecond for a legitimate client
/// registering one username, but a real (if deliberately modest, per the
/// module doc) per-registration tax that scales linearly with how many
/// usernames an automated squatter tries to claim.
pub const REGISTRATION_POW_DIFFICULTY_BITS: u32 = 12;

fn pow_hash(username: &str, discriminator: u16, identity_key: &[u8], solution: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"dratchet-registration-pow-v1");
    hasher.update(username.as_bytes());
    hasher.update(discriminator.to_be_bytes());
    hasher.update(identity_key);
    hasher.update(solution.to_be_bytes());
    hasher.finalize().into()
}

fn leading_zero_bits(hash: &[u8; 32]) -> u32 {
    let mut bits = 0;
    for byte in hash {
        if *byte == 0 {
            bits += 8;
        } else {
            bits += byte.leading_zeros();
            break;
        }
    }
    bits
}

/// Checked server-side when a `PublishBundle` claims a `username#NNNN` the
/// publishing identity doesn't already own (see `ws.rs::publish_bundle`).
pub fn verify_registration_pow(
    username: &str,
    discriminator: u16,
    identity_key: &[u8],
    solution: u64,
) -> bool {
    leading_zero_bits(&pow_hash(username, discriminator, identity_key, solution))
        >= REGISTRATION_POW_DIFFICULTY_BITS
}

/// Brute-force a valid solution — what a client does at registration time,
/// before it ever contacts the service. Exposed as a real function (not
/// `#[cfg(test)]`-gated) since it's the reference implementation a future
/// client crate needs, not just a test fixture.
pub fn solve_registration_pow(username: &str, discriminator: u16, identity_key: &[u8]) -> u64 {
    let mut solution = 0u64;
    loop {
        if verify_registration_pow(username, discriminator, identity_key, solution) {
            return solution;
        }
        solution += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn solved_proof_of_work_verifies() {
        let solution = solve_registration_pow("alice", 1, &[7u8; 32]);
        assert!(verify_registration_pow("alice", 1, &[7u8; 32], solution));
    }

    #[test]
    fn a_solution_does_not_transfer_to_a_different_username_discriminator_or_identity() {
        let solution = solve_registration_pow("alice", 1, &[7u8; 32]);
        assert!(!verify_registration_pow("bob", 1, &[7u8; 32], solution));
        assert!(!verify_registration_pow("alice", 2, &[7u8; 32], solution));
        assert!(!verify_registration_pow("alice", 1, &[8u8; 32], solution));
    }

    #[test]
    fn fetch_rate_limiter_allows_a_burst_then_rejects() {
        let mut limiter = FetchRateLimiter::default();
        let requester = [1u8; 16];
        let target = [2u8; 32];
        for _ in 0..FETCH_RATE_LIMIT_CAPACITY as u32 {
            assert!(limiter.allow(requester, target));
        }
        assert!(
            !limiter.allow(requester, target),
            "burst beyond capacity should be rejected"
        );
    }

    #[test]
    fn fetch_rate_limiter_tracks_targets_independently() {
        let mut limiter = FetchRateLimiter::default();
        let requester = [1u8; 16];
        for _ in 0..FETCH_RATE_LIMIT_CAPACITY as u32 {
            assert!(limiter.allow(requester, [2u8; 32]));
        }
        assert!(
            limiter.allow(requester, [3u8; 32]),
            "a different target has its own budget"
        );
    }

    #[test]
    fn sweep_stale_removes_buckets_idle_past_the_threshold_but_keeps_recently_used_ones() {
        let mut limiter = FetchRateLimiter::default();
        // `allow` always stamps `last_refill` with the real `Instant::now()`
        // (there's no way to inject a fake time into it), so both buckets'
        // `last_refill` is effectively "now" — staleness is then purely a
        // function of how far past "now" the `now` passed to `sweep_stale`
        // is.
        limiter.allow([1u8; 16], [2u8; 32]);
        limiter.allow([9u8; 16], [2u8; 32]);
        assert_eq!(limiter.len(), 2);

        let just_created = Instant::now();
        let threshold = std::time::Duration::from_secs(600);

        let removed = limiter.sweep_stale(threshold, just_created + threshold / 2);
        assert_eq!(
            removed, 0,
            "buckets younger than the staleness threshold must survive"
        );
        assert_eq!(limiter.len(), 2);

        let removed = limiter.sweep_stale(threshold, just_created + threshold * 2);
        assert_eq!(
            removed, 2,
            "buckets idle well past the staleness threshold must be swept"
        );
        assert_eq!(limiter.len(), 0);
    }

    #[test]
    fn fetch_rate_limiter_tracks_requesters_independently() {
        let mut limiter = FetchRateLimiter::default();
        let target = [2u8; 32];
        for _ in 0..FETCH_RATE_LIMIT_CAPACITY as u32 {
            assert!(limiter.allow([1u8; 16], target));
        }
        assert!(
            limiter.allow([9u8; 16], target),
            "a different requester has its own budget"
        );
    }

    /// DRA-0018: proves the new-mailbox rate limiter itself throttles a
    /// burst — the real end-to-end proof that a single identity can no
    /// longer originate unbounded distinct mailboxes is
    /// `server/tests/unbounded_mailbox_creation.rs`, run against this
    /// same limiter wired into `ws.rs`.
    #[test]
    fn new_mailbox_rate_limiter_allows_a_burst_then_rejects() {
        let mut limiter = NewMailboxRateLimiter::default();
        let writer = [1u8; 32];
        for _ in 0..NEW_MAILBOX_RATE_LIMIT_CAPACITY as u32 {
            assert!(limiter.allow(writer));
        }
        assert!(
            !limiter.allow(writer),
            "burst beyond capacity should be rejected"
        );
    }

    #[test]
    fn new_mailbox_rate_limiter_tracks_writers_independently() {
        let mut limiter = NewMailboxRateLimiter::default();
        for _ in 0..NEW_MAILBOX_RATE_LIMIT_CAPACITY as u32 {
            assert!(limiter.allow([1u8; 32]));
        }
        assert!(
            limiter.allow([9u8; 32]),
            "a different writer has its own budget"
        );
    }

    #[test]
    fn new_mailbox_rate_limiter_sweep_stale_removes_idle_buckets() {
        let mut limiter = NewMailboxRateLimiter::default();
        limiter.allow([1u8; 32]);
        limiter.allow([9u8; 32]);
        assert_eq!(limiter.len(), 2);

        let just_created = Instant::now();
        let threshold = std::time::Duration::from_secs(600);
        let removed = limiter.sweep_stale(threshold, just_created + threshold * 2);
        assert_eq!(removed, 2);
        assert_eq!(limiter.len(), 0);
    }
}
