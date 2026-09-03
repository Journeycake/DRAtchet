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
}
