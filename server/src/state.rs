//! In-memory state for the Signaling & Presence Service, per `docs/SERVERS.md`
//! §1.4: "no database migrations, no durable message storage... a
//! single-process in-memory presence table plus prekey-bundle store is
//! sufficient." A restart loses only current-connection state and undelivered
//! mailbox entries — never anything durable, since nothing here is meant to
//! be durable (§1.3).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rand_core::{OsRng, RngCore};
use tokio::sync::{mpsc, RwLock};

use crate::protocol::PrekeyBundleWire;

pub type Fingerprint = [u8; 32];
pub type MailboxId = [u8; 16];

/// A username#NNNN identity, as looked up in the directory.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UsernameKey {
    pub username: String,
    pub discriminator: u16,
}

pub struct StoredBundle {
    pub bundle: PrekeyBundleWire,
    /// One-time prekeys not yet consumed, keyed by id — the batch shrinks
    /// as `FetchBundle` calls consume from it (`ARCHITECTURE.md` §3.4).
    pub one_time_prekeys: HashMap<u32, Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresenceState {
    Online,
    Away,
    Offline { last_seen: u64 },
}

pub struct MailboxEntry {
    pub entry_id: [u8; 16],
    pub envelope: Vec<u8>,
    pub expires_at: SystemTime,
}

/// One connected client's outbound channel — frames pushed here are written
/// to that client's WebSocket by its own connection task.
pub type OutboundSender = mpsc::UnboundedSender<Vec<u8>>;

#[derive(Default)]
pub struct Inner {
    pub directory: HashMap<Fingerprint, StoredBundle>,
    pub username_index: HashMap<UsernameKey, Fingerprint>,
    pub presence: HashMap<Fingerprint, PresenceState>,
    /// target fingerprint -> set of subscriber fingerprints watching it.
    pub subscriptions: HashMap<Fingerprint, std::collections::HashSet<Fingerprint>>,
    /// fetcher fingerprint -> set of fingerprints they've fetched a bundle
    /// for — the evidence `PresenceSubscribe` requires
    /// (`SERVERS.md` §1.3: "only for accounts it has an established or
    /// attempted session with").
    pub fetch_evidence: HashMap<Fingerprint, std::collections::HashSet<Fingerprint>>,
    pub mailboxes: HashMap<MailboxId, Vec<MailboxEntry>>,
    pub connections: HashMap<Fingerprint, OutboundSender>,
    /// Directory abuse resistance (Phase 1.2, `ARCHITECTURE.md` §11.8) —
    /// see `crate::abuse` for what each of these gates.
    pub fetch_rate_limiter: crate::abuse::FetchRateLimiter,
    /// target fingerprint -> count of `FetchBundle` calls that found its
    /// one-time-prekey pool already empty — logged past a threshold as a
    /// "someone keeps hitting this account's exhausted pool" signal
    /// (`ARCHITECTURE.md` §11.8); surfacing it to the affected user is
    /// future client work, not something this server-only phase can do.
    pub otp_exhaustion_attempts: HashMap<Fingerprint, u32>,
}

pub struct AppState {
    pub inner: RwLock<Inner>,
}

impl AppState {
    pub fn new() -> Arc<Self> {
        Arc::new(AppState {
            inner: RwLock::new(Inner::default()),
        })
    }
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after the Unix epoch")
        .as_secs()
}

pub fn random_32() -> [u8; 32] {
    let mut buf = [0u8; 32];
    OsRng.fill_bytes(&mut buf);
    buf
}

pub fn random_16() -> [u8; 16] {
    let mut buf = [0u8; 16];
    OsRng.fill_bytes(&mut buf);
    buf
}

/// Prune mailbox entries whose TTL has expired — called lazily on fetch
/// rather than via a background sweep task, which is sufficient for a v1
/// in-memory store (an expired-but-unfetched entry costs a little memory
/// until the next fetch of that exact mailbox, never correctness).
pub fn prune_expired(entries: &mut Vec<MailboxEntry>) {
    let now = SystemTime::now();
    entries.retain(|e| e.expires_at > now);
}

pub fn ttl_from_secs(ttl: u32) -> Duration {
    Duration::from_secs(ttl as u64)
}
