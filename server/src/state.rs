//! In-memory state for the Signaling & Presence Service, per `docs/SERVERS.md`
//! §1.4: "no database migrations, no durable message storage." A restart
//! loses only current-connection state and undelivered mailbox entries —
//! never anything durable, since nothing here is meant to be durable (§1.3).
//! One exception: `directory`/`username_index` are additionally written
//! through to an on-disk store when `AppState::with_persistence` built this
//! state — see `crate::persistence`'s module doc for why, and
//! `docs/SERVERS.md` §1.4's update for the scope of that exception.

use std::collections::HashMap;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, RwLock};

use crate::protocol::PrekeyBundleWire;

pub type Fingerprint = [u8; 32];
pub type MailboxId = [u8; 16];

/// DRA-0015 (`docs/DELIVERY_FAILURE_FINDINGS.md`) — a hard ceiling on a
/// single `MailboxWrite`'s envelope, enforced in `ws.rs`. A legitimate
/// envelope never approaches this: `core::payload::MAX_PADDED_LEN` caps
/// the *plaintext* a real client ever pads to at 16 KiB, and AEAD/framing
/// overhead on top of that is on the order of tens of bytes, not
/// kilobytes. Set to 4x that ceiling — generous headroom for any real
/// envelope, while still bounding how much memory one malicious
/// `MailboxWrite` can force the server to hold.
pub const MAX_ENVELOPE_LEN: usize = 64 * 1024;

/// DRA-0015 — a hard ceiling on how many entries a single mailbox may
/// hold at once, enforced in `ws.rs`'s `MailboxWrite` handler (after
/// pruning already-expired entries, so a slow-but-legitimate recipient
/// isn't punished for entries that would be dropped on the next fetch
/// anyway). Generous for real offline-queueing use — a real conversation
/// queuing this many undelivered entries before either side reconnects
/// is already far outside normal usage — while bounding one flooded
/// mailbox's worst-case memory to `MAX_MAILBOX_ENTRIES * MAX_ENVELOPE_LEN`
/// (16 MiB) instead of unbounded.
pub const MAX_MAILBOX_ENTRIES: usize = 256;

/// DRA-0017 (`docs/DELIVERY_FAILURE_FINDINGS.md`) — a per-*writer* share
/// of `MAX_MAILBOX_ENTRIES` within one mailbox, enforced alongside the
/// total cap in `ws.rs`'s `MailboxWrite` handler. A mailbox is
/// bidirectional (`ARCHITECTURE.md` §11.1: both participants in a
/// conversation write to and fetch from the identical `mailbox_id`), so
/// a total-only cap let one side unilaterally consume the *entire*
/// budget with their own entries, silently blocking the other side's own
/// legitimate writes into that same shared conversation once the total
/// was reached. Half of `MAX_MAILBOX_ENTRIES`, matching the two-party
/// design this mailbox model assumes: neither of the two normal
/// participants can ever be locked out of writing by the other's volume
/// alone, whatever the other side does with their own half.
pub const MAX_ENTRIES_PER_WRITER_PER_MAILBOX: usize = MAX_MAILBOX_ENTRIES / 2;

/// DRA-0019 (`docs/DELIVERY_FAILURE_FINDINGS.md`) — a hard ceiling on how
/// many one-time prekeys a single `PublishBundle` may carry, enforced in
/// `ws.rs`'s `publish_bundle`. The real batch size any legitimate client
/// ever publishes is `app::ONE_TIME_PREKEY_BATCH` (10) — this is 10x
/// that, generous headroom for a future larger batch, while bounding how
/// much one publish can add to `Inner::directory`, which (unlike
/// mailboxes) is never pruned — a single oversized publish is permanent,
/// not a transient flood that self-heals.
pub const MAX_ONE_TIME_PREKEYS_PER_PUBLISH: usize = 100;

/// DRA-0019 — a hard ceiling on `username`'s length, enforced in
/// `ws.rs`'s `publish_bundle`. Generous for any real `username#NNNN`
/// handle (`ARCHITECTURE.md` §6.1 shows short, ordinary handles) while
/// bounding how much one publish can add to the same never-pruned
/// directory.
pub const MAX_USERNAME_LEN: usize = dratchet_core::username::MAX_LEN;

/// DRA-0024 (`docs/DELIVERY_FAILURE_FINDINGS.md`) — a narrow, ASCII-only
/// floor against Unicode homograph/confusables impersonation, enforced in
/// `ws.rs`'s `publish_bundle`. Without this, nothing stopped registering
/// a `username` that's visually indistinguishable from an already-taken
/// one under a different `discriminator` (e.g. Cyrillic `а` (U+0430) in
/// place of Latin `a`) — a distinct identity a human reader can't tell
/// apart from the real one by eye, `username#NNNN` display included.
/// Deliberately narrow rather than a full Unicode confusables-skeleton
/// solution (which would need a maintained confusables table and a
/// second server-side index, real feature work, not a bounded fix): this
/// closes the specific attack outright for the ASCII case, the same
/// "deliberately modest, a floor not a wall" spirit as the registration
/// proof-of-work (`crate::abuse`), at the cost of non-ASCII handles not
/// being supported at all — a real, accepted i18n tradeoff, not a defect.
pub fn username_has_only_allowed_characters(username: &str) -> bool {
    dratchet_core::username::has_only_allowed_characters(username)
}

/// DRA-0026 (`docs/DELIVERY_FAILURE_FINDINGS.md`) — a hard ceiling on a
/// single `RendezvousOffer`/`RendezvousAnswer`'s `sdp_offer`/`sdp_answer`,
/// enforced in `ws.rs`. Unlike every other client-supplied payload in this
/// file (`MailboxWrite`'s envelope, `PublishBundle`'s username/prekeys),
/// nothing previously bounded this one at all — relayed verbatim to
/// another connected client's outbound channel by `relay_to_peer`, with no
/// relationship check and no rate limit either. A real SDP offer is on the
/// order of a few KiB; generous headroom, while still bounding the
/// server-to-victim amplification a single malicious frame can force.
pub const MAX_SDP_LEN: usize = 64 * 1024;

/// DRA-0026 — a hard ceiling on how many ICE candidates one
/// `RendezvousOffer`/`RendezvousAnswer` may carry. A real WebRTC
/// negotiation gathers at most a handful per network interface; generous
/// headroom for any real client.
pub const MAX_ICE_CANDIDATES: usize = 64;

/// DRA-0026 — a hard ceiling on a single ICE candidate string's length.
/// A real candidate line is well under a hundred bytes.
pub const MAX_ICE_CANDIDATE_LEN: usize = 4096;

/// DRA-0031 (`docs/DELIVERY_FAILURE_FINDINGS.md`) — a hard ceiling on
/// total concurrent WebSocket connections this process will accept at
/// once, enforced in `ws.rs`'s `ws_handler` before the HTTP upgrade
/// completes (`AppState::active_connections`). DRA-0030 bounds a single
/// message/frame; nothing bounded connection *count* at all, so a flood
/// of bare, unauthenticated TCP connections (each cheap for the attacker
/// — no bytes need to be sent past the initial handshake) could still
/// exhaust server memory/file descriptors one `tokio::spawn` task and
/// mpsc channel at a time, at whatever rate the attacker could open
/// sockets. Generous for any real deployment's legitimate concurrent
/// user count while bounding the worst case to a fixed, known ceiling.
pub const MAX_CONCURRENT_CONNECTIONS: usize = 10_000;

/// DRA-0030 (`docs/DELIVERY_FAILURE_FINDINGS.md`) — the *transport-layer*
/// ceiling on a single WebSocket message, applied to every connection
/// (`ws.rs`'s `ws_handler`) before any application-layer frame is even
/// parsed. Every other `MAX_*` cap in this file bounds one specific
/// decoded field; none of them matter for a connection that never gets
/// that far, because `axum`/`tokio-tungstenite` silently defaults to a
/// 64 MiB per-message ceiling when nothing overrides it — a thousand
/// times larger than `MAX_ENVELOPE_LEN`, reachable by any TCP connection,
/// pre-authentication. The largest legitimate frame this protocol ever
/// sends is an ordinary `RendezvousAnswer` (`MAX_SDP_LEN` plus
/// `MAX_ICE_CANDIDATES * MAX_ICE_CANDIDATE_LEN`, well under 320 KiB); 1
/// MiB is generous headroom above that while still cutting the library's
/// default ceiling by 64x.
pub const MAX_WS_MESSAGE_BYTES: usize = 1024 * 1024;

/// A username#NNNN identity, as looked up in the directory.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UsernameKey {
    pub username: String,
    pub discriminator: u16,
}

#[derive(Serialize, Deserialize)]
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
    /// The authenticated identity that wrote this entry — `ARCHITECTURE.md`
    /// §11.1's "bidirectional per-conversation `mailbox_id`" means both
    /// sides of a pairing write to and fetch from the exact same address,
    /// with nothing else distinguishing "my own outgoing mail, still
    /// waiting for the peer to collect it" from "the peer's mail, waiting
    /// for me." Without this, `MailboxFetch` would hand a writer back its
    /// own not-yet-collected entries — decrypting a self-authored envelope
    /// with the *receiving* side of the ratchet fails the AEAD check, gets
    /// classified as a per-entry content error, and (worse) still gets
    /// deleted as "processed" — silently destroying a message before its
    /// real recipient ever sees it. Found while adding `DeliveryAck`
    /// (`ARCHITECTURE.md` §4.6), whose ack-back-over-the-same-mailbox
    /// pattern turns this from a rare, easily-avoided-by-test-choreography
    /// edge case into the common one (`docs/DELIVERY_FAILURE_FINDINGS.md`).
    pub written_by: Fingerprint,
}

/// DRA-0045 (`docs/DELIVERY_FAILURE_FINDINGS.md`) — how many frames may
/// be queued for one client before further pushes are refused.
///
/// This channel used to be unbounded, which meant anything that pushes a
/// frame at *another* client — `ws.rs`'s rendezvous relay above all —
/// could grow one connection's queue as fast as the sender wrote, with
/// the victim's socket draining it only as fast as it could read. A cap
/// turns that from unbounded server memory into a bounded queue plus a
/// refused send. Deep enough that no real client, which is answering its
/// own request/response traffic plus the occasional presence update,
/// ever reaches it.
pub const MAX_QUEUED_OUTBOUND_FRAMES: usize = 64;

/// One connected client's outbound channel — frames pushed here are written
/// to that client's WebSocket by its own connection task. Bounded
/// (DRA-0045); senders use `try_send`, so a client that has stopped
/// draining gets frames refused rather than buffered without limit.
pub type OutboundSender = mpsc::Sender<Vec<u8>>;

#[derive(Default)]
pub struct Inner {
    pub directory: HashMap<Fingerprint, StoredBundle>,
    /// DRA-0049 — reverse index `bootstrap_mailbox_id -> Fingerprint`,
    /// maintained alongside every `directory` insertion.
    ///
    /// `ws::mailbox_id_belongs_to_someone_else` used to answer "is this
    /// mailbox id some *other* account's bootstrap id?" by scanning every
    /// directory key, on every `MailboxFetch`/`MailboxDelete`, while
    /// holding the global write lock. The directory is never pruned, so
    /// that per-call cost only ever grew. This makes the same question an
    /// O(1) lookup.
    ///
    /// Must be written wherever `directory` is: [`Inner::register_bundle`]
    /// is the only way to do so, precisely so the two cannot drift.
    pub bootstrap_mailbox_index: HashMap<MailboxId, Fingerprint>,
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
    /// DRA-0018 — gates how fast one identity can originate brand-new
    /// mailbox ids via `MailboxWrite`. See `crate::abuse::NewMailboxRateLimiter`.
    pub new_mailbox_rate_limiter: crate::abuse::NewMailboxRateLimiter,
    /// DRA-0045 — gates how fast one identity can have rendezvous frames
    /// relayed at other clients. See `crate::abuse::RendezvousRateLimiter`.
    pub rendezvous_rate_limiter: crate::abuse::RendezvousRateLimiter,
    /// DRA-0049 — gates how fast one identity can issue `MailboxFetch`.
    /// See `crate::abuse::MailboxFetchRateLimiter`.
    pub mailbox_fetch_rate_limiter: crate::abuse::MailboxFetchRateLimiter,
    /// target fingerprint -> count of `FetchBundle` calls that found its
    /// one-time-prekey pool already empty — logged past a threshold as a
    /// "someone keeps hitting this account's exhausted pool" signal
    /// (`ARCHITECTURE.md` §11.8); surfacing it to the affected user is
    /// future client work, not something this server-only phase can do.
    pub otp_exhaustion_attempts: HashMap<Fingerprint, u32>,
}

impl Inner {
    /// The only sanctioned way to put a bundle into the directory
    /// (DRA-0049). Keeps [`Inner::bootstrap_mailbox_index`] in step with
    /// [`Inner::directory`] — the index is what makes the mailbox
    /// ownership check O(1) instead of a full directory scan under the
    /// global write lock, and an index that drifted from the directory
    /// would silently stop protecting the accounts it missed.
    pub fn register_bundle(&mut self, fingerprint: Fingerprint, stored: StoredBundle) {
        self.bootstrap_mailbox_index.insert(
            dratchet_core::x3dh::bootstrap_mailbox_id(&fingerprint),
            fingerprint,
        );
        self.directory.insert(fingerprint, stored);
    }

    /// DRA-0049: is `mailbox_id` the bootstrap mailbox of an account other
    /// than `caller`? An O(1) lookup against the index above.
    pub fn bootstrap_mailbox_belongs_to_another(
        &self,
        mailbox_id: &MailboxId,
        caller: &Fingerprint,
    ) -> bool {
        self.bootstrap_mailbox_index
            .get(mailbox_id)
            .is_some_and(|owner| owner != caller)
    }
}

pub struct AppState {
    pub inner: RwLock<Inner>,
    /// `None` for every existing test and dev-default run: the directory
    /// stays exactly as in-memory-only as before. `Some` only when
    /// `crate::app_with_directory_db` built this state — see
    /// `crate::persistence` for what that closes.
    pub persistence: Option<crate::persistence::Persistence>,
    /// DRA-0031 — current live connection count, checked against
    /// `connection_cap` before each new upgrade. A plain `AtomicUsize`
    /// outside `inner`'s `RwLock`: every connection touches this on
    /// connect/disconnect, and it doesn't need to be consistent with any
    /// of `Inner`'s other state.
    pub active_connections: AtomicUsize,
    /// DRA-0031 — the ceiling `active_connections` is checked against.
    /// Always `MAX_CONCURRENT_CONNECTIONS` outside tests; overridable via
    /// [`AppState::new_with_connection_cap`] so a test can prove the cap
    /// is actually enforced without needing to open thousands of real
    /// connections against the real 10,000 default.
    pub connection_cap: usize,
}

impl AppState {
    pub fn new() -> Arc<Self> {
        Arc::new(AppState {
            inner: RwLock::new(Inner::default()),
            persistence: None,
            active_connections: AtomicUsize::new(0),
            connection_cap: MAX_CONCURRENT_CONNECTIONS,
        })
    }

    /// Like [`AppState::new`], but with a caller-chosen connection cap —
    /// a test-only convenience (DRA-0031's own regression test is the
    /// only caller) so the cap can be proven enforced at a small number
    /// instead of the real `MAX_CONCURRENT_CONNECTIONS`.
    #[allow(dead_code)]
    pub fn new_with_connection_cap(cap: usize) -> Arc<Self> {
        Arc::new(AppState {
            inner: RwLock::new(Inner::default()),
            persistence: None,
            active_connections: AtomicUsize::new(0),
            connection_cap: cap,
        })
    }

    /// Like [`AppState::new`], but the directory is seeded from — and
    /// every subsequent mutation to it written through to —
    /// `persistence`. See `crate::app_with_directory_db`, the only
    /// caller.
    pub fn with_persistence(persistence: crate::persistence::Persistence) -> Arc<Self> {
        let mut inner = Inner::default();
        for (fp, stored) in persistence.load_all() {
            let username_key = UsernameKey {
                username: stored.bundle.username.clone(),
                discriminator: stored.bundle.discriminator,
            };
            inner.username_index.insert(username_key, fp);
            inner.register_bundle(fp, stored);
        }
        tracing::info!(
            recovered = inner.directory.len(),
            "directory persistence: loaded from disk"
        );
        Arc::new(AppState {
            inner: RwLock::new(inner),
            persistence: Some(persistence),
            active_connections: AtomicUsize::new(0),
            connection_cap: MAX_CONCURRENT_CONNECTIONS,
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
