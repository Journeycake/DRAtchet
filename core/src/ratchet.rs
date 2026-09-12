//! Double Ratchet engine, per `docs/ARCHITECTURE.md` §3.3 and the reference
//! algorithm at <https://signal.org/docs/specifications/doubleratchet/>.
//!
//! This is the module that has to make good on the project's central claim:
//! that key rotation driven by turn-taking (not a literal per-message
//! keypair) tolerates queue depth — bursts of messages sent before a reply,
//! out-of-order delivery, and retries. See `tests/queue_depth.rs`.

use std::collections::{HashMap, VecDeque};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key as AeadKey, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::envelope::Envelope;
use crate::error::{Error, Result};
use crate::payload;

/// Bound on how many message keys may be derived-ahead-and-cached for a single
/// receiving chain before `decrypt` refuses and returns an error rather than
/// growing the cache unboundedly. Matches `MAX_SKIP` in `docs/ARCHITECTURE.md` §3.3.
/// Configurable per session within [`MIN_MAX_SKIP`, `MAX_MAX_SKIP`] — see
/// [`RatchetState::init_as_initiator`]/[`RatchetState::init_as_responder`].
pub const DEFAULT_MAX_SKIP: u32 = 100;

/// Lower bound on a configurable `max_skip`: below this, an ordinary burst of queued
/// messages (the scenario this whole project exists to handle — see
/// `docs/ARCHITECTURE.md` §1) risks tripping `MaxSkipExceeded` in normal use, not just
/// under attack.
pub const MIN_MAX_SKIP: u32 = 50;

/// Upper bound on a configurable `max_skip`: the skipped-key cache is a per-DH-key
/// `HashMap` a peer's own client has to hold in memory (and an unauthenticated forged
/// envelope's `pn` field, per §11.8 of `docs/ARCHITECTURE.md`, can force derivation up
/// to this bound before the AEAD check ultimately rejects it) — this caps how large a
/// single hostile or corrupted `pn`/`n` can force that derivation to grow.
pub const MAX_MAX_SKIP: u32 = 150;

/// Multiplier applied to `max_skip` to bound the *total* size of the skipped-message-key
/// cache across the ratchet's entire lifetime (many DH ratchet steps) — distinct from
/// the per-call bound `skip_and_derive` already enforces for a single chain. Without
/// this, a correspondent who keeps triggering DH ratchet steps while leaving old
/// messages permanently undelivered (a chronically flaky connection, or a malicious
/// already-paired peer) can grow `RatchetState::skipped` without bound: only a cache
/// *hit* in `decrypt_raw` ever removes an entry, and each new chain gets its own fresh
/// `max_skip`-sized budget on top of whatever's already cached from earlier chains.
/// Sized to comfortably hold a few legitimate full-width gaps at once (the
/// out-of-order-across-a-ratchet-boundary scenarios `tests/queue_depth.rs` exercises)
/// before the oldest, least-likely-to-still-arrive entries start getting evicted.
const SKIPPED_CACHE_LIFETIME_MULTIPLIER: usize = 4;

/// ChaCha20-Poly1305's authentication tag length; its ciphertext is always exactly
/// `plaintext.len() + AEAD_TAG_LEN` bytes.
const AEAD_TAG_LEN: usize = 16;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct DhPubBytes([u8; 32]);

/// A `(chain index, derived key)` pair — the unit `skip_and_derive` produces.
type ChainKeyEntry = (u32, [u8; 32]);
/// A skipped-message-key cache entry, keyed the same way `RatchetState::skipped` is.
type SkippedEntry = ((DhPubBytes, u32), Zeroizing<[u8; 32]>);

pub struct RatchetState {
    conversation_id: [u8; 16],
    max_skip: u32,

    // Key material lives in `Zeroizing` wrappers (and `StaticSecret`, which zeroizes
    // itself via x25519-dalek's "zeroize" feature) so it's overwritten on drop rather
    // than left sitting in freed memory — e.g. for a debugger or core dump to find.
    root_key: Zeroizing<[u8; 32]>,
    dh_self: Option<(StaticSecret, PublicKey)>,
    dh_remote: Option<PublicKey>,

    sending_chain_key: Option<Zeroizing<[u8; 32]>>,
    receiving_chain_key: Option<Zeroizing<[u8; 32]>>,

    send_n: u32,
    recv_n: u32,
    prev_chain_len: u32,

    skipped: HashMap<(DhPubBytes, u32), Zeroizing<[u8; 32]>>,
    /// Insertion order of `skipped`'s keys, oldest first — used to evict the oldest
    /// entries once the total cache exceeds its lifetime bound (see
    /// [`SKIPPED_CACHE_LIFETIME_MULTIPLIER`]). May contain stale entries for keys
    /// already removed from `skipped` via a cache hit; those are harmless no-ops when
    /// popped, since eviction only ever removes-if-present.
    skipped_order: VecDeque<(DhPubBytes, u32)>,
}

impl RatchetState {
    /// The X3DH initiator's ratchet: generates a fresh DH ratchet keypair immediately
    /// and derives a sending chain against the responder's already-known DH public key
    /// (their signed prekey, in the X3DH handshake).
    ///
    /// `max_skip` must fall within [`MIN_MAX_SKIP`, `MAX_MAX_SKIP`] — see
    /// [`validate_max_skip`] for why both bounds exist.
    pub fn init_as_initiator(
        conversation_id: [u8; 16],
        root_key: [u8; 32],
        responder_dh_public: PublicKey,
        max_skip: u32,
    ) -> Result<Self> {
        validate_max_skip(max_skip)?;

        let dh_self_secret = StaticSecret::random_from_rng(OsRng);
        let dh_self_public = PublicKey::from(&dh_self_secret);
        let dh_output = dh_self_secret.diffie_hellman(&responder_dh_public);
        let (new_root, sending_chain_key) = kdf_rk(&root_key, dh_output.as_bytes());

        Ok(RatchetState {
            conversation_id,
            max_skip,
            root_key: Zeroizing::new(new_root),
            dh_self: Some((dh_self_secret, dh_self_public)),
            dh_remote: Some(responder_dh_public),
            sending_chain_key: Some(Zeroizing::new(sending_chain_key)),
            receiving_chain_key: None,
            send_n: 0,
            recv_n: 0,
            prev_chain_len: 0,
            skipped: HashMap::new(),
            skipped_order: VecDeque::new(),
        })
    }

    /// The X3DH responder's ratchet: keeps using the DH keypair whose public half the
    /// initiator already X3DH'd against (typically the signed prekey), and doesn't
    /// derive a receiving chain until the initiator's first message actually arrives.
    ///
    /// `max_skip` must fall within [`MIN_MAX_SKIP`, `MAX_MAX_SKIP`] — see
    /// [`validate_max_skip`] for why both bounds exist.
    pub fn init_as_responder(
        conversation_id: [u8; 16],
        root_key: [u8; 32],
        own_dh_secret: StaticSecret,
        max_skip: u32,
    ) -> Result<Self> {
        validate_max_skip(max_skip)?;

        let own_dh_public = PublicKey::from(&own_dh_secret);
        Ok(RatchetState {
            conversation_id,
            max_skip,
            root_key: Zeroizing::new(root_key),
            dh_self: Some((own_dh_secret, own_dh_public)),
            dh_remote: None,
            sending_chain_key: None,
            receiving_chain_key: None,
            send_n: 0,
            recv_n: 0,
            prev_chain_len: 0,
            skipped: HashMap::new(),
            skipped_order: VecDeque::new(),
        })
    }

    /// Encrypt already-tagged-and-padded plaintext (see [`payload::tag_and_pad`]) into
    /// a wire-ready envelope. Most callers want [`RatchetState::encrypt_payload`] instead.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Envelope> {
        let dh_self_public = self
            .dh_self
            .as_ref()
            .map(|(_, public)| *public)
            .ok_or(Error::RatchetNotInitialized("dh_self"))?;
        let chain_key = copy_secret(
            self.sending_chain_key
                .as_ref()
                .ok_or(Error::RatchetNotInitialized("sending_chain_key"))?,
        );

        let (next_chain_key, message_key) = kdf_ck(&chain_key);
        self.sending_chain_key = Some(Zeroizing::new(next_chain_key));

        // `header_bytes()`'s `ciphertext_len` field must match what the *decoded*
        // envelope will actually carry, since it's part of the AEAD associated data —
        // a placeholder length here (e.g. an empty Vec) would make the AAD used to
        // encrypt differ from the AAD the receiver reconstructs, and every message
        // would fail to decrypt. ChaCha20Poly1305's ciphertext is always exactly
        // `plaintext.len() + AEAD_TAG_LEN`, so that length is known upfront.
        let header = Envelope {
            version: crate::envelope::CURRENT_VERSION,
            conversation_id: self.conversation_id,
            dh_pub: dh_self_public.to_bytes(),
            pn: self.prev_chain_len,
            n: self.send_n,
            ciphertext: vec![0u8; plaintext.len() + AEAD_TAG_LEN],
        };
        self.send_n += 1;

        let ciphertext = aead_encrypt(&message_key, &header.header_bytes(), plaintext)?;
        debug_assert_eq!(ciphertext.len(), header.ciphertext.len());
        Ok(Envelope {
            ciphertext,
            ..header
        })
    }

    /// Decrypt a received envelope, tagged plaintext still tag+padded — callers get the
    /// raw `(payload_type, content)` via `payload::untag_and_unpad` on the returned bytes,
    /// or use [`RatchetState::decrypt_payload`] to do that in one step.
    ///
    /// **Transactional by construction:** every derived key and potential DH ratchet
    /// step is computed into local variables first; `self` is only mutated *after* the
    /// AEAD tag has actually verified. A forged or corrupted envelope — carrying an
    /// arbitrary `dh_pub` an attacker made up — must be rejected without leaving any
    /// trace in the ratchet state. Applying the DH ratchet step before authentication
    /// would let a single unauthenticated envelope permanently desynchronize the
    /// conversation for both legitimate parties, even though that envelope itself gets
    /// correctly rejected — see `tests::garbage_envelope_does_not_desync_the_ratchet`.
    pub fn decrypt_raw(&mut self, envelope: &Envelope) -> Result<Vec<u8>> {
        let skipped_id = (DhPubBytes(envelope.dh_pub), envelope.n);

        // Fast path: an already-cached skipped-message key. Peek, don't remove, until
        // decryption actually succeeds — a failed attempt (corrupted transit, forged
        // envelope) must not discard a legitimately cached key that a correctly
        // retransmitted copy of the same message might still need.
        if let Some(message_key) = self.skipped.get(&skipped_id) {
            let plaintext =
                aead_decrypt(message_key, &envelope.header_bytes(), &envelope.ciphertext)?;
            self.skipped.remove(&skipped_id);
            return Ok(plaintext);
        }

        let incoming_dh = PublicKey::from(envelope.dh_pub);
        let ratchets = self.dh_remote != Some(incoming_dh);
        let mut newly_skipped: Vec<SkippedEntry> = Vec::new();

        // Exhaust (derive-and-stage, not yet commit) the remaining keys of the *old*
        // receiving chain up to the sender-reported previous chain length — matches
        // the reference algorithm's `SkipMessageKeys(state, header.pn)`, computed
        // against the *current* (pre-ratchet) chain key and remote key. `.as_ref()`
        // throughout this method: nothing is moved out of `self` until the commit at
        // the end, so a `?` bailing out early never leaves `self` half-mutated.
        if ratchets {
            if let (Some(old_chain_key), Some(old_dh_remote)) =
                (self.receiving_chain_key.as_ref(), self.dh_remote)
            {
                let (_, keys) = skip_and_derive(
                    self.recv_n,
                    copy_secret(old_chain_key),
                    envelope.pn,
                    self.max_skip,
                )?;
                newly_skipped.extend(
                    keys.into_iter().map(|(n, k)| {
                        ((DhPubBytes(old_dh_remote.to_bytes()), n), Zeroizing::new(k))
                    }),
                );
            }
        }

        let ratchet_step = if ratchets {
            let (dh_self_secret, _) = self
                .dh_self
                .as_ref()
                .ok_or(Error::RatchetNotInitialized("dh_self"))?;
            Some(compute_dh_ratchet_step(
                &self.root_key,
                dh_self_secret,
                &incoming_dh,
            ))
        } else {
            None
        };

        let (receiving_chain_key_before_n, recv_n_before_n) = match &ratchet_step {
            Some(step) => (step.new_receiving_chain_key, 0),
            None => (
                copy_secret(
                    self.receiving_chain_key
                        .as_ref()
                        .ok_or(Error::RatchetNotInitialized("receiving_chain_key"))?,
                ),
                self.recv_n,
            ),
        };
        let (chain_key_at_n, keys) = skip_and_derive(
            recv_n_before_n,
            receiving_chain_key_before_n,
            envelope.n,
            self.max_skip,
        )?;
        newly_skipped.extend(
            keys.into_iter()
                .map(|(n, k)| ((DhPubBytes(incoming_dh.to_bytes()), n), Zeroizing::new(k))),
        );
        let (final_receiving_chain_key, message_key) = kdf_ck(&chain_key_at_n);

        // The only fallible step from here on is AEAD verification — everything above
        // was pure computation. Nothing has touched `self` yet.
        let plaintext = aead_decrypt(&message_key, &envelope.header_bytes(), &envelope.ciphertext)?;

        // Commit: the tag verified, so this envelope is authentic. Apply every staged
        // change now.
        if let Some(step) = ratchet_step {
            self.root_key = Zeroizing::new(step.new_root_key);
            self.dh_self = Some((step.new_dh_self_secret, step.new_dh_self_public));
            self.dh_remote = Some(incoming_dh);
            self.prev_chain_len = self.send_n;
            self.send_n = 0;
            self.sending_chain_key = Some(Zeroizing::new(step.new_sending_chain_key));
        }
        self.receiving_chain_key = Some(Zeroizing::new(final_receiving_chain_key));
        self.recv_n = envelope.n + 1;
        for (id, key) in newly_skipped {
            self.skipped.insert(id, key);
            self.skipped_order.push_back(id);
        }
        self.evict_oldest_skipped_beyond_lifetime_bound();

        Ok(plaintext)
    }

    /// Enforce [`SKIPPED_CACHE_LIFETIME_MULTIPLIER`] `* max_skip` as a hard cap on the
    /// total skipped-key cache, evicting the oldest entries first. Called once per
    /// successful `decrypt_raw`, after any new entries from this call have already
    /// been inserted.
    fn evict_oldest_skipped_beyond_lifetime_bound(&mut self) {
        let cap = self.max_skip as usize * SKIPPED_CACHE_LIFETIME_MULTIPLIER;
        while self.skipped.len() > cap {
            match self.skipped_order.pop_front() {
                Some(oldest) => {
                    self.skipped.remove(&oldest);
                }
                // Every insertion into `skipped` is paired with a push onto
                // `skipped_order`, so this can't happen while `skipped` still has
                // more entries than the cap — but never spin if it somehow did.
                None => break,
            }
        }
    }

    pub fn decrypt_payload(&mut self, envelope: &Envelope) -> Result<(u8, Vec<u8>)> {
        let plaintext = self.decrypt_raw(envelope)?;
        payload::untag_and_unpad(&plaintext)
    }

    pub fn encrypt_payload(&mut self, payload_type: u8, content: &[u8]) -> Result<Envelope> {
        let tagged = payload::tag_and_pad(payload_type, content)?;
        self.encrypt(&tagged)
    }

    #[cfg(test)]
    pub fn skipped_key_count(&self) -> usize {
        self.skipped.len()
    }

    /// Serialize this ratchet's full live state to bytes — CBOR-encoded,
    /// covering every field (root key, both chain keys, the DH keypair, and
    /// the skipped-message-key cache). **Not an at-rest-safe format on its
    /// own**: this is exactly the key material forward secrecy protects, so
    /// a caller persisting these bytes (`store/`'s local database) must
    /// encrypt them first and never write them anywhere unencrypted.
    pub fn export(&self) -> Vec<u8> {
        let exported = ExportedRatchetState::from(self);
        let mut bytes = Vec::new();
        ciborium::into_writer(&exported, &mut bytes)
            .expect("CBOR encoding of a well-formed struct cannot fail");
        bytes
    }

    /// The inverse of [`RatchetState::export`] — reconstructs a ratchet
    /// exactly as it was at export time, ready to keep sending/receiving
    /// immediately, including its skipped-message-key cache (so a message
    /// that arrives late after a restart still decrypts).
    pub fn import(bytes: &[u8]) -> Result<Self> {
        let exported: ExportedRatchetState = ciborium::from_reader(bytes)
            .map_err(|_| Error::MalformedExportedState("not valid CBOR for this shape"))?;
        exported.try_into()
    }
}

#[derive(Serialize, Deserialize)]
struct ExportedSkippedEntry {
    #[serde(with = "serde_bytes")]
    dh_pub: Vec<u8>,
    n: u32,
    #[serde(with = "serde_bytes")]
    key: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct ExportedSkippedOrderEntry {
    #[serde(with = "serde_bytes")]
    dh_pub: Vec<u8>,
    n: u32,
}

/// Every field of [`RatchetState`], as plain bytes — the shape
/// [`RatchetState::export`]/[`RatchetState::import`] (de)serialize. Private:
/// nothing outside this module constructs one directly.
#[derive(Serialize, Deserialize)]
struct ExportedRatchetState {
    #[serde(with = "serde_bytes")]
    conversation_id: Vec<u8>,
    max_skip: u32,
    #[serde(with = "serde_bytes")]
    root_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    dh_self_secret: Option<Vec<u8>>,
    #[serde(with = "serde_bytes")]
    dh_self_public: Option<Vec<u8>>,
    #[serde(with = "serde_bytes")]
    dh_remote: Option<Vec<u8>>,
    #[serde(with = "serde_bytes")]
    sending_chain_key: Option<Vec<u8>>,
    #[serde(with = "serde_bytes")]
    receiving_chain_key: Option<Vec<u8>>,
    send_n: u32,
    recv_n: u32,
    prev_chain_len: u32,
    skipped: Vec<ExportedSkippedEntry>,
    skipped_order: Vec<ExportedSkippedOrderEntry>,
}

impl From<&RatchetState> for ExportedRatchetState {
    fn from(r: &RatchetState) -> Self {
        ExportedRatchetState {
            conversation_id: r.conversation_id.to_vec(),
            max_skip: r.max_skip,
            root_key: r.root_key.to_vec(),
            dh_self_secret: r.dh_self.as_ref().map(|(s, _)| s.to_bytes().to_vec()),
            dh_self_public: r.dh_self.as_ref().map(|(_, p)| p.as_bytes().to_vec()),
            dh_remote: r.dh_remote.map(|p| p.as_bytes().to_vec()),
            sending_chain_key: r.sending_chain_key.as_ref().map(|k| k.to_vec()),
            receiving_chain_key: r.receiving_chain_key.as_ref().map(|k| k.to_vec()),
            send_n: r.send_n,
            recv_n: r.recv_n,
            prev_chain_len: r.prev_chain_len,
            skipped: r
                .skipped
                .iter()
                .map(|((dh, n), k)| ExportedSkippedEntry {
                    dh_pub: dh.0.to_vec(),
                    n: *n,
                    key: k.to_vec(),
                })
                .collect(),
            skipped_order: r
                .skipped_order
                .iter()
                .map(|(dh, n)| ExportedSkippedOrderEntry {
                    dh_pub: dh.0.to_vec(),
                    n: *n,
                })
                .collect(),
        }
    }
}

fn to_array32(v: Vec<u8>, what: &'static str) -> Result<[u8; 32]> {
    v.try_into()
        .map_err(|_| Error::MalformedExportedState(what))
}

impl TryFrom<ExportedRatchetState> for RatchetState {
    type Error = Error;

    fn try_from(e: ExportedRatchetState) -> Result<Self> {
        let conversation_id: [u8; 16] = e
            .conversation_id
            .try_into()
            .map_err(|_| Error::MalformedExportedState("conversation_id"))?;

        let dh_self = match (e.dh_self_secret, e.dh_self_public) {
            (Some(s), Some(p)) => Some((
                StaticSecret::from(to_array32(s, "dh_self_secret")?),
                PublicKey::from(to_array32(p, "dh_self_public")?),
            )),
            (None, None) => None,
            _ => {
                return Err(Error::MalformedExportedState(
                    "dh_self must be fully present or fully absent",
                ))
            }
        };

        let skipped = e
            .skipped
            .into_iter()
            .map(|entry| -> Result<SkippedEntry> {
                let dh_pub = DhPubBytes(to_array32(entry.dh_pub, "skipped[].dh_pub")?);
                let key = Zeroizing::new(to_array32(entry.key, "skipped[].key")?);
                Ok(((dh_pub, entry.n), key))
            })
            .collect::<Result<HashMap<_, _>>>()?;

        let skipped_order = e
            .skipped_order
            .into_iter()
            .map(|entry| -> Result<(DhPubBytes, u32)> {
                Ok((
                    DhPubBytes(to_array32(entry.dh_pub, "skipped_order[].dh_pub")?),
                    entry.n,
                ))
            })
            .collect::<Result<VecDeque<_>>>()?;

        Ok(RatchetState {
            conversation_id,
            max_skip: e.max_skip,
            root_key: Zeroizing::new(to_array32(e.root_key, "root_key")?),
            dh_self,
            dh_remote: e
                .dh_remote
                .map(|p| to_array32(p, "dh_remote").map(PublicKey::from))
                .transpose()?,
            sending_chain_key: e
                .sending_chain_key
                .map(|k| to_array32(k, "sending_chain_key").map(Zeroizing::new))
                .transpose()?,
            receiving_chain_key: e
                .receiving_chain_key
                .map(|k| to_array32(k, "receiving_chain_key").map(Zeroizing::new))
                .transpose()?,
            send_n: e.send_n,
            recv_n: e.recv_n,
            prev_chain_len: e.prev_chain_len,
            skipped,
            skipped_order,
        })
    }
}

/// `KDF_RK`: root key + DH output -> (new root key, new chain key), via HKDF-SHA256.
fn kdf_rk(root_key: &[u8; 32], dh_output: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(Some(root_key), dh_output);
    let mut okm = [0u8; 64];
    hk.expand(b"dratchet-kdf-rk", &mut okm)
        .expect("64 is a valid HKDF-SHA256 output length");
    let mut new_root = [0u8; 32];
    let mut chain_key = [0u8; 32];
    new_root.copy_from_slice(&okm[..32]);
    chain_key.copy_from_slice(&okm[32..]);
    (new_root, chain_key)
}

/// `KDF_CK`: chain key -> (next chain key, message key), via two HMAC-SHA256 calls
/// over fixed single-byte inputs, per the reference Double Ratchet algorithm.
fn kdf_ck(chain_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut mac_ck =
        <HmacSha256 as Mac>::new_from_slice(chain_key).expect("HMAC accepts any key length");
    mac_ck.update(&[0x02]);
    let next_chain_key: [u8; 32] = mac_ck.finalize().into_bytes().into();

    let mut mac_mk =
        <HmacSha256 as Mac>::new_from_slice(chain_key).expect("HMAC accepts any key length");
    mac_mk.update(&[0x01]);
    let message_key: [u8; 32] = mac_mk.finalize().into_bytes().into();

    (next_chain_key, message_key)
}

/// Extract a plain, `Copy`-able array from a zeroizing wrapper, for handing to the
/// pure (non-`self`-touching) helper functions below — the wrapper stays intact and
/// still zeroizes its own storage on drop; this only copies its *current* value out
/// for one short-lived local computation.
fn copy_secret(z: &Zeroizing<[u8; 32]>) -> [u8; 32] {
    let borrowed: &[u8; 32] = z;
    *borrowed
}

/// Reject a `max_skip` outside [`MIN_MAX_SKIP`, `MAX_MAX_SKIP`]. Both bounds are
/// deliberate, not arbitrary: too low and an ordinary queued burst (the exact scenario
/// `docs/ARCHITECTURE.md` §1 exists to handle) can trip `MaxSkipExceeded` in normal
/// use; too high and a single hostile or corrupted envelope's `pn`/`n` field can force
/// a correspondingly larger, wasted skipped-key derivation before the AEAD check
/// ultimately rejects it (§11.8) — this is a memory/CPU bound on that, not just a
/// queue-depth allowance.
fn validate_max_skip(max_skip: u32) -> Result<()> {
    if (MIN_MAX_SKIP..=MAX_MAX_SKIP).contains(&max_skip) {
        Ok(())
    } else {
        Err(Error::InvalidMaxSkip {
            got: max_skip,
            min: MIN_MAX_SKIP,
            max: MAX_MAX_SKIP,
        })
    }
}

/// Derive-and-return message keys for chain indices `[from, until)` — exclusive of
/// `until` — advancing `chain_key` via `KDF_CK` at each step, without mutating any
/// ratchet state. Returns the derived `(index, message_key)` pairs plus the chain key
/// state *after* deriving through index `until - 1`. Bounded by `max_skip`, same as
/// the reference algorithm's `SkipMessageKeys`.
fn skip_and_derive(
    from: u32,
    chain_key: [u8; 32],
    until: u32,
    max_skip: u32,
) -> Result<([u8; 32], Vec<ChainKeyEntry>)> {
    if from.saturating_add(max_skip) < until {
        return Err(Error::MaxSkipExceeded(max_skip));
    }
    let mut chain_key = chain_key;
    let mut keys = Vec::new();
    let mut n = from;
    while n < until {
        let (next_chain_key, message_key) = kdf_ck(&chain_key);
        keys.push((n, message_key));
        chain_key = next_chain_key;
        n += 1;
    }
    Ok((chain_key, keys))
}

/// The result of a (not-yet-committed) DH ratchet step — pure computation, no `&mut
/// self`, so a caller can discard it entirely if authentication ultimately fails.
struct RatchetStep {
    new_root_key: [u8; 32],
    new_receiving_chain_key: [u8; 32],
    new_sending_chain_key: [u8; 32],
    new_dh_self_secret: StaticSecret,
    new_dh_self_public: PublicKey,
}

fn compute_dh_ratchet_step(
    root_key: &[u8; 32],
    dh_self_secret: &StaticSecret,
    incoming_dh: &PublicKey,
) -> RatchetStep {
    let dh_output = dh_self_secret.diffie_hellman(incoming_dh);
    let (root_after_recv, receiving_chain_key) = kdf_rk(root_key, dh_output.as_bytes());

    let new_secret = StaticSecret::random_from_rng(OsRng);
    let new_public = PublicKey::from(&new_secret);
    let dh_output = new_secret.diffie_hellman(incoming_dh);
    let (root_after_send, sending_chain_key) = kdf_rk(&root_after_recv, dh_output.as_bytes());

    RatchetStep {
        new_root_key: root_after_send,
        new_receiving_chain_key: receiving_chain_key,
        new_sending_chain_key: sending_chain_key,
        new_dh_self_secret: new_secret,
        new_dh_self_public: new_public,
    }
}

/// Derive the AEAD encryption key and nonce from a single-use message key, per
/// `docs/MESSAGE_SCHEMA.md` §2 ("Nonce: not transmitted").
fn derive_message_cipher(message_key: &[u8; 32]) -> (AeadKey, Nonce) {
    let hk = Hkdf::<Sha256>::new(None, message_key);
    let mut okm = [0u8; 44];
    hk.expand(b"dratchet-message-key", &mut okm)
        .expect("44 is a valid HKDF-SHA256 output length");
    let key = *AeadKey::from_slice(&okm[..32]);
    let nonce = *Nonce::from_slice(&okm[32..44]);
    (key, nonce)
}

fn aead_encrypt(message_key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let (key, nonce) = derive_message_cipher(message_key);
    let cipher = ChaCha20Poly1305::new(&key);
    cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Aead)
}

fn aead_decrypt(message_key: &[u8; 32], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let (key, nonce) = derive_message_cipher(message_key);
    let cipher = ChaCha20Poly1305::new(&key);
    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::Aead)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payload::{untag_and_unpad, PAYLOAD_CHAT};

    /// A matched initiator/responder ratchet pair sharing a root key, as if X3DH had
    /// already run (see `tests/x3dh_and_ratchet.rs` for the full handshake version).
    fn matched_pair() -> (RatchetState, RatchetState) {
        let conversation_id = [1u8; 16];
        let root_key = [42u8; 32];
        let responder_secret = StaticSecret::random_from_rng(OsRng);
        let responder_public = PublicKey::from(&responder_secret);

        let initiator = RatchetState::init_as_initiator(
            conversation_id,
            root_key,
            responder_public,
            DEFAULT_MAX_SKIP,
        )
        .unwrap();
        let responder = RatchetState::init_as_responder(
            conversation_id,
            root_key,
            responder_secret,
            DEFAULT_MAX_SKIP,
        )
        .unwrap();
        (initiator, responder)
    }

    fn chat(plaintext: &str) -> Vec<u8> {
        payload::tag_and_pad(PAYLOAD_CHAT, plaintext.as_bytes()).unwrap()
    }

    fn read_chat(bytes: &[u8]) -> String {
        let (ty, content) = untag_and_unpad(bytes).unwrap();
        assert_eq!(ty, PAYLOAD_CHAT);
        String::from_utf8(content).unwrap()
    }

    #[test]
    fn basic_round_trip_initiator_to_responder() {
        let (mut alice, mut bob) = matched_pair();
        let envelope = alice.encrypt(&chat("hello")).unwrap();
        let plaintext = bob.decrypt_raw(&envelope).unwrap();
        assert_eq!(read_chat(&plaintext), "hello");
    }

    /// Every other test in this module passes `Envelope` structs directly between
    /// `encrypt`/`decrypt_raw` in memory — that's never how a message actually travels.
    /// This is the one test that puts the fixed-layout wire encoding (`Envelope::encode`/
    /// `decode`, `docs/MESSAGE_SCHEMA.md` §2) in the loop the way a real transport would:
    /// bytes out, bytes in, across several turns including a DH ratchet step.
    #[test]
    fn survives_the_actual_wire_encoding_across_several_turns() {
        let (mut alice, mut bob) = matched_pair();

        let wire = alice.encrypt(&chat("turn 1")).unwrap().encode();
        let received = Envelope::decode(&wire).unwrap();
        assert_eq!(read_chat(&bob.decrypt_raw(&received).unwrap()), "turn 1");

        let wire = bob.encrypt(&chat("turn 2")).unwrap().encode();
        let received = Envelope::decode(&wire).unwrap();
        assert_eq!(read_chat(&alice.decrypt_raw(&received).unwrap()), "turn 2");

        let wire = alice.encrypt(&chat("turn 3")).unwrap().encode();
        let received = Envelope::decode(&wire).unwrap();
        assert_eq!(read_chat(&bob.decrypt_raw(&received).unwrap()), "turn 3");
    }

    /// The security property the whole "single-use message key" design rests on,
    /// checked directly rather than only implied by other tests passing: iterating
    /// `KDF_CK` never produces a repeated message key or chain key. A repeated message
    /// key would mean a repeated (key, nonce) pair handed to ChaCha20-Poly1305 — a
    /// catastrophic AEAD failure (nonce reuse breaks both confidentiality and
    /// authentication for the two messages involved). This can't be proven for all
    /// possible inputs by a test, but 100,000 consecutive steps from a fixed starting
    /// point give real confidence against a gross implementation bug (e.g. an
    /// accidentally-constant key, or the chain key not actually advancing).
    #[test]
    fn chain_key_derivation_never_repeats_across_many_iterations() {
        use std::collections::HashSet;

        let mut chain_key = [7u8; 32];
        let mut seen_message_keys = HashSet::new();
        let mut seen_chain_keys = HashSet::new();
        for step in 0..100_000 {
            let (next_chain_key, message_key) = kdf_ck(&chain_key);
            assert!(
                seen_message_keys.insert(message_key),
                "message key repeated at step {step} — would mean AEAD key/nonce reuse"
            );
            assert!(
                seen_chain_keys.insert(chain_key),
                "chain key repeated at step {step} — the ratchet chain would be cycling"
            );
            chain_key = next_chain_key;
        }
    }

    #[test]
    fn turn_taking_dh_ratchet_both_directions() {
        let (mut alice, mut bob) = matched_pair();

        let e1 = alice.encrypt(&chat("hi bob")).unwrap();
        assert_eq!(read_chat(&bob.decrypt_raw(&e1).unwrap()), "hi bob");

        // Bob's reply carries a *new* DH public key (his first ratchet step) — this is
        // "the next message's public key" from the original brief.
        let e2 = bob.encrypt(&chat("hi alice")).unwrap();
        assert_ne!(e2.dh_pub, e1.dh_pub);
        assert_eq!(read_chat(&alice.decrypt_raw(&e2).unwrap()), "hi alice");

        // And Alice's next reply ratchets again, against Bob's new key.
        let e3 = alice.encrypt(&chat("how are you")).unwrap();
        assert_ne!(e3.dh_pub, e1.dh_pub);
        assert_eq!(read_chat(&bob.decrypt_raw(&e3).unwrap()), "how are you");
    }

    #[test]
    fn many_messages_before_any_reply_all_decrypt_in_order() {
        let (mut alice, mut bob) = matched_pair();
        let sent: Vec<_> = (0..20)
            .map(|i| alice.encrypt(&chat(&format!("message {i}"))).unwrap())
            .collect();
        for (i, envelope) in sent.iter().enumerate() {
            let plaintext = bob.decrypt_raw(envelope).unwrap();
            assert_eq!(read_chat(&plaintext), format!("message {i}"));
        }
    }

    #[test]
    fn out_of_order_delivery_within_one_chain_still_decrypts() {
        let (mut alice, mut bob) = matched_pair();
        let e0 = alice.encrypt(&chat("zero")).unwrap();
        let e1 = alice.encrypt(&chat("one")).unwrap();
        let e2 = alice.encrypt(&chat("two")).unwrap();

        // Deliver 2, then 0, then 1 — the skipped-key cache should have picked up
        // slots 0 and 1 while decrypting message 2 out of turn.
        assert_eq!(read_chat(&bob.decrypt_raw(&e2).unwrap()), "two");
        assert_eq!(bob.skipped_key_count(), 2);
        assert_eq!(read_chat(&bob.decrypt_raw(&e0).unwrap()), "zero");
        assert_eq!(read_chat(&bob.decrypt_raw(&e1).unwrap()), "one");
        assert_eq!(bob.skipped_key_count(), 0);
    }

    #[test]
    fn out_of_order_delivery_across_a_dh_ratchet_step_still_decrypts() {
        let (mut alice, mut bob) = matched_pair();
        let a0 = alice.encrypt(&chat("a0")).unwrap();
        let a1 = alice.encrypt(&chat("a1")).unwrap();

        // Bob must process at least one message before he can reply — a responder's
        // sending chain is only established as a side effect of the DH ratchet step
        // triggered by processing an incoming message (`RatchetInitBob` starts with
        // no sending chain at all).
        assert_eq!(read_chat(&bob.decrypt_raw(&a0).unwrap()), "a0");

        let b0 = bob.encrypt(&chat("b0")).unwrap();
        assert_eq!(read_chat(&alice.decrypt_raw(&b0).unwrap()), "b0");
        let a2 = alice.encrypt(&chat("a2")).unwrap(); // ratchets again, against Bob's new key

        // a1 is still pending from *before* Bob's reply (his old receiving chain);
        // a2 is from *after* it (his new one, following his own DH ratchet step).
        // Deliver the newer one first — the skipped-key cache has to bridge across
        // the DH ratchet boundary to still make sense of a1 once it arrives.
        assert_eq!(read_chat(&bob.decrypt_raw(&a2).unwrap()), "a2");
        assert_eq!(read_chat(&bob.decrypt_raw(&a1).unwrap()), "a1");
    }

    #[test]
    fn each_message_key_is_single_use_replay_is_rejected() {
        let (mut alice, mut bob) = matched_pair();
        let e0 = alice.encrypt(&chat("only once")).unwrap();
        assert!(bob.decrypt_raw(&e0).is_ok());
        // Replaying the same envelope: the message key was consumed and the chain has
        // moved on, so this must fail rather than silently succeed again.
        assert!(bob.decrypt_raw(&e0).is_err());
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let (mut alice, mut bob) = matched_pair();
        let mut e0 = alice.encrypt(&chat("hello")).unwrap();
        let last = e0.ciphertext.len() - 1;
        e0.ciphertext[last] ^= 0xFF;
        assert!(matches!(bob.decrypt_raw(&e0), Err(Error::Aead)));
    }

    #[test]
    fn tampered_header_is_rejected_even_though_ciphertext_is_untouched() {
        let (mut alice, mut bob) = matched_pair();
        let mut e0 = alice.encrypt(&chat("hello")).unwrap();
        e0.n = 5; // header field, part of the AEAD associated data
        assert!(matches!(bob.decrypt_raw(&e0), Err(Error::Aead)));
    }

    #[test]
    fn skipping_beyond_max_skip_is_rejected_not_silently_unbounded() {
        let conversation_id = [1u8; 16];
        let root_key = [7u8; 32];
        let responder_secret = StaticSecret::random_from_rng(OsRng);
        let responder_public = PublicKey::from(&responder_secret);
        let small_max_skip = MIN_MAX_SKIP; // the smallest value the configurable range allows

        let mut alice = RatchetState::init_as_initiator(
            conversation_id,
            root_key,
            responder_public,
            small_max_skip,
        )
        .unwrap();
        let mut bob = RatchetState::init_as_responder(
            conversation_id,
            root_key,
            responder_secret,
            small_max_skip,
        )
        .unwrap();

        let burst = small_max_skip + 10;
        let mut last = None;
        for i in 0..burst {
            last = Some(alice.encrypt(&chat(&format!("msg {i}"))).unwrap());
        }
        // Only the last message of the burst arrives; the skipped-key cache would need
        // to derive-and-cache the rest, which exceeds max_skip.
        assert!(matches!(
            bob.decrypt_raw(&last.unwrap()),
            Err(Error::MaxSkipExceeded(skip)) if skip == small_max_skip
        ));
    }

    /// Delivery-failure scenario: within one real burst, the last-arriving
    /// message is impossibly far ahead (exactly the case above) — but does
    /// rejecting it leave the conversation usable for whichever *other*
    /// messages in the same burst are actually within reach? The doc
    /// comment on `decrypt_raw` promises the rejection is "transactional"
    /// with no side effects; this pins that promise down as a behavioral
    /// test, not just a doc claim — the practical answer to "did one
    /// undeliverable message wedge the whole conversation."
    #[test]
    fn a_maxskipexceeded_rejection_does_not_wedge_the_conversation_for_reachable_messages() {
        let conversation_id = [1u8; 16];
        let root_key = [7u8; 32];
        let responder_secret = StaticSecret::random_from_rng(OsRng);
        let responder_public = PublicKey::from(&responder_secret);
        let small_max_skip = MIN_MAX_SKIP;

        let mut alice = RatchetState::init_as_initiator(
            conversation_id,
            root_key,
            responder_public,
            small_max_skip,
        )
        .unwrap();
        let mut bob = RatchetState::init_as_responder(
            conversation_id,
            root_key,
            responder_secret,
            small_max_skip,
        )
        .unwrap();

        // Wide enough that the last message stays unreachable even *after*
        // Bob catches up to the reachable one below — a tighter burst (e.g.
        // `small_max_skip + 10`) turned out, in an earlier version of this
        // test, to let the "unreachable" message become reachable once
        // Bob's position advanced close enough — a real, useful finding in
        // its own right (reachability is relative to *current* position,
        // not fixed at arrival time), but not the thing this test is
        // proving, so the gap here is widened to keep the two effects
        // separate.
        let burst_size = small_max_skip * 4;
        let envelopes: Vec<_> = (0..burst_size)
            .map(|i| alice.encrypt(&chat(&format!("msg {i}"))).unwrap())
            .collect();

        // The far-ahead message is rejected, exactly as the sibling test
        // above already proves.
        assert!(matches!(
            bob.decrypt_raw(&envelopes[(burst_size - 1) as usize]),
            Err(Error::MaxSkipExceeded(_))
        ));

        // A message from earlier in the *same* burst, still within reach of
        // Bob's (untouched) starting position, must still decrypt — the
        // failed attempt above left no trace to interfere with it.
        let reachable_index = (small_max_skip / 2) as usize;
        let recovered = bob
            .decrypt_raw(&envelopes[reachable_index])
            .expect("an in-range message must decrypt fine after a prior rejection");
        assert_eq!(read_chat(&recovered), format!("msg {reachable_index}"));

        // The specific far-ahead message is still out of reach even from
        // Bob's now-advanced position (burst_size - reachable_index still
        // exceeds max_skip) — genuinely unrecoverable, not a bug, just the
        // inherent limit: it never arrives again once nothing will ever
        // bring the gap back within max_skip.
        assert!(matches!(
            bob.decrypt_raw(&envelopes[(burst_size - 1) as usize]),
            Err(Error::MaxSkipExceeded(_))
        ));
    }

    #[test]
    fn max_skip_outside_the_configurable_range_is_rejected() {
        let conversation_id = [1u8; 16];
        let root_key = [7u8; 32];
        let responder_secret = StaticSecret::random_from_rng(OsRng);
        let responder_public = PublicKey::from(&responder_secret);

        assert!(matches!(
            RatchetState::init_as_initiator(conversation_id, root_key, responder_public, MIN_MAX_SKIP - 1),
            Err(Error::InvalidMaxSkip { got, min, max }) if got == MIN_MAX_SKIP - 1 && min == MIN_MAX_SKIP && max == MAX_MAX_SKIP
        ));
        assert!(matches!(
            RatchetState::init_as_initiator(conversation_id, root_key, responder_public, MAX_MAX_SKIP + 1),
            Err(Error::InvalidMaxSkip { got, .. }) if got == MAX_MAX_SKIP + 1
        ));
        // The whole supported range must actually be accepted, not just its interior.
        assert!(RatchetState::init_as_initiator(
            conversation_id,
            root_key,
            responder_public,
            MIN_MAX_SKIP
        )
        .is_ok());
        assert!(RatchetState::init_as_initiator(
            conversation_id,
            root_key,
            responder_public,
            MAX_MAX_SKIP
        )
        .is_ok());
        assert!(RatchetState::init_as_responder(
            conversation_id,
            root_key,
            responder_secret,
            MIN_MAX_SKIP - 1
        )
        .is_err());
    }

    /// Regression test for a real vulnerability found while reviewing this module: an
    /// unauthenticated attacker who doesn't hold any real key can still cause a DH
    /// ratchet step by sending an envelope with an arbitrary `dh_pub` (a fresh,
    /// unrelated keypair) and garbage ciphertext. Before the fix, `decrypt_raw` applied
    /// the DH ratchet step's state mutation *before* checking the AEAD tag, so even
    /// though the forged envelope itself was correctly rejected, the receiver's ratchet
    /// state was already corrupted — `dh_remote` now pointed at the attacker's bogus
    /// key, permanently desynchronizing the conversation the next time the real peer
    /// sent a legitimate message. `decrypt_raw` is now transactional: everything is
    /// computed into locals and only committed to `self` after the AEAD tag verifies.
    #[test]
    fn garbage_envelope_does_not_desync_the_ratchet() {
        let (mut alice, mut bob) = matched_pair();

        let e0 = alice.encrypt(&chat("message 1")).unwrap();
        assert_eq!(read_chat(&bob.decrypt_raw(&e0).unwrap()), "message 1");

        // An attacker with no knowledge of any real key forges an envelope using a
        // freshly generated, completely unrelated keypair.
        let attacker_secret = StaticSecret::random_from_rng(OsRng);
        let attacker_public = PublicKey::from(&attacker_secret);
        let forged = Envelope {
            version: crate::envelope::CURRENT_VERSION,
            conversation_id: [1u8; 16],
            dh_pub: attacker_public.to_bytes(),
            pn: 0,
            n: 0,
            ciphertext: vec![0u8; 48],
        };
        assert!(
            matches!(bob.decrypt_raw(&forged), Err(Error::Aead)),
            "a forged envelope must be rejected as an AEAD failure"
        );

        // Alice, unaware anything happened, sends her next real message using her
        // unchanged keypair. It must still decrypt cleanly — the rejected forgery
        // must have left no trace in Bob's ratchet state.
        let e1 = alice.encrypt(&chat("message 2")).unwrap();
        assert_eq!(
            read_chat(&bob.decrypt_raw(&e1).unwrap()),
            "message 2",
            "a single rejected forged envelope must not desynchronize the conversation"
        );

        // And the conversation keeps working normally afterward, in both directions.
        let e2 = bob.encrypt(&chat("message 3")).unwrap();
        assert_eq!(read_chat(&alice.decrypt_raw(&e2).unwrap()), "message 3");
    }

    /// The same probe, but the forged envelope arrives *instead of* — not alongside —
    /// a legitimate first contact from an unknown-to-Bob key, and with a `pn` that
    /// claims a large previous chain length. Before the fix this could also be used to
    /// force a large, wasted skipped-key derivation as a side effect of a step that
    /// ultimately gets discarded; confirms the bound still applies and nothing is
    /// committed on failure.
    #[test]
    fn garbage_envelope_with_inflated_pn_is_rejected_without_side_effects() {
        let (mut alice, mut bob) = matched_pair();
        let e0 = alice.encrypt(&chat("hi")).unwrap();
        assert_eq!(read_chat(&bob.decrypt_raw(&e0).unwrap()), "hi");

        let attacker_secret = StaticSecret::random_from_rng(OsRng);
        let attacker_public = PublicKey::from(&attacker_secret);
        let forged = Envelope {
            version: crate::envelope::CURRENT_VERSION,
            conversation_id: [1u8; 16],
            dh_pub: attacker_public.to_bytes(),
            pn: 10_000_000,
            n: 0,
            ciphertext: vec![0u8; 48],
        };
        // Either an AEAD failure or a MaxSkipExceeded is an acceptable rejection here —
        // what matters is that it's rejected, and rejected without mutating state.
        assert!(bob.decrypt_raw(&forged).is_err());
        assert_eq!(
            bob.skipped_key_count(),
            0,
            "a rejected forgery must not populate the skipped-key cache"
        );

        let e1 = alice.encrypt(&chat("still fine")).unwrap();
        assert_eq!(read_chat(&bob.decrypt_raw(&e1).unwrap()), "still fine");
    }

    /// Regression test for a real bug found while auditing this module: the
    /// per-derivation `max_skip` bound only caps how many keys a *single*
    /// `skip_and_derive` call may produce; nothing previously capped the *total*
    /// `skipped` cache across many DH ratchet steps. A correspondent who keeps
    /// ratcheting forward (replying) while leaving one message per round
    /// permanently undelivered — plausible with a flaky connection, or a malicious
    /// already-paired peer — grew the cache linearly forever, since only a cache
    /// *hit* in `decrypt_raw` ever removes an entry. Confirmed empirically before
    /// the fix: 30 such rounds left exactly 30 entries cached, ~30x the naive
    /// expectation that `max_skip` alone bounds this. `evict_oldest_skipped_beyond_
    /// lifetime_bound` now caps the total at `max_skip * SKIPPED_CACHE_LIFETIME_
    /// MULTIPLIER`, evicting oldest-first.
    #[test]
    fn skipped_cache_is_bounded_across_many_dh_ratchet_steps() {
        let (mut alice, mut bob) = matched_pair();
        let cap = DEFAULT_MAX_SKIP as usize * SKIPPED_CACHE_LIFETIME_MULTIPLIER;

        // Every round: Alice sends a message that's never delivered (a permanent gap),
        // then one that is; Bob replies, forcing his own ratchet forward each time.
        // None of the gap keys are ever consumed, so without a lifetime bound this
        // cache would grow by one entry every round, forever.
        for round in 0..(cap * 3) {
            let _never_delivered = alice.encrypt(&chat(&format!("gap {round}"))).unwrap();
            let delivered = alice.encrypt(&chat(&format!("delivered {round}"))).unwrap();
            bob.decrypt_raw(&delivered).unwrap();
            let reply = bob.encrypt(&chat(&format!("reply {round}"))).unwrap();
            alice.decrypt_raw(&reply).unwrap();
        }

        assert!(
            bob.skipped_key_count() <= cap,
            "skipped-key cache grew to {} entries, past its {}-entry lifetime cap",
            bob.skipped_key_count(),
            cap
        );
    }

    /// The eviction the previous test relies on must not throw away keys a *legitimate*
    /// late arrival still needs, as long as the total in flight stays under the cap —
    /// only genuinely never-consumed old entries should ever be at risk.
    #[test]
    fn eviction_does_not_break_a_legitimate_late_arrival_within_the_cap() {
        let (mut alice, mut bob) = matched_pair();

        let stray = alice.encrypt(&chat("delivered very late")).unwrap();
        // A handful of further turns, well under the lifetime cap, none of which
        // should evict `stray`'s still-pending skipped key.
        for round in 0..5 {
            let from_alice = alice.encrypt(&chat(&format!("a{round}"))).unwrap();
            bob.decrypt_raw(&from_alice).unwrap();
            let from_bob = bob.encrypt(&chat(&format!("b{round}"))).unwrap();
            alice.decrypt_raw(&from_bob).unwrap();
        }

        assert_eq!(
            read_chat(&bob.decrypt_raw(&stray).unwrap()),
            "delivered very late",
            "a late arrival well within the cache's lifetime cap must still decrypt"
        );
    }

    /// A full copy of a `RatchetState`'s live fields, as if an attacker had exfiltrated
    /// a process's entire memory at this instant — not a public `Clone` impl (the
    /// production type deliberately doesn't offer one; nothing legitimate needs to
    /// duplicate live ratchet secrets), just direct field access from within this
    /// module, the same way `matched_pair` already builds `RatchetState`s directly.
    fn snapshot(r: &RatchetState) -> RatchetState {
        RatchetState {
            conversation_id: r.conversation_id,
            max_skip: r.max_skip,
            root_key: r.root_key.clone(),
            dh_self: r.dh_self.clone(),
            dh_remote: r.dh_remote,
            sending_chain_key: r.sending_chain_key.clone(),
            receiving_chain_key: r.receiving_chain_key.clone(),
            send_n: r.send_n,
            recv_n: r.recv_n,
            prev_chain_len: r.prev_chain_len,
            skipped: r.skipped.clone(),
            skipped_order: r.skipped_order.clone(),
        }
    }

    /// `docs/ARCHITECTURE.md` §2 goal 1: "compromise of a current key must not expose
    /// past messages." Checked directly: an attacker who exfiltrates Bob's *entire*
    /// live state right after he's processed a run of messages still cannot decrypt any
    /// of them again from that snapshot — the chain key has already moved past them via
    /// `KDF_CK`'s one-way step, and no message key is ever retained once consumed (see
    /// `decrypt_raw`'s doc comment: nothing is stored beyond the advanced chain key
    /// until a *skip* is involved, which none of these are). This isn't the same claim
    /// as `each_message_key_is_single_use_replay_is_rejected` below: that test replays
    /// against the *same* object, which could in principle be explained away as mere
    /// bookkeeping ("already marked used"). Here the attempt runs against a completely
    /// independent, freshly-built `RatchetState` holding nothing but the snapshotted
    /// key material — so a decrypt failure here means the key genuinely isn't
    /// recoverable from that state, not that some other field remembers it was used.
    #[test]
    fn forward_secrecy_a_full_state_leak_cannot_decrypt_already_consumed_messages() {
        let (mut alice, mut bob) = matched_pair();

        let history: Vec<Envelope> = (0..5)
            .map(|i| alice.encrypt(&chat(&format!("secret {i}"))).unwrap())
            .collect();
        for envelope in &history {
            bob.decrypt_raw(envelope).unwrap();
        }

        // The leak: an attacker walks away with a complete copy of Bob's live state,
        // right after he's read all five messages.
        let mut attacker = snapshot(&bob);

        for (i, envelope) in history.iter().enumerate() {
            assert!(
                attacker.decrypt_raw(envelope).is_err(),
                "leaked state decrypted an already-consumed message (index {i}) — \
                 forward secrecy violated"
            );
        }

        // The leak isn't a generally broken clone, though — specifically the *past* is
        // unrecoverable. The attacker's copy is still a live, functioning ratchet that
        // (for now — see the post-compromise test below) can keep reading new traffic,
        // same as the real Bob could.
        let next = alice.encrypt(&chat("not secret yet")).unwrap();
        assert_eq!(
            read_chat(&attacker.decrypt_raw(&next).unwrap()),
            "not secret yet"
        );
    }

    /// `docs/ARCHITECTURE.md` §2 goal 2: "post-compromise (self-healing) security:
    /// after a compromise, the session heals." A one-time leak of Bob's full live state
    /// does *not* compromise the conversation forever — checked directly, not just
    /// asserted. The mechanism: `compute_dh_ratchet_step` draws a fresh `StaticSecret`
    /// from `OsRng` every time a party *receives* a new incoming DH key. An attacker's
    /// frozen snapshot, run forward on its own, draws its *own* independent randomness
    /// at that same step — so the instant both the real Bob and the attacker's copy
    /// have each processed one more incoming ratcheted message since the leak, their
    /// two DH keypairs are different values that happen to share an origin, not the
    /// same secret. The exposure isn't instantaneous, though, and this test checks the
    /// honest shape of it, not just the eventual good outcome: the very next ratcheted
    /// message after the leak is *still* readable by the attacker (it was already
    /// determined by key material the snapshot has), and only the one after *that* —
    /// once fresh randomness has actually been drawn on both sides — is finally out of
    /// reach.
    #[test]
    fn post_compromise_security_heals_after_the_next_ratchet_step() {
        let (mut alice, mut bob) = matched_pair();

        // Bob's first ratchet step, bootstrapping his receiving chain against Alice's
        // initial ephemeral key.
        let msg0 = alice.encrypt(&chat("msg0")).unwrap();
        bob.decrypt_raw(&msg0).unwrap();

        // The leak: right here, right after Bob's first ratchet.
        let mut attacker = snapshot(&bob);

        // Bob replies (no ratchet on send); Alice decrypts and ratchets, establishing a
        // fresh sending chain of her own.
        let msg1 = bob.encrypt(&chat("msg1")).unwrap();
        alice.decrypt_raw(&msg1).unwrap();

        // Alice's reply carries *her* fresh key — the first incoming ratchet either Bob
        // or the attacker's frozen copy has seen since the leak. Both still have the
        // exact same pre-ratchet state (Bob hasn't received anything in between), so
        // both can still derive the correct receiving chain from it: this message is
        // still exposed.
        let msg2 = alice.encrypt(&chat("msg2")).unwrap();
        assert_eq!(read_chat(&bob.decrypt_raw(&msg2).unwrap()), "msg2");
        assert_eq!(
            read_chat(&attacker.decrypt_raw(&msg2).unwrap()),
            "msg2",
            "the first post-leak ratchet is expected to still be exposed — healing \
             takes one more step"
        );

        // But processing msg2 just drew fresh randomness independently on *both* the
        // real Bob and the attacker's copy — two different `OsRng` calls, two
        // different new DH secrets. From here on they've diverged. Bob's next reply is
        // encrypted under a sending chain the attacker's copy has no way to derive.
        let msg3 = bob.encrypt(&chat("msg3")).unwrap();
        assert_eq!(read_chat(&alice.decrypt_raw(&msg3).unwrap()), "msg3");
        assert!(
            attacker.decrypt_raw(&msg3).is_err(),
            "leaked state decrypted a message sent after the session had healed — \
             post-compromise security violated"
        );
    }

    /// `export`/`import` (Phase 1.5.1 — local storage needs a ratchet to
    /// survive an app restart) must round-trip a ratchet well enough to
    /// keep chatting in both directions afterward, not just decode without
    /// erroring.
    #[test]
    fn export_then_import_can_still_send_and_receive_in_both_directions() {
        let (mut alice, mut bob) = matched_pair();

        // Some real history before the "restart", so more than just a
        // freshly-initialized ratchet gets exercised.
        let a0 = alice.encrypt(&chat("before restart, from alice")).unwrap();
        assert_eq!(
            read_chat(&bob.decrypt_raw(&a0).unwrap()),
            "before restart, from alice"
        );
        let b0 = bob.encrypt(&chat("before restart, from bob")).unwrap();
        assert_eq!(
            read_chat(&alice.decrypt_raw(&b0).unwrap()),
            "before restart, from bob"
        );

        let alice_bytes = alice.export();
        let bob_bytes = bob.export();
        let mut alice = RatchetState::import(&alice_bytes).unwrap();
        let mut bob = RatchetState::import(&bob_bytes).unwrap();

        let a1 = alice.encrypt(&chat("after restart, from alice")).unwrap();
        assert_eq!(
            read_chat(&bob.decrypt_raw(&a1).unwrap()),
            "after restart, from alice"
        );
        let b1 = bob.encrypt(&chat("after restart, from bob")).unwrap();
        assert_eq!(
            read_chat(&alice.decrypt_raw(&b1).unwrap()),
            "after restart, from bob"
        );

        // And several more turns past that, to prove the reconstructed
        // ratchet keeps advancing correctly, not just working once.
        for round in 0..5 {
            let from_alice = alice.encrypt(&chat(&format!("a{round}"))).unwrap();
            assert_eq!(
                read_chat(&bob.decrypt_raw(&from_alice).unwrap()),
                format!("a{round}")
            );
            let from_bob = bob.encrypt(&chat(&format!("b{round}"))).unwrap();
            assert_eq!(
                read_chat(&alice.decrypt_raw(&from_bob).unwrap()),
                format!("b{round}")
            );
        }
    }

    /// A message skipped-over before the "restart" (queued in the
    /// skipped-key cache, per `tests/queue_depth.rs`) must still decrypt
    /// after an export/import cycle — the cache itself has to round-trip,
    /// not just the chain keys.
    #[test]
    fn a_skipped_message_key_survives_export_and_import_then_still_decrypts() {
        let (mut alice, mut bob) = matched_pair();

        let stray = alice.encrypt(&chat("delivered very late")).unwrap();
        let delivered = alice.encrypt(&chat("delivered on time")).unwrap();
        assert_eq!(
            read_chat(&bob.decrypt_raw(&delivered).unwrap()),
            "delivered on time"
        );
        assert_eq!(
            bob.skipped_key_count(),
            1,
            "the skipped stray key should be cached"
        );

        let bob_bytes = bob.export();
        let mut bob = RatchetState::import(&bob_bytes).unwrap();
        assert_eq!(
            bob.skipped_key_count(),
            1,
            "the skipped-key cache must survive the export/import round trip"
        );

        assert_eq!(
            read_chat(&bob.decrypt_raw(&stray).unwrap()),
            "delivered very late",
            "a late arrival must still decrypt after a simulated restart"
        );
    }

    /// The exported bytes must actually carry the real key material, not a
    /// stub — a spot check against the live, pre-export values, so a future
    /// change that accidentally exports garbage (a bug that would otherwise
    /// only show up as import() failing, or worse, silently reconstructing
    /// a *different* working-but-wrong ratchet) gets caught here directly.
    #[test]
    fn exported_bytes_contain_the_same_key_material_as_the_live_state() {
        let (alice, _bob) = matched_pair();
        let exported: ExportedRatchetState = ciborium::from_reader(alice.export().as_slice())
            .expect("export() must produce what it claims to");

        assert_eq!(exported.root_key, alice.root_key.to_vec());
        assert_eq!(
            exported.sending_chain_key,
            alice.sending_chain_key.as_ref().map(|k| k.to_vec())
        );
        assert_eq!(
            exported.dh_self_secret,
            alice.dh_self.as_ref().map(|(s, _)| s.to_bytes().to_vec())
        );
    }
}
