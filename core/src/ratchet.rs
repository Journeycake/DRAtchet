//! Double Ratchet engine, per `docs/ARCHITECTURE.md` §3.3 and the reference
//! algorithm at <https://signal.org/docs/specifications/doubleratchet/>.
//!
//! This is the module that has to make good on the project's central claim:
//! that key rotation driven by turn-taking (not a literal per-message
//! keypair) tolerates queue depth — bursts of messages sent before a reply,
//! out-of-order delivery, and retries. See `tests/queue_depth.rs`.

use std::collections::HashMap;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key as AeadKey, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand_core::OsRng;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::envelope::Envelope;
use crate::error::{Error, Result};
use crate::payload;

/// Bound on how many message keys may be derived-ahead-and-cached for a single
/// receiving chain before `decrypt` refuses and returns an error rather than
/// growing the cache unboundedly. Matches `MAX_SKIP` in `docs/ARCHITECTURE.md` §3.3.
pub const DEFAULT_MAX_SKIP: u32 = 1000;

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
}

impl RatchetState {
    /// The X3DH initiator's ratchet: generates a fresh DH ratchet keypair immediately
    /// and derives a sending chain against the responder's already-known DH public key
    /// (their signed prekey, in the X3DH handshake).
    pub fn init_as_initiator(
        conversation_id: [u8; 16],
        root_key: [u8; 32],
        responder_dh_public: PublicKey,
        max_skip: u32,
    ) -> Self {
        let dh_self_secret = StaticSecret::random_from_rng(OsRng);
        let dh_self_public = PublicKey::from(&dh_self_secret);
        let dh_output = dh_self_secret.diffie_hellman(&responder_dh_public);
        let (new_root, sending_chain_key) = kdf_rk(&root_key, dh_output.as_bytes());

        RatchetState {
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
        }
    }

    /// The X3DH responder's ratchet: keeps using the DH keypair whose public half the
    /// initiator already X3DH'd against (typically the signed prekey), and doesn't
    /// derive a receiving chain until the initiator's first message actually arrives.
    pub fn init_as_responder(
        conversation_id: [u8; 16],
        root_key: [u8; 32],
        own_dh_secret: StaticSecret,
        max_skip: u32,
    ) -> Self {
        let own_dh_public = PublicKey::from(&own_dh_secret);
        RatchetState {
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
        }
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
        self.skipped.extend(newly_skipped);

        Ok(plaintext)
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
        );
        let responder = RatchetState::init_as_responder(
            conversation_id,
            root_key,
            responder_secret,
            DEFAULT_MAX_SKIP,
        );
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
        let small_max_skip = 5;

        let mut alice = RatchetState::init_as_initiator(
            conversation_id,
            root_key,
            responder_public,
            small_max_skip,
        );
        let mut bob = RatchetState::init_as_responder(
            conversation_id,
            root_key,
            responder_secret,
            small_max_skip,
        );

        let mut last = None;
        for i in 0..10 {
            last = Some(alice.encrypt(&chat(&format!("msg {i}"))).unwrap());
        }
        // Only the last of 10 messages arrives; the skipped-key cache would need to
        // derive-and-cache the other 9, which exceeds max_skip=5.
        assert!(matches!(
            bob.decrypt_raw(&last.unwrap()),
            Err(Error::MaxSkipExceeded(5))
        ));
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
}
