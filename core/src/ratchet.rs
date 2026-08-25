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

pub struct RatchetState {
    conversation_id: [u8; 16],
    max_skip: u32,

    root_key: [u8; 32],
    dh_self: Option<(StaticSecret, PublicKey)>,
    dh_remote: Option<PublicKey>,

    sending_chain_key: Option<[u8; 32]>,
    receiving_chain_key: Option<[u8; 32]>,

    send_n: u32,
    recv_n: u32,
    prev_chain_len: u32,

    skipped: HashMap<(DhPubBytes, u32), [u8; 32]>,
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
            root_key: new_root,
            dh_self: Some((dh_self_secret, dh_self_public)),
            dh_remote: Some(responder_dh_public),
            sending_chain_key: Some(sending_chain_key),
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
            root_key,
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
        let chain_key = self
            .sending_chain_key
            .ok_or(Error::RatchetNotInitialized("sending_chain_key"))?;

        let (next_chain_key, message_key) = kdf_ck(&chain_key);
        self.sending_chain_key = Some(next_chain_key);

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
    pub fn decrypt_raw(&mut self, envelope: &Envelope) -> Result<Vec<u8>> {
        if let Some(mk) = self.take_skipped_key(&envelope.dh_pub, envelope.n) {
            let header_bytes = envelope.header_bytes();
            return aead_decrypt(&mk, &header_bytes, &envelope.ciphertext);
        }

        let incoming_dh = PublicKey::from(envelope.dh_pub);
        if self.dh_remote != Some(incoming_dh) {
            // Exhaust (and cache) the remaining keys of the *old* receiving chain up to
            // the sender-reported previous chain length, then perform the DH ratchet step.
            self.skip_message_keys(envelope.pn)?;
            self.dh_ratchet_step(incoming_dh);
        }

        self.skip_message_keys(envelope.n)?;

        let chain_key = self
            .receiving_chain_key
            .ok_or(Error::RatchetNotInitialized("receiving_chain_key"))?;
        let (next_chain_key, message_key) = kdf_ck(&chain_key);
        self.receiving_chain_key = Some(next_chain_key);
        self.recv_n += 1;

        aead_decrypt(&message_key, &envelope.header_bytes(), &envelope.ciphertext)
    }

    pub fn decrypt_payload(&mut self, envelope: &Envelope) -> Result<(u8, Vec<u8>)> {
        let plaintext = self.decrypt_raw(envelope)?;
        payload::untag_and_unpad(&plaintext)
    }

    pub fn encrypt_payload(&mut self, payload_type: u8, content: &[u8]) -> Result<Envelope> {
        let tagged = payload::tag_and_pad(payload_type, content)?;
        self.encrypt(&tagged)
    }

    fn take_skipped_key(&mut self, dh_pub: &[u8; 32], n: u32) -> Option<[u8; 32]> {
        self.skipped.remove(&(DhPubBytes(*dh_pub), n))
    }

    fn skip_message_keys(&mut self, until: u32) -> Result<()> {
        let Some(chain_key) = self.receiving_chain_key else {
            // No receiving chain yet (e.g. responder before the first message) — nothing
            // to skip ahead in; `until` should be 0 in that case, which is a no-op.
            return Ok(());
        };
        if self.recv_n.saturating_add(self.max_skip) < until {
            return Err(Error::MaxSkipExceeded(self.max_skip));
        }
        let Some(dh_remote) = self.dh_remote else {
            return Ok(());
        };

        let mut chain_key = chain_key;
        while self.recv_n < until {
            let (next_chain_key, message_key) = kdf_ck(&chain_key);
            self.skipped
                .insert((DhPubBytes(dh_remote.to_bytes()), self.recv_n), message_key);
            chain_key = next_chain_key;
            self.recv_n += 1;
        }
        self.receiving_chain_key = Some(chain_key);
        Ok(())
    }

    fn dh_ratchet_step(&mut self, incoming_dh: PublicKey) {
        self.prev_chain_len = self.send_n;
        self.send_n = 0;
        self.recv_n = 0;
        self.dh_remote = Some(incoming_dh);

        let (dh_self_secret, _) = self.dh_self.as_ref().expect("dh_self always set");
        let dh_output = dh_self_secret.diffie_hellman(&incoming_dh);
        let (root_after_recv, receiving_chain_key) = kdf_rk(&self.root_key, dh_output.as_bytes());
        self.root_key = root_after_recv;
        self.receiving_chain_key = Some(receiving_chain_key);

        let new_secret = StaticSecret::random_from_rng(OsRng);
        let new_public = PublicKey::from(&new_secret);
        let dh_output = new_secret.diffie_hellman(&incoming_dh);
        let (root_after_send, sending_chain_key) = kdf_rk(&self.root_key, dh_output.as_bytes());
        self.root_key = root_after_send;
        self.sending_chain_key = Some(sending_chain_key);
        self.dh_self = Some((new_secret, new_public));
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
}
