//! X3DH session establishment, per `docs/ARCHITECTURE.md` §3.2 and
//! `docs/MESSAGE_SCHEMA.md` §3.

use hkdf::Hkdf;
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::Result;
use crate::prekey::PrekeyBundle;

/// What the initiator sends the responder to complete the handshake on their end,
/// per `docs/MESSAGE_SCHEMA.md` §3.
pub struct X3dhInitMessage {
    pub initiator_identity_dh_public: PublicKey,
    pub initiator_ephemeral_public: PublicKey,
    pub used_signed_prekey_id: u32,
    pub used_one_time_prekey_id: Option<u32>,
}

pub struct X3dhInitResult {
    pub root_key: [u8; 32],
    pub message: X3dhInitMessage,
}

/// Run X3DH as the initiator against a (already-fetched) recipient prekey bundle.
/// Verifies the bundle's signatures before deriving anything from it.
pub fn initiate(
    initiator_identity_dh_secret: &StaticSecret,
    initiator_identity_dh_public: PublicKey,
    bundle: &PrekeyBundle,
) -> Result<X3dhInitResult> {
    bundle.verify()?;

    let ephemeral_secret = StaticSecret::random_from_rng(OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);

    let dh1 = initiator_identity_dh_secret.diffie_hellman(&bundle.signed_prekey.public);
    let dh2 = ephemeral_secret.diffie_hellman(&bundle.identity_dh_public);
    let dh3 = ephemeral_secret.diffie_hellman(&bundle.signed_prekey.public);
    let dh4 = bundle
        .one_time_prekey
        .as_ref()
        .map(|otp| ephemeral_secret.diffie_hellman(&otp.public));

    let root_key = derive_root_key(
        dh1.as_bytes(),
        dh2.as_bytes(),
        dh3.as_bytes(),
        dh4.as_ref().map(|s| s.as_bytes()),
    );

    Ok(X3dhInitResult {
        root_key,
        message: X3dhInitMessage {
            initiator_identity_dh_public,
            initiator_ephemeral_public: ephemeral_public,
            used_signed_prekey_id: bundle.signed_prekey.id,
            used_one_time_prekey_id: bundle.one_time_prekey.map(|otp| otp.id),
        },
    })
}

/// Run X3DH as the responder, given the secrets behind whichever of *our own*
/// prekeys the initiator's message says it used. `one_time_prekey_secret` is `None`
/// when the initiator's message carries no one-time prekey id (degraded mode, per
/// `docs/MESSAGE_SCHEMA.md` §3) — the caller is responsible for looking these secrets
/// up (and, for the one-time prekey, discarding it afterward: `docs/ARCHITECTURE.md` §3.4).
pub fn respond(
    responder_identity_dh_secret: &StaticSecret,
    responder_signed_prekey_secret: &StaticSecret,
    responder_one_time_prekey_secret: Option<&StaticSecret>,
    init_message: &X3dhInitMessage,
) -> [u8; 32] {
    let dh1 =
        responder_signed_prekey_secret.diffie_hellman(&init_message.initiator_identity_dh_public);
    let dh2 = responder_identity_dh_secret.diffie_hellman(&init_message.initiator_ephemeral_public);
    let dh3 =
        responder_signed_prekey_secret.diffie_hellman(&init_message.initiator_ephemeral_public);
    let dh4 = responder_one_time_prekey_secret
        .map(|s| s.diffie_hellman(&init_message.initiator_ephemeral_public));

    derive_root_key(
        dh1.as_bytes(),
        dh2.as_bytes(),
        dh3.as_bytes(),
        dh4.as_ref().map(|s| s.as_bytes()),
    )
}

/// Mailbox id for the *very first* message of a new conversation — before a
/// root key exists on both sides to derive the normal, unlinkable
/// `HKDF(root_key, "mailbox" ‖ direction)` id from (`ARCHITECTURE.md` §4.2/
/// §11.1). The responder can't compute that id until they've already
/// received the initiator's X3DH handshake fields, and those have to travel
/// through *some* mailbox first — a real bootstrap gap, not one the existing
/// design resolves.
///
/// Fix, deliberately minimal: derive this one id from the recipient's own
/// public identity alone, so anyone who has fetched their prekey bundle can
/// compute it and write the handshake there. This is a **known, bounded**
/// exception to §11.1's unlinkability property: a relay can observe "someone
/// new wrote to this recipient" once per new relationship (never once per
/// message, and never *who* — the writer's identity isn't revealed by the id
/// itself). Every message after this first one reverts to the fully
/// unlinkable, root-key-derived id, exactly as designed. See `ARCHITECTURE.md`
/// §11.1 for the write-up of this trade-off.
pub fn bootstrap_mailbox_id(recipient_identity_fingerprint: &[u8]) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(b"dratchet-x3dh-bootstrap-v1");
    hasher.update(recipient_identity_fingerprint);
    let digest = hasher.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

fn derive_root_key(
    dh1: &[u8; 32],
    dh2: &[u8; 32],
    dh3: &[u8; 32],
    dh4: Option<&[u8; 32]>,
) -> [u8; 32] {
    let mut ikm = Vec::with_capacity(32 * 4);
    ikm.extend_from_slice(dh1);
    ikm.extend_from_slice(dh2);
    ikm.extend_from_slice(dh3);
    if let Some(dh4) = dh4 {
        ikm.extend_from_slice(dh4);
    }
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut root_key = [0u8; 32];
    hk.expand(b"dratchet-x3dh-root", &mut root_key)
        .expect("32 is a valid HKDF-SHA256 output length");
    root_key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_mailbox_id_is_deterministic() {
        let fp = [7u8; 32];
        assert_eq!(bootstrap_mailbox_id(&fp), bootstrap_mailbox_id(&fp));
    }

    #[test]
    fn bootstrap_mailbox_id_differs_per_recipient() {
        assert_ne!(
            bootstrap_mailbox_id(&[1u8; 32]),
            bootstrap_mailbox_id(&[2u8; 32])
        );
    }
}
