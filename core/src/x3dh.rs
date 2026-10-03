//! X3DH session establishment, per `docs/ARCHITECTURE.md` §3.2 and
//! `docs/MESSAGE_SCHEMA.md` §3.

use hkdf::Hkdf;
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

use crate::error::{Error, Result};
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

    // DRA-0037 (`docs/DELIVERY_FAILURE_FINDINGS.md`): reject low-order
    // points. See `respond`'s own check for the full reasoning — the
    // initiator's exposure is narrower (a bundle's keys are signature-
    // bound to the identity that published them), but a peer is still
    // free to *sign* a low-order key as their own, and a root key that
    // any observer can recompute is never acceptable on either side.
    reject_non_contributory(&[Some(&dh1), Some(&dh2), Some(&dh3), dh4.as_ref()])?;

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
/// **DRA-0037 (`docs/DELIVERY_FAILURE_FINDINGS.md`), the reason this
/// returns `Result`:** every public key this runs Diffie-Hellman against
/// comes verbatim from an `X3dhInitMessage` an *attacker* may have
/// written. X25519 (RFC 7748) has a small subgroup of order 8, so a peer
/// who supplies a low-order point — the all-zero point being the simplest
/// — forces `diffie_hellman` to return an all-zero shared secret
/// regardless of which private key it was called with. Supplying
/// low-order points for *both* public keys below collapses dh1/dh2/dh3
/// (and dh4, which runs against the same ephemeral) to all-zeros, so the
/// derived root key depends on nothing secret at all and any observer can
/// recompute it — destroying X3DH's core authentication property, that
/// the root key proves possession of the initiator's private keys.
/// `FirstContactWire::verify_identity_binding` is no help: an attacker
/// signs their own low-order "DH key" with their own genuine identity
/// key, so that binding check passes.
pub fn respond(
    responder_identity_dh_secret: &StaticSecret,
    responder_signed_prekey_secret: &StaticSecret,
    responder_one_time_prekey_secret: Option<&StaticSecret>,
    init_message: &X3dhInitMessage,
) -> Result<[u8; 32]> {
    let dh1 =
        responder_signed_prekey_secret.diffie_hellman(&init_message.initiator_identity_dh_public);
    let dh2 = responder_identity_dh_secret.diffie_hellman(&init_message.initiator_ephemeral_public);
    let dh3 =
        responder_signed_prekey_secret.diffie_hellman(&init_message.initiator_ephemeral_public);
    let dh4 = responder_one_time_prekey_secret
        .map(|s| s.diffie_hellman(&init_message.initiator_ephemeral_public));

    reject_non_contributory(&[Some(&dh1), Some(&dh2), Some(&dh3), dh4.as_ref()])?;

    Ok(derive_root_key(
        dh1.as_bytes(),
        dh2.as_bytes(),
        dh3.as_bytes(),
        dh4.as_ref().map(|s| s.as_bytes()),
    ))
}

/// DRA-0037: reject the handshake if *any* of these Diffie-Hellman
/// outputs is non-contributory — i.e. the peer's public key was a
/// low-order point, so that output carries no contribution from the
/// private key at all. `SharedSecret::was_contributory` is exactly the
/// check `x25519-dalek` exposes for this; it is the caller's job to
/// actually call it, which is what this finding was.
fn reject_non_contributory(shared_secrets: &[Option<&SharedSecret>]) -> Result<()> {
    for shared_secret in shared_secrets.iter().flatten() {
        if !shared_secret.was_contributory() {
            return Err(Error::NonContributoryHandshake);
        }
    }
    Ok(())
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

    /// The all-zero X25519 point: order 1, so `diffie_hellman` against it
    /// yields an all-zero shared secret for *every* private key. The
    /// canonical member of RFC 7748's small subgroup.
    const LOW_ORDER_POINT: [u8; 32] = [0u8; 32];

    /// Penetration-test finding DRA-0037: two responders with *entirely
    /// different* secrets must never derive the same root key. Pre-fix
    /// they did, whenever the initiator supplied low-order points -- every
    /// DH output collapses to all-zeros, so the responder's own secrets
    /// contribute nothing at all and an attacker holding no key material
    /// derives the identical root key.
    #[test]
    fn low_order_points_cannot_make_two_different_responders_derive_the_same_root_key() {
        let malicious_init = X3dhInitMessage {
            initiator_identity_dh_public: PublicKey::from(LOW_ORDER_POINT),
            initiator_ephemeral_public: PublicKey::from(LOW_ORDER_POINT),
            used_signed_prekey_id: 1,
            used_one_time_prekey_id: None,
        };

        let bob_identity = StaticSecret::random_from_rng(OsRng);
        let bob_signed_prekey = StaticSecret::random_from_rng(OsRng);
        let carol_identity = StaticSecret::random_from_rng(OsRng);
        let carol_signed_prekey = StaticSecret::random_from_rng(OsRng);

        let bob = respond(&bob_identity, &bob_signed_prekey, None, &malicious_init);
        let carol = respond(&carol_identity, &carol_signed_prekey, None, &malicious_init);

        match (bob, carol) {
            // Fixed: a non-contributory handshake is refused outright.
            (Err(_), Err(_)) => {}
            (Ok(bob_root_key), Ok(carol_root_key)) => {
                assert_ne!(
                    bob_root_key, carol_root_key,
                    "VULNERABILITY: low-order X25519 points forced every DH output to all-zeros, \
                     so two responders holding completely different secrets derived the *same* \
                     root key -- meaning an attacker with no key material at all derives it too, \
                     completely bypassing X3DH's authentication property"
                );
            }
            _ => panic!("both responders must agree on whether the handshake is acceptable"),
        }
    }

    /// DRA-0037, the one-time-prekey variant: dh4 runs against the same
    /// attacker-chosen ephemeral, so including it is no protection.
    #[test]
    fn a_low_order_ephemeral_defeats_the_one_time_prekey_dh_too() {
        let malicious_init = X3dhInitMessage {
            initiator_identity_dh_public: PublicKey::from(LOW_ORDER_POINT),
            initiator_ephemeral_public: PublicKey::from(LOW_ORDER_POINT),
            used_signed_prekey_id: 1,
            used_one_time_prekey_id: Some(7),
        };

        let bob_otp = StaticSecret::random_from_rng(OsRng);
        let carol_otp = StaticSecret::random_from_rng(OsRng);
        let bob = respond(
            &StaticSecret::random_from_rng(OsRng),
            &StaticSecret::random_from_rng(OsRng),
            Some(&bob_otp),
            &malicious_init,
        );
        let carol = respond(
            &StaticSecret::random_from_rng(OsRng),
            &StaticSecret::random_from_rng(OsRng),
            Some(&carol_otp),
            &malicious_init,
        );

        match (bob, carol) {
            (Err(_), Err(_)) => {}
            (Ok(bob_root_key), Ok(carol_root_key)) => {
                assert_ne!(
                    bob_root_key, carol_root_key,
                    "VULNERABILITY: the one-time-prekey DH is no protection -- it runs against \
                     the same attacker-chosen low-order ephemeral, so dh4 is all-zeros too"
                );
            }
            _ => panic!("both responders must agree on whether the handshake is acceptable"),
        }
    }

    /// The fix must not be overly strict: an ordinary handshake between
    /// two genuine parties must still derive matching root keys on both
    /// sides.
    #[test]
    fn an_ordinary_handshake_still_derives_matching_root_keys() {
        use crate::identity::Identity;
        use crate::prekey::{PrekeyBundle, SignedPrekeyPublic};

        let responder_identity = Identity::generate().unwrap();
        let responder_identity_dh = StaticSecret::random_from_rng(OsRng);
        let responder_identity_dh_public = PublicKey::from(&responder_identity_dh);
        let responder_signed_prekey = StaticSecret::random_from_rng(OsRng);
        let responder_signed_prekey_public = PublicKey::from(&responder_signed_prekey);

        let identity_dh_signature = responder_identity
            .sign_prekey(
                crate::account::IDENTITY_DH_SIGNATURE_ID,
                responder_identity_dh_public.as_bytes(),
            )
            .unwrap();
        let signed_prekey_signature = responder_identity
            .sign_prekey(1, responder_signed_prekey_public.as_bytes())
            .unwrap();

        let bundle = PrekeyBundle {
            identity_public_key: responder_identity.export_public_key().unwrap(),
            identity_dh_public: responder_identity_dh_public,
            identity_dh_signature,
            signed_prekey: SignedPrekeyPublic {
                id: 1,
                public: responder_signed_prekey_public,
                signature: signed_prekey_signature,
            },
            one_time_prekey: None,
        };

        let initiator_identity_dh = StaticSecret::random_from_rng(OsRng);
        let initiator_identity_dh_public = PublicKey::from(&initiator_identity_dh);
        let init = initiate(
            &initiator_identity_dh,
            initiator_identity_dh_public,
            &bundle,
        )
        .expect("a genuine bundle must still complete the initiator side");

        let responder_root_key = respond(
            &responder_identity_dh,
            &responder_signed_prekey,
            None,
            &init.message,
        )
        .expect("a genuine handshake must still complete the responder side");

        assert_eq!(
            init.root_key, responder_root_key,
            "the fix must not break real handshakes -- both sides must still agree"
        );
    }
}
