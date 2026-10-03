//! Penetration-test finding, DRA-0022 (round 3, priority 1: gaining access
//! to individual messages/conversations via an active MITM), found
//! auditing `client/src/handshake.rs`'s Option B direct-pairing flow
//! (`docs/ARCHITECTURE.md` §6.3a) against `client/src/x3dh.rs`'s
//! `respond`.
//!
//! `PairingBundle` binds its `identity_dh_public` to `identity_key` with a
//! real signature (`identity_dh_signature`, checked by
//! `PrekeyBundle::verify` inside `handshake::initiate`) — exactly what
//! `docs/ARCHITECTURE.md` §3.2 requires for the directory-based flow too.
//! But `PairingResponse`, the message flowing the *other* direction,
//! carried `identity_dh_public` and `ephemeral_public` with no such
//! binding at all, even though `x3dh::respond` uses both as real
//! Diffie-Hellman inputs. Nothing about the two fields' relationship to
//! the reported `identity_key` was ever checked before this fix.
//!
//! The first test below proves the underlying cryptographic consequence
//! directly, at the `core::x3dh` level, independent of any wire format or
//! git state: given only the public prekeys either side would necessarily
//! already know (they're both in `PairingBundle`, exchanged in the open),
//! a party holding no secret belonging to either Alice or Bob can pick two
//! arbitrary secrets of its own, substitute the corresponding public keys
//! in place of Alice's real `identity_dh_public`/`ephemeral_public`, and
//! independently derive the *exact same root key* `x3dh::respond` (called
//! as Bob) lands on — a complete break of this session's confidentiality,
//! using nothing but public information plus two keys the attacker made
//! up. This is exactly what an on-path relay of the copy-pasted pairing
//! blobs could do while leaving `identity_key` untouched, so Bob's later
//! out-of-band fingerprint check against Alice's real identity would
//! still pass — the system's designed final defense never fires, because
//! the field it isn't checking is the one that was actually forged.
//!
//! The second test proves the fix: `handshake::respond` now verifies
//! `PairingResponse::response_signature` — binding `identity_dh_public`,
//! `ephemeral_public`, and `routing_id` to `identity_key` — and rejects a
//! response whose DH material was altered after signing.

use dratchet_client::handshake;
use dratchet_core::account::Account;
use dratchet_core::x3dh::{self, X3dhInitMessage};
use x25519_dalek::{PublicKey, StaticSecret};

#[test]
fn a_mitm_can_derive_bobs_root_key_from_only_public_material_without_response_binding() {
    let bob = Account::generate().unwrap();
    let bob_bundle = bob.publish_bundle(false).unwrap();

    // Mallory has no secret belonging to Alice or Bob -- just two freshly
    // made-up keypairs, standing in for whatever she substitutes into
    // Alice's PairingResponse in place of the real identity_dh_public and
    // ephemeral_public.
    let mallory_fake_identity_dh_secret = StaticSecret::random_from_rng(rand_core::OsRng);
    let mallory_fake_identity_dh_public = PublicKey::from(&mallory_fake_identity_dh_secret);
    let mallory_fake_ephemeral_secret = StaticSecret::random_from_rng(rand_core::OsRng);
    let mallory_fake_ephemeral_public = PublicKey::from(&mallory_fake_ephemeral_secret);

    // Bob runs the real responder computation against the forged message
    // -- exactly what pre-fix `handshake::respond` did with no check that
    // these fields actually belonged to the identity_key it also received.
    let forged_message = X3dhInitMessage {
        initiator_identity_dh_public: mallory_fake_identity_dh_public,
        initiator_ephemeral_public: mallory_fake_ephemeral_public,
        used_signed_prekey_id: bob_bundle.signed_prekey.id,
        used_one_time_prekey_id: None,
    };
    let bob_root_key = x3dh::respond(
        bob.identity_dh_secret(),
        bob.signed_prekey_secret(),
        None,
        &forged_message,
    )
    .unwrap();

    // Mallory independently derives the same root key using only Bob's
    // already-public bundle values (identity_dh_public, signed_prekey --
    // both sent in the open as part of PairingBundle) and her own two
    // made-up secrets -- the same DH formula `x3dh::respond` uses,
    // reordered by ECDH's commutativity (s * P == secret * S_public).
    let mallory_dh1 =
        mallory_fake_identity_dh_secret.diffie_hellman(&bob_bundle.signed_prekey.public);
    let mallory_dh2 = mallory_fake_ephemeral_secret.diffie_hellman(&bob_bundle.identity_dh_public);
    let mallory_dh3 =
        mallory_fake_ephemeral_secret.diffie_hellman(&bob_bundle.signed_prekey.public);
    let mut ikm = Vec::new();
    ikm.extend_from_slice(mallory_dh1.as_bytes());
    ikm.extend_from_slice(mallory_dh2.as_bytes());
    ikm.extend_from_slice(mallory_dh3.as_bytes());
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, &ikm);
    let mut mallory_root_key = [0u8; 32];
    hk.expand(b"dratchet-x3dh-root", &mut mallory_root_key)
        .unwrap();

    assert_eq!(
        bob_root_key, mallory_root_key,
        "VULNERABILITY: an attacker holding no secret from either party can derive the exact \
         session root key from only public bundle data plus two keys of its own choosing, \
         because nothing binds identity_dh_public/ephemeral_public to the claimed identity_key"
    );
}

#[test]
fn respond_accepts_a_genuine_untampered_pairing_response() {
    let alice = Account::generate().unwrap();
    let mut bob = Account::generate().unwrap();
    bob.generate_one_time_prekeys(1);

    let bob_bundle = handshake::build_pairing_bundle(&bob, b"bob-routing".to_vec()).unwrap();
    let (_alice_ratchet, response) =
        handshake::initiate(&alice, &bob_bundle, b"alice-routing".to_vec()).unwrap();

    assert!(
        handshake::respond(&mut bob, &response).is_ok(),
        "the fix must not be overly strict -- a genuine, untampered PairingResponse must still \
         be accepted"
    );
}

#[test]
fn respond_rejects_a_pairing_response_whose_dh_material_was_tampered_with_after_signing() {
    let alice = Account::generate().unwrap();
    let mut bob = Account::generate().unwrap();
    bob.generate_one_time_prekeys(1);

    let bob_bundle = handshake::build_pairing_bundle(&bob, b"bob-routing".to_vec()).unwrap();
    let (_alice_ratchet, mut response) =
        handshake::initiate(&alice, &bob_bundle, b"alice-routing".to_vec()).unwrap();

    // Simulate the MITM: substitute a fresh, attacker-chosen DH key in
    // place of Alice's real ephemeral_public, leaving identity_key (and so
    // the fingerprint Bob would later verify out of band) untouched.
    let forged_secret = StaticSecret::random_from_rng(rand_core::OsRng);
    let forged_public = PublicKey::from(&forged_secret);
    response.ephemeral_public = forged_public.as_bytes().to_vec();

    let result = handshake::respond(&mut bob, &response);
    assert!(
        result.is_err(),
        "FIX VERIFIED: a PairingResponse whose DH material no longer matches its signature must \
         be rejected, not silently used to derive a session key"
    );
}
