//! End-to-end: two real `Account`s (OpenPGP identity + prekeys), a real X3DH
//! handshake, then the Double Ratchet taking over — per `docs/ARCHITECTURE.md`
//! §3.2/§3.3.

use dratchet_core::account::Account;
use dratchet_core::payload::{untag_and_unpad, PAYLOAD_CHAT};
use dratchet_core::ratchet::{RatchetState, DEFAULT_MAX_SKIP};
use dratchet_core::{conversation_id, x3dh};

fn chat(text: &str) -> Vec<u8> {
    dratchet_core::payload::tag_and_pad(PAYLOAD_CHAT, text.as_bytes()).unwrap()
}

fn read_chat(bytes: &[u8]) -> String {
    let (ty, content) = untag_and_unpad(bytes).unwrap();
    assert_eq!(ty, PAYLOAD_CHAT);
    String::from_utf8(content).unwrap()
}

#[test]
fn full_handshake_with_one_time_prekey_then_ratchet_conversation() {
    let alice_account = Account::generate("alice@example.test").unwrap();
    let mut bob_account = Account::generate("bob@example.test").unwrap();
    bob_account.generate_one_time_prekeys(1);

    let conv_id = conversation_id(
        alice_account.identity.fingerprint().as_bytes(),
        bob_account.identity.fingerprint().as_bytes(),
    );

    // Alice fetches Bob's bundle (consuming his one one-time prekey, as a directory
    // server would) and runs X3DH as the initiator.
    let bob_bundle = bob_account.publish_bundle(true).unwrap();
    assert!(bob_bundle.one_time_prekey.is_some());
    let init = x3dh::initiate(
        alice_account.identity_dh_secret(),
        alice_account.identity_dh_public,
        &bob_bundle,
    )
    .unwrap();

    // Bob looks up which of his own prekeys the init message names and responds.
    let otp_secret = init
        .message
        .used_one_time_prekey_id
        .and_then(|id| bob_account.take_one_time_prekey_secret(id));
    assert!(
        otp_secret.is_some(),
        "the consumed one-time prekey should be found by id"
    );
    let bob_root_key = x3dh::respond(
        bob_account.identity_dh_secret(),
        bob_account.signed_prekey_secret(),
        otp_secret.as_ref(),
        &init.message,
    );

    assert_eq!(
        init.root_key, bob_root_key,
        "both sides must derive the same X3DH root key"
    );

    // The one-time prekey must actually be gone now — single-use, discard-after-use.
    assert!(
        bob_account.take_one_time_prekey_secret(0).is_none(),
        "a consumed one-time prekey must not be usable a second time"
    );

    // Ratchet takes over: Alice as initiator (uses Bob's signed prekey as his initial
    // ratchet public key), Bob as responder (keeps his signed prekey as his own
    // initial ratchet keypair until Alice's first message arrives).
    let mut alice_ratchet = RatchetState::init_as_initiator(
        conv_id,
        init.root_key,
        bob_bundle.signed_prekey.public,
        DEFAULT_MAX_SKIP,
    );
    let mut bob_ratchet = RatchetState::init_as_responder(
        conv_id,
        bob_root_key,
        bob_account.signed_prekey_secret().clone(),
        DEFAULT_MAX_SKIP,
    );

    let e0 = alice_ratchet.encrypt(&chat("hello, Bob")).unwrap();
    assert_eq!(
        read_chat(&bob_ratchet.decrypt_raw(&e0).unwrap()),
        "hello, Bob"
    );

    let e1 = bob_ratchet.encrypt(&chat("hi Alice")).unwrap();
    assert_eq!(
        read_chat(&alice_ratchet.decrypt_raw(&e1).unwrap()),
        "hi Alice"
    );
}

#[test]
fn handshake_degrades_gracefully_without_a_one_time_prekey() {
    let alice_account = Account::generate("alice@example.test").unwrap();
    let bob_account = Account::generate("bob@example.test").unwrap();
    // No one_time_prekeys generated — the bundle will have none available.

    let bob_bundle = bob_account.publish_bundle(true).unwrap();
    assert!(bob_bundle.one_time_prekey.is_none());

    let init = x3dh::initiate(
        alice_account.identity_dh_secret(),
        alice_account.identity_dh_public,
        &bob_bundle,
    )
    .unwrap();
    assert!(init.message.used_one_time_prekey_id.is_none());

    let bob_root_key = x3dh::respond(
        bob_account.identity_dh_secret(),
        bob_account.signed_prekey_secret(),
        None,
        &init.message,
    );
    assert_eq!(init.root_key, bob_root_key);
}

#[test]
fn tampered_bundle_signature_is_rejected_before_any_key_agreement() {
    let alice_account = Account::generate("alice@example.test").unwrap();
    let bob_account = Account::generate("bob@example.test").unwrap();
    let mut bob_bundle = bob_account.publish_bundle(false).unwrap();

    // Flip a byte of the signed prekey's public value without updating its signature —
    // simulating a compromised or malicious directory substituting a key.
    let mut tampered = bob_bundle.signed_prekey.public.to_bytes();
    tampered[0] ^= 0xFF;
    bob_bundle.signed_prekey.public = tampered.into();

    let result = x3dh::initiate(
        alice_account.identity_dh_secret(),
        alice_account.identity_dh_public,
        &bob_bundle,
    );
    assert!(
        result.is_err(),
        "a tampered/substituted prekey must fail bundle verification"
    );
}
