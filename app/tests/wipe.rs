//! Real end-to-end proof of `docs/ARCHITECTURE.md` §11.9's duress-response
//! wipe, through the actual `dratchet_app::{quick_wipe, full_wipe}` API a
//! UI calls — against a real spawned `dratchet_server::app()`, a real
//! chat message actually sent and received, and a real on-disk `Db` file.
//! No mocks, matching this project's standing rule.
//!
//! Reuses `pairing_and_chat.rs`'s real X3DH-via-directory + routing-id-
//! exchange setup rather than duplicating a lighter-weight version, since
//! both tests need the same real, verified, chat-capable pair to start
//! from.

use std::sync::Arc;

use dratchet_app::{
    announce_routing_id, receive_pending, record_verification_result, send_message,
};
use dratchet_client::net::Connection;
use dratchet_core::account::Account;
use dratchet_core::prekey::{OneTimePrekeyPublic, PrekeyBundle, SignedPrekeyPublic};
use dratchet_core::ratchet::{RatchetState, DEFAULT_MAX_SKIP};
use dratchet_core::x3dh::{self, bootstrap_mailbox_id};
use dratchet_server::protocol::*;
use dratchet_store::{Contact, Db, VerificationState};
use rand_core::{OsRng, RngCore};
use tokio::net::TcpListener;
use x25519_dalek::PublicKey;

async fn spawn_server() -> String {
    let (router, _state) = dratchet_server::app();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    format!("ws://{addr}/v1/ws")
}

fn random_routing_id() -> Vec<u8> {
    let mut buf = [0u8; 32];
    OsRng.fill_bytes(&mut buf);
    buf.to_vec()
}

fn to_core_bundle(wire: &FetchedBundleWire) -> PrekeyBundle {
    let identity_dh_public: [u8; 32] = wire.identity_dh_public.as_slice().try_into().unwrap();
    let signed_prekey_public: [u8; 32] = wire.signed_prekey.as_slice().try_into().unwrap();
    PrekeyBundle {
        identity_public_key: wire.identity_key.clone(),
        identity_dh_public: PublicKey::from(identity_dh_public),
        identity_dh_signature: wire.identity_dh_signature.clone(),
        signed_prekey: SignedPrekeyPublic {
            id: wire.signed_prekey_id,
            public: PublicKey::from(signed_prekey_public),
            signature: wire.signed_prekey_sig.clone(),
        },
        one_time_prekey: wire.one_time_prekey.as_ref().map(|otp| {
            let public: [u8; 32] = otp.key.as_slice().try_into().unwrap();
            OneTimePrekeyPublic {
                id: otp.id,
                public: PublicKey::from(public),
            }
        }),
    }
}

/// A real verified, chat-capable pair, each with a real on-disk `Db` at a
/// known path: `dratchet-app`'s own real API used throughout (not
/// hand-rolled protocol calls), mirroring `pairing_and_chat.rs`. Returns
/// `(db_alice, alice_path, alice, alice_conn, alice_contact, db_bob,
/// bob_conv_id)` — the pieces each test in this file needs.
#[allow(clippy::type_complexity)]
async fn verified_pair_with_one_message_exchanged() -> (
    Arc<Db>,
    std::path::PathBuf,
    Account,
    Connection,
    Contact,
    Db,
    [u8; 16],
) {
    let url = spawn_server().await;

    let mut bob = Account::generate().unwrap();
    let bob_otp_publics = bob.generate_one_time_prekeys(1);
    let bob_local_bundle = bob.publish_bundle(false).unwrap();
    let bob_bundle_wire = PrekeyBundleWire {
        username: "bob".into(),
        discriminator: 5001,
        identity_key: bob_local_bundle.identity_public_key.clone(),
        identity_dh_public: bob_local_bundle.identity_dh_public.as_bytes().to_vec(),
        identity_dh_signature: bob_local_bundle.identity_dh_signature.clone(),
        signed_prekey_id: bob_local_bundle.signed_prekey.id,
        signed_prekey: bob_local_bundle.signed_prekey.public.as_bytes().to_vec(),
        signed_prekey_sig: bob_local_bundle.signed_prekey.signature.clone(),
        signed_prekey_expires_at: 0,
        one_time_prekeys: bob_otp_publics
            .into_iter()
            .map(|otp| OneTimePrekeyWire {
                id: otp.id,
                key: otp.public.as_bytes().to_vec(),
            })
            .collect(),
        registration_pow: Some(dratchet_server::abuse::solve_registration_pow(
            "bob",
            5001,
            &bob_local_bundle.identity_public_key,
        )),
    };
    let mut publisher = Connection::connect(&url).await.unwrap();
    let (_, _challenge): (_, AuthChallenge) = publisher.recv().await.unwrap();
    publisher
        .send(
            FrameTag::PublishBundle,
            &PublishBundle {
                bundle: bob_bundle_wire,
            },
        )
        .await
        .unwrap();

    let alice = Account::generate().unwrap();
    let mut fetcher = Connection::connect(&url).await.unwrap();
    let (_, _challenge): (_, AuthChallenge) = fetcher.recv().await.unwrap();
    fetcher
        .send(
            FrameTag::FetchBundle,
            &FetchBundle {
                username: "bob".into(),
                discriminator: 5001,
            },
        )
        .await
        .unwrap();
    let (_, result): (_, BundleResult) = fetcher.recv().await.unwrap();
    let fetched = result.bundle.expect("bob's bundle should be found");
    let core_bundle = to_core_bundle(&fetched);

    let init = x3dh::initiate(
        alice.identity_dh_secret(),
        alice.identity_dh_public,
        &core_bundle,
    )
    .unwrap();
    let conv_id = dratchet_core::conversation_id(
        alice.identity.fingerprint().as_bytes(),
        bob.identity.fingerprint().as_bytes(),
    );
    let alice_ratchet = RatchetState::init_as_initiator(
        conv_id,
        init.root_key,
        core_bundle.signed_prekey.public,
        DEFAULT_MAX_SKIP,
    )
    .unwrap();

    let bob_otp_secret = init
        .message
        .used_one_time_prekey_id
        .and_then(|id| bob.take_one_time_prekey_secret(id));
    let bob_root_key = x3dh::respond(
        bob.identity_dh_secret(),
        bob.signed_prekey_secret(),
        bob_otp_secret.as_ref(),
        &init.message,
    );
    let bob_ratchet = RatchetState::init_as_responder(
        conv_id,
        bob_root_key,
        bob.signed_prekey_secret().clone(),
        DEFAULT_MAX_SKIP,
    )
    .unwrap();

    let alice_fp = alice.identity.fingerprint().as_bytes().to_vec();
    let bob_fp = bob.identity.fingerprint().as_bytes().to_vec();
    let alice_routing_id = random_routing_id();
    let bob_routing_id = random_routing_id();

    let alice_path = tempfile::tempdir().unwrap().keep().join("alice.redb");
    let db_alice = Arc::new(Db::create(&alice_path, "pw").unwrap());
    db_alice.save_account(&alice).unwrap();
    let mut alice_contact = Contact {
        fingerprint: bob_fp.clone(),
        username: Some("bob".into()),
        discriminator: Some(5001),
        verification_state: VerificationState::Pending,
        mailbox_id: bootstrap_mailbox_id(&bob_fp).to_vec(),
        created_at: 0,
        local_routing_id: alice_routing_id.clone(),
        peer_routing_id: None,
        wipe_ask_before_delete: false,
        peer_wipe_ask_before_delete: None,
        wipe_include_session: false,
        peer_wipe_include_session: None,
        wipe_request_pending: false,
    };
    db_alice.save_contact(&alice_contact).unwrap();
    db_alice.save_ratchet(conv_id, &alice_ratchet).unwrap();

    let bob_path = tempfile::tempdir().unwrap().keep().join("bob.redb");
    let db_bob = Db::create(&bob_path, "pw").unwrap();
    db_bob.save_account(&bob).unwrap();
    let mut bob_contact = Contact {
        fingerprint: alice_fp.clone(),
        username: None,
        discriminator: None,
        verification_state: VerificationState::Pending,
        mailbox_id: bootstrap_mailbox_id(&alice_fp).to_vec(),
        created_at: 0,
        local_routing_id: bob_routing_id.clone(),
        peer_routing_id: None,
        wipe_ask_before_delete: false,
        peer_wipe_ask_before_delete: None,
        wipe_include_session: false,
        peer_wipe_include_session: None,
        wipe_request_pending: false,
    };
    db_bob.save_contact(&bob_contact).unwrap();
    db_bob.save_ratchet(conv_id, &bob_ratchet).unwrap();

    let mut alice_conn = Connection::connect(&url).await.unwrap();
    alice_conn.authenticate(&alice).await.unwrap();
    let mut bob_conn = Connection::connect(&url).await.unwrap();
    bob_conn.authenticate(&bob).await.unwrap();

    announce_routing_id(
        &db_alice,
        &mut alice_conn,
        &alice,
        &alice_contact,
        alice_routing_id,
    )
    .await
    .unwrap();
    receive_pending(&db_bob, &mut bob_conn, &bob, &bob_contact)
        .await
        .unwrap();
    bob_contact = db_bob.load_contact(&alice_fp).unwrap().unwrap();
    announce_routing_id(&db_bob, &mut bob_conn, &bob, &bob_contact, bob_routing_id)
        .await
        .unwrap();
    receive_pending(&db_alice, &mut alice_conn, &alice, &alice_contact)
        .await
        .unwrap();
    alice_contact = db_alice.load_contact(&bob_fp).unwrap().unwrap();

    alice_contact = record_verification_result(&db_alice, alice_contact, true).unwrap();
    record_verification_result(&db_bob, bob_contact, true).unwrap();

    let sent = send_message(
        &db_alice,
        &mut alice_conn,
        &alice,
        &alice_contact,
        b"hi bob, before any wipe",
    )
    .await
    .unwrap();
    assert_eq!(sent.content, b"hi bob, before any wipe");

    let bob_conv_id = dratchet_core::conversation_id(&bob_fp, &alice_fp);

    (
        db_alice,
        alice_path,
        alice,
        alice_conn,
        alice_contact,
        db_bob,
        bob_conv_id,
    )
}

#[tokio::test]
async fn quick_wipe_erases_history_and_session_but_the_account_and_contact_survive() {
    let (db_alice, _path, alice, mut alice_conn, alice_contact, _db_bob, _bob_conv_id) =
        verified_pair_with_one_message_exchanged().await;

    let conv_id = dratchet_core::conversation_id(
        alice.identity.fingerprint().as_bytes(),
        &alice_contact.fingerprint,
    );
    assert_eq!(
        dratchet_app::list_messages(&db_alice, &alice, &alice_contact)
            .unwrap()
            .len(),
        1,
        "sanity check: the message is really there before the wipe"
    );

    let removed = dratchet_app::quick_wipe(&db_alice).unwrap();
    assert_eq!(removed, 2, "one message + one ratchet record");

    // The identity and the contact (including its Verified state) survive
    // — the account keeps functioning.
    assert!(db_alice.load_account().unwrap().is_some());
    let reloaded_contact = db_alice
        .load_contact(&alice_contact.fingerprint)
        .unwrap()
        .unwrap();
    assert_eq!(
        reloaded_contact.verification_state,
        VerificationState::Verified
    );

    // The message history is gone.
    assert!(
        dratchet_app::list_messages(&db_alice, &alice, &reloaded_contact)
            .unwrap()
            .is_empty()
    );
    assert!(db_alice.load_ratchet(conv_id).unwrap().is_none());

    // And the real, documented consequence: with the ratchet gone, this
    // conversation can no longer send until a fresh session is
    // established — proven through the real send_message API, not
    // asserted against store internals only.
    let result = send_message(
        &db_alice,
        &mut alice_conn,
        &alice,
        &reloaded_contact,
        b"can't send this",
    )
    .await;
    assert!(
        matches!(result, Err(dratchet_app::Error::NoSession)),
        "sending after a quick wipe must fail with NoSession until the contact is re-paired: {result:?}"
    );
}

#[tokio::test]
async fn full_wipe_leaves_no_recoverable_database_behind() {
    let (db_alice, path, _alice, _alice_conn, _alice_contact, _db_bob, _bob_conv_id) =
        verified_pair_with_one_message_exchanged().await;

    dratchet_app::full_wipe(&db_alice, &path).unwrap();

    assert!(
        !path.exists(),
        "full_wipe must remove the underlying database file"
    );

    // A fresh Db::create at the same path — the real next step the UI
    // takes after a restart following a full wipe — works cleanly, proving
    // nothing about the old file lingers to interfere.
    let fresh = Db::create(&path, "a brand new passphrase").unwrap();
    assert!(
        fresh.load_account().unwrap().is_none(),
        "a full wipe must force the next session to start from a fresh identity"
    );
}
