//! Real end-to-end proof of `dratchet-app`'s actual public API — the same
//! guarantees `store/tests/routing_id_exchange.rs` proves at the `store`
//! level, now proven through the functions a UI would really call
//! (`open_account`, `announce_routing_id`, `receive_pending`,
//! `send_message`, `record_verification_result`), against a real spawned
//! `dratchet_server::app()`. No mocks, matching this project's standing
//! rule.
//!
//! Deliberately starts from contacts/ratchets already established the
//! same way that test does (see `dratchet_app`'s module doc for the real,
//! currently-unimplemented gap — `docs/MESSAGE_SCHEMA.md` §3's X3DH
//! session-establishment wire message — that blocks a true "discover a
//! stranger's incoming X3DH attempt" flow).

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

fn temp_db() -> Db {
    let dir = tempfile::tempdir().unwrap().keep();
    Db::create(dir.join("test.redb"), "pw").unwrap()
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

#[tokio::test]
async fn pending_gated_send_fails_then_succeeds_after_verification_over_a_real_server() {
    let url = spawn_server().await;

    // --- Real X3DH via the directory (same setup as
    // store/tests/routing_id_exchange.rs, since a from-scratch "discover
    // a stranger" flow isn't implemented yet — see this crate's module
    // doc). ---
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

    // --- Each side saves its account, Pending contact, and ratchet. ---
    let alice_fp = alice.identity.fingerprint().as_bytes().to_vec();
    let bob_fp = bob.identity.fingerprint().as_bytes().to_vec();
    let alice_routing_id = random_routing_id();
    let bob_routing_id = random_routing_id();

    let db_alice = Arc::new(temp_db());
    db_alice.save_account(&alice).unwrap();
    let mut alice_contact = Contact {
        fingerprint: bob_fp.clone(),
        username: Some("bob".into()),
        discriminator: Some(5001),
        verification_state: VerificationState::Pending,
        mailbox_id: bootstrap_mailbox_id(&bob_fp).to_vec(),
        created_at: 0,
        disappearing_timer_secs: None,
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

    let db_bob = Arc::new(temp_db());
    db_bob.save_account(&bob).unwrap();
    let mut bob_contact = Contact {
        fingerprint: alice_fp.clone(),
        username: None,
        discriminator: None,
        verification_state: VerificationState::Pending,
        mailbox_id: bootstrap_mailbox_id(&alice_fp).to_vec(),
        created_at: 0,
        disappearing_timer_secs: None,
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

    // --- Routing-id exchange through the real app API, sequentially
    // (the responder has no sending chain until it decrypts something —
    // same constraint the routing_id_exchange.rs test documents). ---
    announce_routing_id(
        &db_alice,
        &mut alice_conn,
        &alice,
        &alice_contact,
        alice_routing_id,
    )
    .await
    .unwrap();

    let received = receive_pending(&db_bob, &mut bob_conn, &bob, &bob_contact)
        .await
        .unwrap();
    assert!(
        received.messages.is_empty(),
        "a routing-id announce is not chat content"
    );
    bob_contact = db_bob.load_contact(&alice_fp).unwrap().unwrap();
    assert_ne!(
        bob_contact.mailbox_id,
        bootstrap_mailbox_id(&alice_fp).to_vec(),
        "bob's send-to-alice address should have transitioned off the bootstrap mailbox"
    );

    announce_routing_id(&db_bob, &mut bob_conn, &bob, &bob_contact, bob_routing_id)
        .await
        .unwrap();

    let received = receive_pending(&db_alice, &mut alice_conn, &alice, &alice_contact)
        .await
        .unwrap();
    assert!(received.messages.is_empty());
    alice_contact = db_alice.load_contact(&bob_fp).unwrap().unwrap();
    assert_eq!(
        alice_contact.mailbox_id, bob_contact.mailbox_id,
        "both sides must converge on the identical transitioned mailbox"
    );

    // --- The actual claim: chat is blocked while Pending, through the
    // real send_message API — not just at the store::gate unit level. ---
    let blocked = send_message(
        &db_alice,
        &mut alice_conn,
        &alice,
        &alice_contact,
        b"hi bob",
    )
    .await;
    assert!(
        matches!(
            blocked,
            Err(dratchet_app::Error::Store(
                dratchet_store::Error::NotVerified
            ))
        ),
        "sending chat content to a Pending contact must be refused: {blocked:?}"
    );

    // --- Verify both sides (standing in for a completed §6.3/§6.4 check
    // — this crate never performs that comparison itself, only records
    // the result). ---
    alice_contact = record_verification_result(&db_alice, alice_contact, true).unwrap();
    bob_contact = record_verification_result(&db_bob, bob_contact, true).unwrap();
    assert_eq!(
        alice_contact.verification_state,
        VerificationState::Verified
    );
    assert_eq!(bob_contact.verification_state, VerificationState::Verified);

    // --- Now a real chat message goes through end to end. ---
    let sent = send_message(
        &db_alice,
        &mut alice_conn,
        &alice,
        &alice_contact,
        b"hi bob",
    )
    .await
    .unwrap();
    assert_eq!(sent.content, b"hi bob");

    let received = receive_pending(&db_bob, &mut bob_conn, &bob, &bob_contact)
        .await
        .unwrap();
    assert_eq!(received.messages.len(), 1);
    assert_eq!(received.messages[0].content, b"hi bob");

    // And it's genuinely persisted on Bob's side, not just returned in
    // memory.
    let bob_conv_id = dratchet_core::conversation_id(&bob_fp, &alice_fp);
    let stored = db_bob.list_messages(bob_conv_id).unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].content, b"hi bob");
}
