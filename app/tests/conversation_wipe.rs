//! Real end-to-end proof of `docs/ARCHITECTURE.md` §11.9a's per-
//! conversation wipe — including the *remote* side actually complying —
//! against a real spawned `dratchet_server::app()`. No mocks, matching
//! this project's standing rule. Reuses `pairing_and_chat.rs`'s real
//! X3DH-via-directory setup pattern rather than a lighter-weight one,
//! since these tests need the same real, verified, chat-capable pair.

use dratchet_app::{
    announce_routing_id, announce_wipe_policy, confirm_pending_wipe, decline_pending_wipe,
    receive_pending, record_verification_result, request_conversation_wipe, send_message,
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

struct Peer {
    db: Db,
    account: Account,
    conn: Connection,
    contact: Contact,
}

fn temp_db() -> Db {
    let dir = tempfile::tempdir().unwrap().keep();
    Db::create(dir.join("test.redb"), "pw").unwrap()
}

/// A real verified, chat-capable pair — real X3DH via the directory, real
/// routing-id exchange, both marked `Verified` — with no messages sent
/// yet, so each test can configure wipe policies from a clean slate.
/// Returns `(alice, bob, conversation_id)`.
async fn verified_pair() -> (Peer, Peer, [u8; 16]) {
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

    let db_alice = temp_db();
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

    let db_bob = temp_db();
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
    bob_contact = record_verification_result(&db_bob, bob_contact, true).unwrap();

    (
        Peer {
            db: db_alice,
            account: alice,
            conn: alice_conn,
            contact: alice_contact,
        },
        Peer {
            db: db_bob,
            account: bob,
            conn: bob_conn,
            contact: bob_contact,
        },
        conv_id,
    )
}

/// Both sides announce their preferences to each other, in both
/// directions — the real exchange a UI would trigger once after pairing.
/// Both announce before either receives, exercising `receive_pending`'s
/// fix for its own not-yet-deleted entry showing up in the shared,
/// post-transition mailbox (`app/tests/receive_pending_own_message.rs`) —
/// no longer worked around with a strict send/receive/send/receive
/// alternation now that that's handled correctly.
async fn exchange_wipe_policies(
    alice: &mut Peer,
    bob: &mut Peer,
    alice_ask: bool,
    alice_session: bool,
    bob_ask: bool,
    bob_session: bool,
) {
    alice.contact = announce_wipe_policy(
        &alice.db,
        &mut alice.conn,
        &alice.account,
        &alice.contact,
        alice_ask,
        alice_session,
    )
    .await
    .unwrap();
    bob.contact = announce_wipe_policy(
        &bob.db,
        &mut bob.conn,
        &bob.account,
        &bob.contact,
        bob_ask,
        bob_session,
    )
    .await
    .unwrap();

    receive_pending(&bob.db, &mut bob.conn, &bob.account, &bob.contact)
        .await
        .unwrap();
    bob.contact = bob
        .db
        .load_contact(&bob.contact.fingerprint)
        .unwrap()
        .unwrap();

    receive_pending(&alice.db, &mut alice.conn, &alice.account, &alice.contact)
        .await
        .unwrap();
    alice.contact = alice
        .db
        .load_contact(&alice.contact.fingerprint)
        .unwrap()
        .unwrap();
}

async fn send_and_deliver(alice: &mut Peer, bob: &mut Peer, text: &[u8]) {
    send_message(
        &alice.db,
        &mut alice.conn,
        &alice.account,
        &alice.contact,
        text,
    )
    .await
    .unwrap();
    let received = receive_pending(&bob.db, &mut bob.conn, &bob.account, &bob.contact)
        .await
        .unwrap();
    assert_eq!(received.messages.len(), 1);
}

#[tokio::test]
async fn both_permissive_auto_deletes_on_receipt_messages_only() {
    let (mut alice, mut bob, conv_id) = verified_pair().await;
    exchange_wipe_policies(&mut alice, &mut bob, false, false, false, false).await;
    send_and_deliver(&mut alice, &mut bob, b"hi bob").await;
    assert_eq!(bob.db.list_messages(conv_id).unwrap().len(), 1);

    let removed =
        request_conversation_wipe(&alice.db, &mut alice.conn, &alice.account, &alice.contact)
            .await
            .unwrap();
    assert_eq!(removed, 1, "alice's own copy: one message, session kept");
    assert!(alice.db.list_messages(conv_id).unwrap().is_empty());
    assert!(alice.db.load_ratchet(conv_id).unwrap().is_some());

    let outcome = receive_pending(&bob.db, &mut bob.conn, &bob.account, &bob.contact)
        .await
        .unwrap();
    assert!(outcome.wipe_activity, "bob must observe wipe activity");
    assert!(
        bob.db.list_messages(conv_id).unwrap().is_empty(),
        "bob must auto-comply when both sides are permissive"
    );
    assert!(
        bob.db.load_ratchet(conv_id).unwrap().is_some(),
        "messages-only wipe must leave the session intact"
    );
    let bob_contact = bob
        .db
        .load_contact(&bob.contact.fingerprint)
        .unwrap()
        .unwrap();
    assert!(!bob_contact.wipe_request_pending);

    // The session survived, so both sides can keep chatting immediately.
    bob.contact = bob_contact;
    send_and_deliver(&mut bob, &mut alice, b"still here").await;
}

#[tokio::test]
async fn both_strict_holds_for_confirmation_then_deletes_on_allow() {
    let (mut alice, mut bob, conv_id) = verified_pair().await;
    exchange_wipe_policies(&mut alice, &mut bob, true, false, true, false).await;
    send_and_deliver(&mut alice, &mut bob, b"hi bob").await;

    request_conversation_wipe(&alice.db, &mut alice.conn, &alice.account, &alice.contact)
        .await
        .unwrap();

    let outcome = receive_pending(&bob.db, &mut bob.conn, &bob.account, &bob.contact)
        .await
        .unwrap();
    assert!(outcome.wipe_activity);
    assert_eq!(
        bob.db.list_messages(conv_id).unwrap().len(),
        1,
        "nothing must be deleted until bob confirms"
    );
    let bob_contact = bob
        .db
        .load_contact(&bob.contact.fingerprint)
        .unwrap()
        .unwrap();
    assert!(bob_contact.wipe_request_pending);
    bob.contact = bob_contact;

    let removed = confirm_pending_wipe(&bob.db, &bob.account, &bob.contact).unwrap();
    assert_eq!(removed, 1);
    assert!(bob.db.list_messages(conv_id).unwrap().is_empty());
    let bob_contact = bob
        .db
        .load_contact(&bob.contact.fingerprint)
        .unwrap()
        .unwrap();
    assert!(!bob_contact.wipe_request_pending);
}

#[tokio::test]
async fn both_strict_declining_deletes_nothing() {
    let (mut alice, mut bob, conv_id) = verified_pair().await;
    exchange_wipe_policies(&mut alice, &mut bob, true, false, true, false).await;
    send_and_deliver(&mut alice, &mut bob, b"hi bob").await;

    request_conversation_wipe(&alice.db, &mut alice.conn, &alice.account, &alice.contact)
        .await
        .unwrap();
    receive_pending(&bob.db, &mut bob.conn, &bob.account, &bob.contact)
        .await
        .unwrap();
    bob.contact = bob
        .db
        .load_contact(&bob.contact.fingerprint)
        .unwrap()
        .unwrap();
    assert!(bob.contact.wipe_request_pending);

    let declined = decline_pending_wipe(&bob.db, &bob.contact).unwrap();
    assert!(!declined.wipe_request_pending);
    assert_eq!(
        bob.db.list_messages(conv_id).unwrap().len(),
        1,
        "declining must not delete anything"
    );
}

#[tokio::test]
async fn asymmetric_ask_preference_auto_delete_wins() {
    // Bob wants to be asked; Alice does not. Unanimity is required for
    // "ask," so the effective policy is delete-on-receipt.
    let (mut alice, mut bob, conv_id) = verified_pair().await;
    exchange_wipe_policies(&mut alice, &mut bob, false, false, true, false).await;
    send_and_deliver(&mut alice, &mut bob, b"hi bob").await;

    request_conversation_wipe(&alice.db, &mut alice.conn, &alice.account, &alice.contact)
        .await
        .unwrap();
    receive_pending(&bob.db, &mut bob.conn, &bob.account, &bob.contact)
        .await
        .unwrap();

    assert!(
        bob.db.list_messages(conv_id).unwrap().is_empty(),
        "alice's permissive preference must win — unanimous consent was not reached"
    );
    let bob_contact = bob
        .db
        .load_contact(&bob.contact.fingerprint)
        .unwrap()
        .unwrap();
    assert!(!bob_contact.wipe_request_pending);
}

#[tokio::test]
async fn asymmetric_scope_preference_session_included_wins() {
    // Only bob prefers the fuller wipe. `exchange_wipe_policies` is a
    // real bilateral exchange — both sides learn the other's preference —
    // so the merge function's core guarantee is that *both* sides
    // independently compute the same effective policy from the same two
    // inputs: alice's own local wipe (of her own copy, in
    // `request_conversation_wipe`) and bob's auto-complied wipe should
    // both end up including the session, even though alice's own
    // preference alone was `false`.
    let (mut alice, mut bob, conv_id) = verified_pair().await;
    exchange_wipe_policies(&mut alice, &mut bob, false, false, false, true).await;
    assert!(
        alice.contact.effective_wipe_include_session(),
        "alice must see the same effective policy bob does, once she's received his announce"
    );
    send_and_deliver(&mut alice, &mut bob, b"hi bob").await;

    request_conversation_wipe(&alice.db, &mut alice.conn, &alice.account, &alice.contact)
        .await
        .unwrap();
    receive_pending(&bob.db, &mut bob.conn, &bob.account, &bob.contact)
        .await
        .unwrap();

    assert!(bob.db.list_messages(conv_id).unwrap().is_empty());
    assert!(
        bob.db.load_ratchet(conv_id).unwrap().is_none(),
        "bob's session-included preference must win even though alice didn't ask for it"
    );
    assert!(
        alice.db.load_ratchet(conv_id).unwrap().is_none(),
        "alice's own local wipe also used the same effective (session-included) policy"
    );

    // Both sides' sessions are gone — a send from either must now fail.
    let bob_contact = bob
        .db
        .load_contact(&bob.contact.fingerprint)
        .unwrap()
        .unwrap();
    let bob_result =
        send_message(&bob.db, &mut bob.conn, &bob.account, &bob_contact, b"can't").await;
    assert!(matches!(bob_result, Err(dratchet_app::Error::NoSession)));
    let alice_result = send_message(
        &alice.db,
        &mut alice.conn,
        &alice.account,
        &alice.contact,
        b"can't",
    )
    .await;
    assert!(matches!(alice_result, Err(dratchet_app::Error::NoSession)));
}
