//! Real end-to-end regression proof for the `receive_pending` bug fixed
//! alongside this test: after the routing-id transition
//! (`store::routing`, Phase 1.6.2), both sides' send and fetch addresses
//! become the same symmetric `mailbox_id` (`receive_pending`'s own doc
//! comment in `app/src/lib.rs`), so a `MailboxFetch` can return not only
//! the peer's messages but also this side's own not-yet-deleted ones. This
//! side's ratchet has no receiving chain for its own outgoing `dh_pub`, so
//! decrypting its own message fails with an AEAD error
//! (`dratchet_store::Error::Core(dratchet_core::error::Error::Aead)`) —
//! `client/src/main.rs`'s reference CLI has always treated that as a
//! documented, harmless, silent-skip case (`client/README.md`), but
//! `receive_pending` didn't, so it hard-aborted the whole call instead.
//!
//! Reproduced here the most direct way: both Alice and Bob call
//! `send_message` before either calls `receive_pending`, so each side's
//! very next fetch returns a batch containing *both* its own message and
//! the peer's. Real spawned `dratchet_server::app()`, no mocks, matching
//! this project's standing rule — same setup pattern as
//! `pairing_and_chat.rs` and `conversation_wipe.rs`.

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
/// routing-id exchange (so both sides' `contact.mailbox_id` have already
/// converged on the same symmetric, post-transition address), both marked
/// `Verified`, no messages sent yet. Returns `(alice, bob, conversation_id)`.
/// Same setup `conversation_wipe.rs`'s `verified_pair` uses, duplicated
/// here rather than shared — this project's existing integration tests
/// each own their setup rather than importing a `tests/common` module.
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

    assert_eq!(
        alice_contact.mailbox_id, bob_contact.mailbox_id,
        "both sides must share the same post-transition mailbox_id for this test to actually \
         exercise the bug"
    );

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

/// The regression proof: both sides send into the shared mailbox before
/// either fetches, so each side's own `receive_pending` batch contains its
/// own message alongside the peer's. Neither call may error, and both
/// sides must end up with exactly the peer's message — not their own, and
/// not zero (which a wrongly-deleted own-entry would produce for the
/// *other* side once they got around to fetching).
#[tokio::test]
async fn both_send_before_either_receives_over_a_real_server() {
    let (mut alice, mut bob, conv_id) = verified_pair().await;

    send_message(
        &alice.db,
        &mut alice.conn,
        &alice.account,
        &alice.contact,
        b"hi bob",
    )
    .await
    .unwrap();
    send_message(
        &bob.db,
        &mut bob.conn,
        &bob.account,
        &bob.contact,
        b"hi alice",
    )
    .await
    .unwrap();

    // Before the fix: this panicked/errored out of `receive_pending`
    // entirely with `Store(Core(Aead))` the moment it hit its own
    // not-yet-deleted "hi bob" entry in the shared mailbox.
    let alice_received =
        receive_pending(&alice.db, &mut alice.conn, &alice.account, &alice.contact)
            .await
            .unwrap();
    assert_eq!(
        alice_received.messages.len(),
        1,
        "alice must get exactly bob's message"
    );
    assert_eq!(alice_received.messages[0].content, b"hi alice");

    let bob_received = receive_pending(&bob.db, &mut bob.conn, &bob.account, &bob.contact)
        .await
        .unwrap();
    assert_eq!(
        bob_received.messages.len(),
        1,
        "bob must get exactly alice's message"
    );
    assert_eq!(bob_received.messages[0].content, b"hi bob");

    // Final persisted state on both sides: `list_messages` returns full
    // conversation history (sent and received alike), so each side now
    // holds its own outgoing message plus the peer's incoming one — never
    // its own message a second time as "received", and never zero, which
    // a wrongly-deleted own-entry (the other bug this fix also avoids:
    // skipping without also skipping the `MailboxDelete` would let the
    // reader that couldn't decrypt an entry delete it anyway, destroying
    // it before the real recipient ever fetched) would produce on the
    // *other* side once it got around to fetching.
    // Same-second timestamps can tie, and message ids (so iteration order)
    // are random (`save_message`'s doc), so check membership rather than
    // position.
    let alice_stored = alice.db.list_messages(conv_id).unwrap();
    assert_eq!(alice_stored.len(), 2);
    assert!(alice_stored
        .iter()
        .any(|m| m.content == b"hi bob" && m.sender_is_local));
    assert!(alice_stored
        .iter()
        .any(|m| m.content == b"hi alice" && !m.sender_is_local));

    let bob_stored = bob.db.list_messages(conv_id).unwrap();
    assert_eq!(bob_stored.len(), 2);
    assert!(bob_stored
        .iter()
        .any(|m| m.content == b"hi alice" && m.sender_is_local));
    assert!(bob_stored
        .iter()
        .any(|m| m.content == b"hi bob" && !m.sender_is_local));

    // The session survived both own-message decrypt attempts uncorrupted
    // — an ordinary round trip still works immediately afterward.
    send_message(
        &alice.db,
        &mut alice.conn,
        &alice.account,
        &alice.contact,
        b"still works",
    )
    .await
    .unwrap();
    let follow_up = receive_pending(&bob.db, &mut bob.conn, &bob.account, &bob.contact)
        .await
        .unwrap();
    assert_eq!(follow_up.messages.len(), 1);
    assert_eq!(follow_up.messages[0].content, b"still works");
}
