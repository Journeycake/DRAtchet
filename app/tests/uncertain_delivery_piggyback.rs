//! Real, no-mocks proof of the TCP-style cumulative piggyback ack
//! (`core::payload::ChatContent::piggyback_ack`,
//! `Db::mark_messages_delivered_up_to`) against a real spawned
//! `dratchet_server::app()`. Specifically isolates the case the dedicated
//! per-message `DeliveryAck` alone can't cover: Bob genuinely receives
//! Alice's messages (his ratchet really does advance — simulated here by
//! decrypting them with the raw `RatchetState` API rather than
//! `receive_pending`, which always sends a dedicated ack) but no
//! dedicated `DeliveryAck` for them is ever sent — the same state a
//! crash between "decrypted" and "ack sent" would leave behind. Alice
//! marks those sends `uncertain` (this app's response to detecting a
//! connection interruption). The claim under test: an ordinary,
//! unrelated follow-up chat message from Bob — sent through the real
//! `send_message` API, no dedicated ack involved anywhere — is enough by
//! itself to resolve Alice's uncertain messages to delivered.

use std::sync::Arc;

use dratchet_app::{
    announce_routing_id, mark_pending_sends_uncertain, receive_pending, record_verification_result,
    send_message,
};
use dratchet_client::net::Connection;
use dratchet_core::account::Account;
use dratchet_core::envelope::Envelope;
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
async fn a_followup_chat_messages_piggyback_ack_resolves_uncertain_sends_with_no_dedicated_ack_ever_sent(
) {
    let url = spawn_server().await;

    // --- Real X3DH pairing (same setup `pairing_and_chat.rs` uses). ---
    let mut bob = Account::generate().unwrap();
    let bob_otp_publics = bob.generate_one_time_prekeys(1);
    let bob_local_bundle = bob.publish_bundle(false).unwrap();
    let bob_bundle_wire = PrekeyBundleWire {
        username: "bob".into(),
        discriminator: 6001,
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
            6001,
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
                discriminator: 6001,
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

    let db_alice = Arc::new(temp_db());
    db_alice.save_account(&alice).unwrap();
    let mut alice_contact = Contact {
        fingerprint: bob_fp.clone(),
        username: Some("bob".into()),
        discriminator: Some(6001),
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

    let db_bob = Arc::new(temp_db());
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
    assert_eq!(alice_contact.mailbox_id, bob_contact.mailbox_id);

    alice_contact = record_verification_result(&db_alice, alice_contact, true).unwrap();
    bob_contact = record_verification_result(&db_bob, bob_contact, true).unwrap();

    // --- Alice sends 2 real messages to Bob through the real API. ---
    let sent_1 = send_message(
        &db_alice,
        &mut alice_conn,
        &alice,
        &alice_contact,
        b"are you there?",
    )
    .await
    .unwrap();
    let sent_2 = send_message(
        &db_alice,
        &mut alice_conn,
        &alice,
        &alice_contact,
        b"hello?",
    )
    .await
    .unwrap();
    assert!(!sent_1.delivered && !sent_1.uncertain);
    assert!(!sent_2.delivered && !sent_2.uncertain);

    // --- Alice detects a connection interruption (simulated directly,
    // matching what the Tauri poll loop's reconnect-succeeded path does)
    // and marks her outstanding sends uncertain. ---
    let newly_uncertain = mark_pending_sends_uncertain(&db_alice, &alice).unwrap();
    assert_eq!(newly_uncertain, 2);
    let alice_messages = dratchet_app::list_messages(&db_alice, &alice, &alice_contact).unwrap();
    assert!(alice_messages
        .iter()
        .all(|m| !m.sender_is_local || (m.uncertain && !m.delivered)));

    // --- Bob genuinely receives both messages — but via the RAW ratchet
    // API, not `receive_pending`, so his ratchet state really does
    // advance (recv_n = 2) while no dedicated `DeliveryAck` is ever sent
    // for either one. This is exactly the state a crash between
    // "decrypted" and "ack sent" would leave behind.
    //
    // Load bob's ratchet fresh from the db rather than reusing the local
    // `bob_ratchet` captured before the routing-id handshake: that
    // handshake (`announce_routing_id`/`receive_pending` above) already
    // drove the *persisted* ratchet through real DH ratchet steps, so the
    // stale local copy is cryptographically out of sync with what alice
    // actually encrypted with by this point. ---
    let mut bob_ratchet = db_bob.load_ratchet(conv_id).unwrap().unwrap();
    bob_conn
        .send(
            FrameTag::MailboxFetch,
            &MailboxFetch {
                mailbox_id: bob_contact.mailbox_id.clone(),
            },
        )
        .await
        .unwrap();
    let (_, entries): (_, MailboxEntries) = bob_conn.recv().await.unwrap();
    assert_eq!(
        entries.entries.len(),
        2,
        "both of alice's real sends should be sitting in bob's mailbox"
    );
    for entry in &entries.entries {
        let envelope = Envelope::decode(&entry.envelope).unwrap();
        let (payload_type, _content) = bob_ratchet.decrypt_payload(&envelope).unwrap();
        assert_eq!(payload_type, dratchet_core::payload::PAYLOAD_CHAT);
        bob_conn
            .send(
                FrameTag::MailboxDelete,
                &MailboxDelete {
                    mailbox_id: bob_contact.mailbox_id.clone(),
                    entry_id: entry.entry_id.clone(),
                },
            )
            .await
            .unwrap();
        let (_, ack): (_, Ack) = bob_conn.recv().await.unwrap();
        assert!(ack.ok);
    }
    db_bob.save_ratchet(conv_id, &bob_ratchet).unwrap();
    // No DeliveryAck was ever written to alice's mailbox for either
    // message — confirmed structurally: nothing in this block ever
    // called `receive_pending` (the only code path that sends one) or
    // wrote to `alice_contact.mailbox_id` at all.

    // --- Bob now sends a real, unrelated follow-up chat message through
    // the real API. His ratchet's `receiving_progress()` correctly
    // reports (alice's chain, highest_n=1), so this message's envelope
    // carries a real `PiggybackAck` covering both of alice's sends. ---
    let bob_reply = send_message(
        &db_bob,
        &mut bob_conn,
        &bob,
        &bob_contact,
        b"yes, sorry, here now",
    )
    .await
    .unwrap();
    assert!(!bob_reply.delivered && !bob_reply.uncertain);

    // --- Alice receives Bob's reply through the real API. ---
    let received = receive_pending(&db_alice, &mut alice_conn, &alice, &alice_contact)
        .await
        .unwrap();
    assert_eq!(received.messages.len(), 1);
    assert_eq!(received.messages[0].content, b"yes, sorry, here now");

    // The claim under test: both of alice's previously-uncertain sends
    // are now delivered, resolved purely by the piggyback ack riding on
    // bob's unrelated reply — no dedicated ack ever touched them.
    assert_eq!(
        received.delivered.len(),
        2,
        "the piggyback ack should resolve both uncertain sends in one shot"
    );
    let alice_messages = dratchet_app::list_messages(&db_alice, &alice, &alice_contact).unwrap();
    let sent_by_alice: Vec<_> = alice_messages
        .iter()
        .filter(|m| m.sender_is_local)
        .collect();
    assert_eq!(sent_by_alice.len(), 2);
    for m in sent_by_alice {
        assert!(m.delivered, "message should now be delivered: {m:?}");
        assert!(
            !m.uncertain,
            "delivered messages must not still read as uncertain: {m:?}"
        );
    }
}
