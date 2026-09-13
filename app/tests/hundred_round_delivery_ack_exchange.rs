//! Real, no-mocks 100-round bidirectional exchange test for `DeliveryAck`
//! (`ARCHITECTURE.md` §4.6) — the follow-up requested after building the
//! feature: same scale as `app/tests/full_conversation_100_messages.rs`'s
//! two-client 100-message functionality test, but this one specifically
//! exercises `DeliveryAck` itself, not just ordinary message delivery.
//!
//! 100 rounds of real alternating turn-taking (Alice sends, Bob receives
//! and acks, Bob sends, Alice receives and acks) — the shape that
//! `docs/DELIVERY_FAILURE_FINDINGS.md` finding #28 identifies as the
//! *common* case, where a fresh Double Ratchet DH step fires on nearly
//! every turn, and confirms `DeliveryAck` still resolves correctly under
//! it despite that finding's documented `acked_n`-collision limitation
//! (ordinary sequential turn-taking is exactly the case the current
//! matching heuristic is correct for). Real accounts, real pairing, real
//! spawned `dratchet_server::app()` — no mocked crypto or network
//! behavior anywhere, matching this project's standing rule.

use std::sync::Arc;

use dratchet_app::{
    add_contact_by_username, generate_pairing_code, open_account, publish_own_bundle,
    receive_first_contact_attempts, receive_pending, send_message,
};
use dratchet_client::net::Connection;
use dratchet_store::Db;
use tokio::net::TcpListener;

const ROUNDS: usize = 100;

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

#[tokio::test]
async fn a_hundred_round_bidirectional_exchange_resolves_every_delivery_ack() {
    let url = spawn_server().await;

    // --- Setup: real self-registration + real pairing-code add-contact,
    // exactly the flow a user drives from the UI (same as
    // full_conversation_100_messages.rs). ---
    let db_alice = Arc::new(temp_db());
    let mut alice = open_account(&db_alice).unwrap();
    let mut alice_conn = Connection::connect(&url).await.unwrap();
    alice_conn.authenticate(&alice).await.unwrap();
    let alice_profile = publish_own_bundle(&db_alice, &mut alice_conn, &mut alice, "alice-ack")
        .await
        .unwrap();

    let db_bob = Arc::new(temp_db());
    let mut bob = open_account(&db_bob).unwrap();
    let mut bob_conn = Connection::connect(&url).await.unwrap();
    bob_conn.authenticate(&bob).await.unwrap();
    let bob_profile = publish_own_bundle(&db_bob, &mut bob_conn, &mut bob, "bob-ack")
        .await
        .unwrap();

    let code = generate_pairing_code(&db_bob).unwrap().code;
    let alice_contact = add_contact_by_username(
        &db_alice,
        &mut alice_conn,
        &alice,
        &alice_profile,
        &bob_profile.username,
        bob_profile.discriminator,
        &code,
    )
    .await
    .expect("pairing must succeed with the real, live code");

    let bob_contact = receive_first_contact_attempts(&db_bob, &mut bob_conn, &mut bob)
        .await
        .unwrap()
        .into_iter()
        .next()
        .expect("bob must discover the one attempt");

    let mut alice_sent_ids: Vec<Vec<u8>> = Vec::with_capacity(ROUNDS);
    let mut bob_sent_ids: Vec<Vec<u8>> = Vec::with_capacity(ROUNDS);

    // --- 100 rounds of real alternating turn-taking. Each round: alice
    // sends, bob receives (picking up alice's message and, from round 2
    // on, the ack for bob's *previous* round's send), bob sends, alice
    // receives (picking up bob's message and the ack for alice's
    // *current* round's send, since it was already sitting in the
    // mailbox by the time bob wrote his ack for it just above). ---
    for i in 0..ROUNDS {
        let a_text = format!("alice round {i}");
        let a_sent = send_message(
            &db_alice,
            &mut alice_conn,
            &alice,
            &alice_contact,
            a_text.as_bytes(),
        )
        .await
        .unwrap_or_else(|e| panic!("alice send round {i} failed: {e}"));
        alice_sent_ids.push(a_sent.id.clone());

        let bob_round = receive_pending(&db_bob, &mut bob_conn, &bob, &bob_contact)
            .await
            .unwrap_or_else(|e| panic!("bob receive round {i} failed: {e}"));
        assert_eq!(
            bob_round.messages.len(),
            1,
            "round {i}: bob must receive exactly alice's one new message"
        );
        assert_eq!(bob_round.messages[0].content, a_text.as_bytes());
        if i > 0 {
            assert_eq!(
                bob_round.delivered.len(),
                1,
                "round {i}: bob must see his previous round's send flip to delivered"
            );
            assert_eq!(bob_round.delivered[0].id, bob_sent_ids[i - 1]);
        }

        let b_text = format!("bob round {i}");
        let b_sent = send_message(
            &db_bob,
            &mut bob_conn,
            &bob,
            &bob_contact,
            b_text.as_bytes(),
        )
        .await
        .unwrap_or_else(|e| panic!("bob send round {i} failed: {e}"));
        bob_sent_ids.push(b_sent.id.clone());

        let alice_round = receive_pending(&db_alice, &mut alice_conn, &alice, &alice_contact)
            .await
            .unwrap_or_else(|e| panic!("alice receive round {i} failed: {e}"));
        assert_eq!(
            alice_round.messages.len(),
            1,
            "round {i}: alice must receive exactly bob's one new message"
        );
        assert_eq!(alice_round.messages[0].content, b_text.as_bytes());
        assert_eq!(
            alice_round.delivered.len(),
            1,
            "round {i}: alice must see her own this-round send flip to delivered"
        );
        assert_eq!(alice_round.delivered[0].id, alice_sent_ids[i]);
    }

    // --- Trailing poll on each side to pick up the very last round's
    // outstanding ack (bob's ack for alice's round-99 send arrived above;
    // alice's ack for bob's round-99 send was written during that same
    // call but bob hasn't polled again to receive it yet). ---
    let bob_trailing = receive_pending(&db_bob, &mut bob_conn, &bob, &bob_contact)
        .await
        .unwrap();
    assert!(bob_trailing.messages.is_empty());
    assert_eq!(bob_trailing.delivered.len(), 1);
    assert_eq!(bob_trailing.delivered[0].id, bob_sent_ids[ROUNDS - 1]);

    // --- The real point of this test: every one of the 100 messages each
    // side sent is durably marked delivered — not just returned once in a
    // `Received::delivered` batch, but actually persisted that way. ---
    let alice_conv_id = dratchet_core::conversation_id(
        alice.identity.fingerprint().as_bytes(),
        &alice_contact.fingerprint,
    );
    let alice_history = db_alice.list_messages(alice_conv_id).unwrap();
    assert_eq!(alice_history.len(), 2 * ROUNDS);
    let alice_sent_count = alice_history.iter().filter(|m| m.sender_is_local).count();
    assert_eq!(alice_sent_count, ROUNDS);
    let alice_delivered_count = alice_history
        .iter()
        .filter(|m| m.sender_is_local && m.delivered)
        .count();
    assert_eq!(
        alice_delivered_count, ROUNDS,
        "every one of alice's 100 sent messages must be marked delivered"
    );

    let bob_conv_id = dratchet_core::conversation_id(
        bob.identity.fingerprint().as_bytes(),
        &bob_contact.fingerprint,
    );
    let bob_history = db_bob.list_messages(bob_conv_id).unwrap();
    assert_eq!(bob_history.len(), 2 * ROUNDS);
    let bob_sent_count = bob_history.iter().filter(|m| m.sender_is_local).count();
    assert_eq!(bob_sent_count, ROUNDS);
    let bob_delivered_count = bob_history
        .iter()
        .filter(|m| m.sender_is_local && m.delivered)
        .count();
    assert_eq!(
        bob_delivered_count, ROUNDS,
        "every one of bob's 100 sent messages must be marked delivered"
    );

    // Received messages are never themselves marked delivered — that flag
    // only ever describes the sender's own outgoing messages.
    assert!(alice_history
        .iter()
        .filter(|m| !m.sender_is_local)
        .all(|m| !m.delivered));
    assert!(bob_history
        .iter()
        .filter(|m| !m.sender_is_local)
        .all(|m| !m.delivered));
}
