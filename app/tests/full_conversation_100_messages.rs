//! Real, no-mocks functionality test: two real accounts, paired through
//! the actual production add-contact flow (§6.4), exchange 100 real
//! messages over a real spawned `dratchet_server::app()` — the same
//! `send_message`/`receive_pending` functions the Tauri UI calls, no
//! shortcuts. Three phases, matching the requested shape:
//!
//! 1. 25 messages Alice → Bob, sent as a burst then drained in one
//!    `receive_pending` call (tests batch/out-of-order-arrival handling
//!    at the app layer, not just the already-covered ratchet layer).
//! 2. 25 messages Bob → Alice, synchronous send-then-immediately-receive
//!    each time (the ordinary one-at-a-time chat pattern).
//! 3. 50 messages, real back-and-forth turn-taking (25 each way,
//!    alternating) — the only phase where the Double Ratchet's DH step
//!    actually fires on every turn, since that only happens when a reply
//!    crosses over the other side's last-seen key.
//!
//! Every phase checks content and per-phase counts. The final check is
//! the real point of this test: does each side's full, persisted message
//! history (`list_messages`) come back in the *actual* order the
//! messages were sent, not just "the right 100 messages, some order"?
//! See `scenario_final` below for why that's a real, non-obvious question
//! here rather than a formality.

use std::sync::Arc;

use dratchet_app::{
    add_contact_by_username, generate_pairing_code, open_account, publish_own_bundle,
    receive_first_contact_attempts, receive_pending, send_message,
};
use dratchet_client::net::Connection;
use dratchet_store::{Contact, Db};
use tokio::net::TcpListener;

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
async fn a_full_100_message_conversation_between_two_real_clients() {
    let url = spawn_server().await;

    // --- Setup: real self-registration + real pairing-code add-contact,
    // exactly the flow a user drives from the UI. ---
    let db_alice = Arc::new(temp_db());
    let mut alice = open_account(&db_alice).unwrap();
    let mut alice_conn = Connection::connect(&url).await.unwrap();
    alice_conn.authenticate(&alice).await.unwrap();
    let alice_profile = publish_own_bundle(&db_alice, &mut alice_conn, &mut alice, "alice100")
        .await
        .unwrap();

    let db_bob = Arc::new(temp_db());
    let mut bob = open_account(&db_bob).unwrap();
    let mut bob_conn = Connection::connect(&url).await.unwrap();
    bob_conn.authenticate(&bob).await.unwrap();
    let bob_profile = publish_own_bundle(&db_bob, &mut bob_conn, &mut bob, "bob100")
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

    let bob_new = receive_first_contact_attempts(&db_bob, &mut bob_conn, &mut bob)
        .await
        .unwrap();
    assert_eq!(
        bob_new.len(),
        1,
        "bob must discover exactly the one attempt"
    );
    let bob_contact = bob_new.into_iter().next().unwrap();

    let mut alice_sent_texts: Vec<String> = Vec::new();
    let mut bob_sent_texts: Vec<String> = Vec::new();
    // Records (sender, text) in the *actual real-time order* every send
    // call in this test completed — the ground truth the final ordering
    // check below is measured against.
    let mut real_send_order: Vec<(&'static str, String)> = Vec::new();

    // --- Phase 1: 25 Alice -> Bob, burst then one batch receive. ---
    for i in 0..25 {
        let text = format!("alice burst {i}");
        send_message(
            &db_alice,
            &mut alice_conn,
            &alice,
            &alice_contact,
            text.as_bytes(),
        )
        .await
        .unwrap_or_else(|e| panic!("alice send {i} in phase 1 failed: {e}"));
        real_send_order.push(("alice", text.clone()));
        alice_sent_texts.push(text);
    }
    let received = receive_pending(&db_bob, &mut bob_conn, &bob, &bob_contact)
        .await
        .unwrap();
    assert_eq!(
        received.messages.len(),
        25,
        "phase 1: bob must receive all 25 burst messages in one batch fetch"
    );
    let received_texts: Vec<String> = received
        .messages
        .iter()
        .map(|m| String::from_utf8(m.content.clone()).unwrap())
        .collect();
    assert_eq!(
        received_texts, alice_sent_texts,
        "phase 1: the batch must decrypt in the order the messages were actually \
         encrypted (chain position order), not arrival/fetch order"
    );

    // --- Phase 2: 25 Bob -> Alice, synchronous send-then-receive. ---
    for i in 0..25 {
        let text = format!("bob reply {i}");
        send_message(&db_bob, &mut bob_conn, &bob, &bob_contact, text.as_bytes())
            .await
            .unwrap_or_else(|e| panic!("bob send {i} in phase 2 failed: {e}"));
        real_send_order.push(("bob", text.clone()));
        bob_sent_texts.push(text.clone());

        let received = receive_pending(&db_alice, &mut alice_conn, &alice, &alice_contact)
            .await
            .unwrap();
        assert_eq!(
            received.messages.len(),
            1,
            "phase 2, message {i}: exactly one new message per synchronous round trip"
        );
        assert_eq!(
            String::from_utf8(received.messages[0].content.clone()).unwrap(),
            text,
            "phase 2, message {i}: content must match exactly"
        );
    }

    // --- Phase 3: 50 messages, real alternating turn-taking (25 each
    // way) — the only phase where the DH ratchet actually steps on every
    // single turn. ---
    for i in 0..25 {
        let a_text = format!("alice turn {i}");
        send_message(
            &db_alice,
            &mut alice_conn,
            &alice,
            &alice_contact,
            a_text.as_bytes(),
        )
        .await
        .unwrap_or_else(|e| panic!("alice send in phase 3 turn {i} failed: {e}"));
        real_send_order.push(("alice", a_text.clone()));
        alice_sent_texts.push(a_text.clone());

        let bob_received = receive_pending(&db_bob, &mut bob_conn, &bob, &bob_contact)
            .await
            .unwrap();
        assert_eq!(bob_received.messages.len(), 1);
        assert_eq!(
            String::from_utf8(bob_received.messages[0].content.clone()).unwrap(),
            a_text
        );

        let b_text = format!("bob turn {i}");
        send_message(
            &db_bob,
            &mut bob_conn,
            &bob,
            &bob_contact,
            b_text.as_bytes(),
        )
        .await
        .unwrap_or_else(|e| panic!("bob send in phase 3 turn {i} failed: {e}"));
        real_send_order.push(("bob", b_text.clone()));
        bob_sent_texts.push(b_text.clone());

        let alice_received = receive_pending(&db_alice, &mut alice_conn, &alice, &alice_contact)
            .await
            .unwrap();
        assert_eq!(alice_received.messages.len(), 1);
        assert_eq!(
            String::from_utf8(alice_received.messages[0].content.clone()).unwrap(),
            b_text
        );
    }

    assert_eq!(real_send_order.len(), 100, "sanity: 25 + 25 + 50 = 100");
    assert_eq!(alice_sent_texts.len(), 50);
    assert_eq!(bob_sent_texts.len(), 50);

    // --- Final check: does the persisted, displayed history come back in
    // the order the messages actually happened? Both sides' full
    // conversation history should contain all 100 messages (50 sent + 50
    // received, from each side's own point of view) and — this is the
    // real point of the test — in the same order `real_send_order` above
    // recorded them happening in real time, not some other order.
    verify_full_history_matches_real_order(&db_alice, &alice, &alice_contact, &real_send_order);
    verify_full_history_matches_real_order(&db_bob, &bob, &bob_contact, &real_send_order);
}

fn verify_full_history_matches_real_order(
    db: &Db,
    account: &dratchet_core::account::Account,
    peer_contact: &Contact,
    real_send_order: &[(&'static str, String)],
) {
    let conv_id = dratchet_core::conversation_id(
        account.identity.fingerprint().as_bytes(),
        &peer_contact.fingerprint,
    );
    let history = db.list_messages(conv_id).unwrap();
    assert_eq!(
        history.len(),
        100,
        "every side's persisted history must contain all 100 messages, sent and received"
    );

    let history_texts: Vec<String> = history
        .iter()
        .map(|m| String::from_utf8(m.content.clone()).unwrap())
        .collect();
    let expected_texts: Vec<String> = real_send_order.iter().map(|(_, t)| t.clone()).collect();

    if history_texts != expected_texts {
        // Not a hard failure of the whole test suite via panic-with-no-
        // context — report exactly where the order first diverges, since
        // this is the actual finding this test exists to surface, not an
        // incidental assertion failure.
        let first_mismatch = history_texts
            .iter()
            .zip(expected_texts.iter())
            .position(|(a, b)| a != b);
        panic!(
            "message history is NOT in real chronological order.\n\
             first divergence at index {first_mismatch:?}\n\
             expected (real send order): {expected_texts:?}\n\
             actual   (list_messages):   {history_texts:?}"
        );
    }
}
