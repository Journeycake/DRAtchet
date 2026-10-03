//! Real end-to-end proof of `DeliveryAck` (`ARCHITECTURE.md` §4.6): two
//! real accounts, paired through the actual production add-contact flow,
//! exchanging real chat messages over a real spawned `dratchet_server::app()`.
//! No mocks, matching this project's standing rule.

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

struct Pair {
    db_alice: Arc<Db>,
    alice: dratchet_core::account::Account,
    alice_conn: Connection,
    alice_contact: Contact,
    db_bob: Arc<Db>,
    bob: dratchet_core::account::Account,
    bob_conn: Connection,
    bob_contact: Contact,
}

async fn paired(url: &str, tag: &str) -> Pair {
    let db_alice = Arc::new(temp_db());
    let mut alice = open_account(&db_alice).unwrap();
    let mut alice_conn = Connection::connect(url).await.unwrap();
    alice_conn.authenticate(&alice).await.unwrap();
    let alice_profile = publish_own_bundle(
        &db_alice,
        &mut alice_conn,
        &mut alice,
        &format!("alice{tag}"),
    )
    .await
    .unwrap();

    let db_bob = Arc::new(temp_db());
    let mut bob = open_account(&db_bob).unwrap();
    let mut bob_conn = Connection::connect(url).await.unwrap();
    bob_conn.authenticate(&bob).await.unwrap();
    let bob_profile = publish_own_bundle(&db_bob, &mut bob_conn, &mut bob, &format!("bob{tag}"))
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
    .unwrap();

    let bob_contact = receive_first_contact_attempts(&db_bob, &mut bob_conn, &mut bob)
        .await
        .unwrap()
        .into_iter()
        .next()
        .unwrap();

    Pair {
        db_alice,
        alice,
        alice_conn,
        alice_contact,
        db_bob,
        bob,
        bob_conn,
        bob_contact,
    }
}

#[tokio::test]
async fn receiving_a_chat_message_sends_back_a_delivery_ack_that_marks_it_delivered() {
    let url = spawn_server().await;
    let mut pair = paired(&url, "1").await;

    let sent = send_message(
        &pair.db_alice,
        &mut pair.alice_conn,
        &pair.alice,
        &pair.alice_contact,
        b"hello bob",
    )
    .await
    .unwrap();
    assert!(
        !sent.delivered,
        "must not be marked delivered before any ack has come back"
    );

    // Bob decrypting the message is what fires the ack, per `ARCHITECTURE.md`
    // §4.6 ("the moment a ratchet envelope decrypts successfully").
    let bob_received = receive_pending(
        &pair.db_bob,
        &mut pair.bob_conn,
        &pair.bob,
        &pair.bob_contact,
    )
    .await
    .unwrap();
    assert_eq!(bob_received.messages.len(), 1);
    assert_eq!(bob_received.messages[0].content, b"hello bob");
    assert!(
        bob_received.delivered.is_empty(),
        "bob has nothing of his own pending delivery yet"
    );

    // Alice's next receive_pending picks up the ack Bob just sent back.
    let alice_received = receive_pending(
        &pair.db_alice,
        &mut pair.alice_conn,
        &pair.alice,
        &pair.alice_contact,
    )
    .await
    .unwrap();
    assert!(
        alice_received.messages.is_empty(),
        "a DeliveryAck is not chat content"
    );
    assert_eq!(
        alice_received.delivered.len(),
        1,
        "alice must see her sent message flip to delivered"
    );
    assert_eq!(alice_received.delivered[0].id, sent.id);
    assert!(alice_received.delivered[0].delivered);

    // And it's genuinely persisted, not just returned in memory.
    let conv_id = dratchet_core::conversation_id(
        pair.alice.identity.fingerprint().as_bytes(),
        &pair.alice_contact.fingerprint,
    );
    let history = pair.db_alice.list_messages(conv_id).unwrap();
    assert_eq!(history.len(), 1);
    assert!(history[0].delivered);
}

#[tokio::test]
async fn acks_flow_correctly_in_both_directions() {
    let url = spawn_server().await;
    let mut pair = paired(&url, "2").await;

    let alice_sent = send_message(
        &pair.db_alice,
        &mut pair.alice_conn,
        &pair.alice,
        &pair.alice_contact,
        b"alice says hi",
    )
    .await
    .unwrap();
    receive_pending(
        &pair.db_bob,
        &mut pair.bob_conn,
        &pair.bob,
        &pair.bob_contact,
    )
    .await
    .unwrap();

    let bob_sent = send_message(
        &pair.db_bob,
        &mut pair.bob_conn,
        &pair.bob,
        &pair.bob_contact,
        b"bob says hi",
    )
    .await
    .unwrap();

    // Alice's mailbox now holds two entries from bob: the ack for
    // `alice_sent` (written right after his `receive_pending` above
    // decrypted it) and `bob_sent` itself — one batch fetch picks up
    // both: `alice_sent` flips delivered via the ack, and processing
    // `bob_sent` fires alice's own ack back to bob in the same call.
    let alice_round = receive_pending(
        &pair.db_alice,
        &mut pair.alice_conn,
        &pair.alice,
        &pair.alice_contact,
    )
    .await
    .unwrap();
    assert_eq!(alice_round.messages.len(), 1);
    assert_eq!(alice_round.messages[0].content, b"bob says hi");
    assert_eq!(alice_round.delivered.len(), 1);
    assert_eq!(alice_round.delivered[0].id, alice_sent.id);

    // Bob's next poll picks up the ack alice just sent for `bob_sent`.
    let bob_final = receive_pending(
        &pair.db_bob,
        &mut pair.bob_conn,
        &pair.bob,
        &pair.bob_contact,
    )
    .await
    .unwrap();
    assert_eq!(bob_final.delivered.len(), 1);
    assert_eq!(bob_final.delivered[0].id, bob_sent.id);

    let alice_conv_id = dratchet_core::conversation_id(
        pair.alice.identity.fingerprint().as_bytes(),
        &pair.alice_contact.fingerprint,
    );
    let alice_history = pair.db_alice.list_messages(alice_conv_id).unwrap();
    let alice_sent_record = alice_history
        .iter()
        .find(|m| m.sender_is_local)
        .expect("alice's own sent message must be in her history");
    assert!(alice_sent_record.delivered);

    let bob_conv_id = dratchet_core::conversation_id(
        pair.bob.identity.fingerprint().as_bytes(),
        &pair.bob_contact.fingerprint,
    );
    let bob_history = pair.db_bob.list_messages(bob_conv_id).unwrap();
    let bob_sent_record = bob_history
        .iter()
        .find(|m| m.sender_is_local)
        .expect("bob's own sent message must be in his history");
    assert!(bob_sent_record.delivered);
}

#[tokio::test]
async fn polling_immediately_after_sending_does_not_self_consume_the_message() {
    // Real, previously-undiscovered gap found while building this feature
    // (`ARCHITECTURE.md` §11.1's mailbox is bidirectional — see
    // `MailboxEntry::written_by` in `server/src/state.rs`): before the
    // fix, a sender polling the same shared mailbox before the recipient
    // fetched would see its own not-yet-collected envelope, fail to
    // decrypt it, and delete it as "processed" — destroying the message.
    // `DeliveryAck` writes back to that same shared mailbox on every
    // single received chat message, which turns this from a rare
    // choreography edge case into the common case for a real polling
    // client. This test proves the fix holds up under exactly that
    // pattern: the sender polls right after sending, *before* the
    // recipient ever fetches.
    let url = spawn_server().await;
    let mut pair = paired(&url, "3").await;

    let sent = send_message(
        &pair.db_alice,
        &mut pair.alice_conn,
        &pair.alice,
        &pair.alice_contact,
        b"still here?",
    )
    .await
    .unwrap();

    // Alice immediately polls her own mailbox — the exact ordering a fast
    // poll_loop tick could produce — before Bob ever fetches.
    let self_poll = receive_pending(
        &pair.db_alice,
        &mut pair.alice_conn,
        &pair.alice,
        &pair.alice_contact,
    )
    .await
    .unwrap();
    assert!(
        self_poll.messages.is_empty(),
        "alice must never receive her own sent message as if it were incoming"
    );
    assert_eq!(
        self_poll.skipped, 0,
        "alice's own not-yet-collected entry must simply not appear, not appear and fail to decrypt"
    );

    // Bob still gets it, completely intact.
    let bob_received = receive_pending(
        &pair.db_bob,
        &mut pair.bob_conn,
        &pair.bob,
        &pair.bob_contact,
    )
    .await
    .unwrap();
    assert_eq!(bob_received.messages.len(), 1);
    assert_eq!(bob_received.messages[0].content, sent.content);
}
