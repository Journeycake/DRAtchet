//! Real end-to-end proof of the `receive_pending` fix: a single
//! corrupted/undecryptable mailbox entry must not wedge the whole batch.
//! Before the fix, any decode/decrypt failure hard-aborted the entire
//! call before that entry's `MailboxDelete` was sent — the bad entry
//! stayed in the mailbox forever, every entry behind it (in this batch
//! and every later poll) was unreachable, and any ratchet advancement
//! from entries processed earlier in the same batch was discarded since
//! the function returned before the trailing `db.save_ratchet`. No
//! mocks, matching this project's standing rule: a garbage entry is
//! written with a real raw `MailboxWrite`, sandwiched between two real
//! chat messages sent through the real app API.

use std::sync::Arc;

use dratchet_app::{
    add_contact_by_username, generate_pairing_code, open_account, publish_own_bundle,
    receive_first_contact_attempts, receive_pending, send_message,
};
use dratchet_client::net::Connection;
use dratchet_server::protocol::{FrameTag, MailboxWrite};
use dratchet_store::Db;
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
async fn a_corrupted_entry_between_two_real_messages_is_skipped_not_a_wedge() {
    let url = spawn_server().await;

    let db_alice = Arc::new(temp_db());
    let mut alice = open_account(&db_alice).unwrap();
    let mut alice_conn = Connection::connect(&url).await.unwrap();
    alice_conn.authenticate(&alice).await.unwrap();
    let alice_profile = publish_own_bundle(&db_alice, &mut alice_conn, &mut alice, "alice")
        .await
        .unwrap();

    let db_bob = Arc::new(temp_db());
    let mut bob = open_account(&db_bob).unwrap();
    let mut bob_conn = Connection::connect(&url).await.unwrap();
    bob_conn.authenticate(&bob).await.unwrap();
    let bob_profile = publish_own_bundle(&db_bob, &mut bob_conn, &mut bob, "bob")
        .await
        .unwrap();

    let code = generate_pairing_code(&db_bob).unwrap();
    let alice_contact = add_contact_by_username(
        &db_alice,
        &mut alice_conn,
        &alice,
        &alice_profile,
        &bob_profile.username,
        bob_profile.discriminator,
        &code.code,
    )
    .await
    .unwrap();
    let bob_contact = receive_first_contact_attempts(&db_bob, &mut bob_conn, &mut bob)
        .await
        .unwrap()
        .into_iter()
        .next()
        .unwrap();

    // Complete the routing-id exchange so both sides are on the stable,
    // symmetric mailbox address rather than the shared bootstrap inbox —
    // isolates this test to the fix itself, not the separate
    // shared-inbox-demultiplexing limitation `receive_pending` already
    // documents.
    receive_pending(&db_alice, &mut alice_conn, &alice, &alice_contact)
        .await
        .unwrap();
    let alice_contact = db_alice
        .load_contact(&alice_contact.fingerprint)
        .unwrap()
        .unwrap();
    receive_pending(&db_bob, &mut bob_conn, &bob, &bob_contact)
        .await
        .unwrap();
    let bob_contact = db_bob
        .load_contact(&bob_contact.fingerprint)
        .unwrap()
        .unwrap();

    send_message(&db_alice, &mut alice_conn, &alice, &alice_contact, b"one")
        .await
        .unwrap();

    // A garbage entry, written directly to the same mailbox real messages
    // land in — not a valid `Envelope` at all, so `Envelope::decode` in
    // `apply_entry` fails immediately. This is deliberately the crudest
    // possible corruption (rather than reproducing the specific
    // self-decrypt scenario that originally surfaced the bug) since the
    // fix's contract is "any per-entry content error is skipped," not
    // just that one case.
    alice_conn
        .send(
            FrameTag::MailboxWrite,
            &MailboxWrite {
                mailbox_id: alice_contact.mailbox_id.clone(),
                envelope: vec![0xDE, 0xAD, 0xBE, 0xEF],
                ttl: 3600,
            },
        )
        .await
        .unwrap();
    alice_conn.recv_raw().await.unwrap();

    send_message(&db_alice, &mut alice_conn, &alice, &alice_contact, b"two")
        .await
        .unwrap();

    let outcome = receive_pending(&db_bob, &mut bob_conn, &bob, &bob_contact)
        .await
        .unwrap();
    assert_eq!(
        outcome.messages.len(),
        2,
        "both real messages must survive the corrupted entry between them"
    );
    assert_eq!(outcome.messages[0].content, b"one");
    assert_eq!(outcome.messages[1].content, b"two");
    assert_eq!(
        outcome.skipped, 1,
        "the corrupted entry must be counted, not silently vanish without a trace"
    );

    // The mailbox must actually be drained — a second immediate fetch
    // must not turn up the same bad entry again (the wedge this test
    // guards against) or re-deliver the two real messages.
    let again = receive_pending(&db_bob, &mut bob_conn, &bob, &bob_contact)
        .await
        .unwrap();
    assert!(again.messages.is_empty());
    assert_eq!(again.skipped, 0);

    // And the ratchet survived the mixed batch intact: a further message
    // still round-trips normally afterward.
    send_message(&db_alice, &mut alice_conn, &alice, &alice_contact, b"three")
        .await
        .unwrap();
    let outcome = receive_pending(&db_bob, &mut bob_conn, &bob, &bob_contact)
        .await
        .unwrap();
    assert_eq!(outcome.messages.len(), 1);
    assert_eq!(outcome.messages[0].content, b"three");
}
