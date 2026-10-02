//! DRA-0064: a server restart silently lost every queued message.
//!
//! Mailboxes live only in the server's memory (audit scenario 9). A
//! restart, redeploy or crash dropped every message waiting to be
//! collected, for every user at once, and told nobody: senders kept
//! seeing "sent", recipients never got them.

use std::sync::Arc;

use dratchet_app::{
    add_contact_by_username, generate_pairing_code, note_server_boot, open_account,
    publish_own_bundle, receive_first_contact_attempts, receive_pending, retry_message,
    send_message,
};
use dratchet_client::net::Connection;
use dratchet_core::account::Account;
use dratchet_store::{Contact, Db, RetryReason};
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

fn conversation_id_for(account: &Account, contact: &Contact) -> [u8; 16] {
    dratchet_core::conversation_id(
        account.identity.fingerprint().as_bytes(),
        &contact.fingerprint,
    )
}

fn temp_db() -> Db {
    let dir = tempfile::tempdir().unwrap().keep();
    Db::create(dir.join("test.redb"), "pw").unwrap()
}

// `bob_conn` goes unused here: in the restart test Bob reconnects to the
// replacement server instead.
#[allow(dead_code)]
struct Pair {
    db_alice: Arc<Db>,
    alice: Account,
    alice_conn: Connection,
    alice_contact: Contact,
    db_bob: Arc<Db>,
    bob: Account,
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
async fn messages_waiting_on_a_server_that_restarted_are_flagged_for_retry() {
    // The server Alice and Bob paired on, and the one that replaces it.
    let before = spawn_server().await;
    let mut p = paired(&before, "64a").await;
    let conv = conversation_id_for(&p.alice, &p.alice_contact);
    note_server_boot(&p.db_alice, &p.alice, &p.alice_conn).unwrap();

    let sent = send_message(
        &p.db_alice,
        &mut p.alice_conn,
        &p.alice,
        &p.alice_contact,
        b"sent before the crash",
    )
    .await
    .unwrap();

    // The server restarts (a fresh process: new boot id, empty mailboxes)
    // before Bob collects anything.
    let after = spawn_server().await;
    let mut alice_conn = Connection::connect(&after).await.unwrap();
    alice_conn.authenticate(&p.alice).await.unwrap();
    let flagged = note_server_boot(&p.db_alice, &p.alice, &alice_conn).unwrap();

    let now = p.db_alice.load_message(conv, &sent.id).unwrap().unwrap();
    assert_eq!(
        now.retry_reason,
        Some(RetryReason::ServerRestarted),
        "VULNERABILITY: the server restarted and lost its queued mail, but the sender's \
         unconfirmed message is still shown as merely 'sent' -- nobody is told it is gone"
    );
    assert_eq!(flagged, 1);

    // Retrying puts it on the new server; Bob gets it there.
    retry_message(
        &p.db_alice,
        &mut alice_conn,
        &p.alice,
        &p.alice_contact,
        &sent.id,
    )
    .await
    .unwrap();
    let mut bob_conn = Connection::connect(&after).await.unwrap();
    bob_conn.authenticate(&p.bob).await.unwrap();
    let got = receive_pending(&p.db_bob, &mut bob_conn, &p.bob, &p.bob_contact)
        .await
        .unwrap();
    assert_eq!(got.messages.len(), 1);
    assert_eq!(got.messages[0].content, b"sent before the crash");
}

/// Guard: reconnecting to the same running server flags nothing.
#[tokio::test]
async fn reconnecting_to_the_same_server_flags_nothing() {
    let url = spawn_server().await;
    let mut p = paired(&url, "64b").await;
    note_server_boot(&p.db_alice, &p.alice, &p.alice_conn).unwrap();
    send_message(
        &p.db_alice,
        &mut p.alice_conn,
        &p.alice,
        &p.alice_contact,
        b"still waiting",
    )
    .await
    .unwrap();

    let mut again = Connection::connect(&url).await.unwrap();
    again.authenticate(&p.alice).await.unwrap();
    assert_eq!(note_server_boot(&p.db_alice, &p.alice, &again).unwrap(), 0);
}
