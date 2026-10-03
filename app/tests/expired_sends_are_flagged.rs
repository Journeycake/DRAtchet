//! DRA-0063: a message the recipient never collected expired silently.
//!
//! The relay keeps an uncollected message for `MAILBOX_TTL_SECS` (14 days)
//! and then discards it, telling nobody (audit scenario 1). The sender's
//! copy stayed "sent, not yet delivered" forever, indistinguishable from
//! one still waiting, with no way to resend it except retyping it.

use std::sync::Arc;

use dratchet_app::{
    add_contact_by_username, generate_pairing_code, mark_expired_sends, open_account,
    publish_own_bundle, receive_first_contact_attempts, receive_pending, retry_message,
    send_message, EXPIRY_GRACE_SECS, MAILBOX_TTL_SECS,
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
async fn a_message_undelivered_past_the_mailbox_lifetime_is_flagged_for_retry() {
    let url = spawn_server().await;
    let mut p = paired(&url, "63a").await;
    let conv = conversation_id_for(&p.alice, &p.alice_contact);

    let sent = send_message(
        &p.db_alice,
        &mut p.alice_conn,
        &p.alice,
        &p.alice_contact,
        b"anyone there?",
    )
    .await
    .unwrap();
    let accepted_at = sent.last_sent_at.expect("the server accepted it");
    let expires_at = accepted_at + u64::from(MAILBOX_TTL_SECS) + EXPIRY_GRACE_SECS;

    // Bob never collects it. Just before the server would have dropped it,
    // nothing is flagged.
    assert_eq!(
        mark_expired_sends(&p.db_alice, &p.alice, expires_at - 1).unwrap(),
        0
    );
    // Once it's past the server's lifetime for it:
    mark_expired_sends(&p.db_alice, &p.alice, expires_at).unwrap();
    let after = p.db_alice.load_message(conv, &sent.id).unwrap().unwrap();
    assert_eq!(
        after.retry_reason,
        Some(RetryReason::Expired),
        "VULNERABILITY: a message nobody collected within the server's {} days is still shown \
         as merely 'sent' -- the server has discarded it and the sender is never told",
        MAILBOX_TTL_SECS / 86_400
    );

    // Retrying sends it again with a fresh key; Bob sees it once (the
    // test server never actually discarded the original, so this also
    // exercises DRA-0060's duplicate suppression).
    let retried = retry_message(
        &p.db_alice,
        &mut p.alice_conn,
        &p.alice,
        &p.alice_contact,
        &sent.id,
    )
    .await
    .unwrap();
    assert_eq!(retried.retry_reason, None);
    assert!(
        retried.last_sent_at.is_some(),
        "a retry restarts the lifetime"
    );
    let got = receive_pending(&p.db_bob, &mut p.bob_conn, &p.bob, &p.bob_contact)
        .await
        .unwrap();
    assert_eq!(got.messages.len(), 1);
    assert_eq!(got.messages[0].content, b"anyone there?");
}

/// Guard: a delivery receipt that turns up after the message was flagged
/// clears the flag -- it was delivered after all.
#[tokio::test]
async fn a_late_delivery_receipt_clears_the_expired_flag() {
    let url = spawn_server().await;
    let mut p = paired(&url, "63b").await;
    let conv = conversation_id_for(&p.alice, &p.alice_contact);

    let sent = send_message(
        &p.db_alice,
        &mut p.alice_conn,
        &p.alice,
        &p.alice_contact,
        b"late but delivered",
    )
    .await
    .unwrap();
    let expires_at = sent.last_sent_at.unwrap() + u64::from(MAILBOX_TTL_SECS) + EXPIRY_GRACE_SECS;
    mark_expired_sends(&p.db_alice, &p.alice, expires_at).unwrap();

    receive_pending(&p.db_bob, &mut p.bob_conn, &p.bob, &p.bob_contact)
        .await
        .unwrap();
    receive_pending(&p.db_alice, &mut p.alice_conn, &p.alice, &p.alice_contact)
        .await
        .unwrap();
    let after = p.db_alice.load_message(conv, &sent.id).unwrap().unwrap();
    assert!(after.delivered);
    assert_eq!(after.retry_reason, None);
}
