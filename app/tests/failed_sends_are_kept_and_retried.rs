//! DRA-0060: a send that failed -- or whose acknowledgement was lost --
//! vanished from the sender's history, and the only "retry" was typing
//! it again as a brand-new message.
//!
//! `send_message` saved the message only after the server's `Ack`. If the
//! Ack was lost after the server had stored the envelope, the recipient
//! got the message but the sender's history never showed it; pressing
//! send again then delivered a second, separate copy. The two sides'
//! records of the conversation disagreed either way.

use std::sync::Arc;

use dratchet_app::{
    add_contact_by_username, generate_pairing_code, open_account, publish_own_bundle,
    receive_first_contact_attempts, receive_pending, retry_message, save_unsent_message,
    send_message, Error,
};
use dratchet_client::net::Connection;
use dratchet_core::account::Account;
use dratchet_server::protocol::*;
use dratchet_store::{Contact, Db, RetryReason};
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message as WsMessage;

async fn spawn_server() -> String {
    let (router, _state) = dratchet_server::app();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    format!("ws://{addr}/v1/ws")
}

/// Authenticates anyone, then drops the connection on the first
/// `MailboxWrite` without acknowledging it.
async fn spawn_relay_that_loses_the_ack() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
                let challenge = encode(
                    FrameTag::AuthChallenge,
                    &AuthChallenge {
                        nonce: vec![7u8; 32],
                    },
                );
                ws.send(WsMessage::Binary(challenge)).await.unwrap();
                while let Some(Ok(WsMessage::Binary(frame))) = ws.next().await {
                    match split_tag(&frame).unwrap().0 {
                        FrameTag::AuthResponse => {
                            let ack = encode(FrameTag::Ack, &Ack { ok: true });
                            ws.send(WsMessage::Binary(ack)).await.unwrap();
                        }
                        FrameTag::MailboxWrite => return,
                        _ => {}
                    }
                }
            });
        }
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
async fn a_failed_send_stays_in_the_senders_history_and_can_be_retried() {
    let url = spawn_server().await;
    let mut p = paired(&url, "60a").await;
    let conv = conversation_id_for(&p.alice, &p.alice_contact);

    let lossy = spawn_relay_that_loses_the_ack().await;
    let mut lossy_conn = Connection::connect(&lossy).await.unwrap();
    lossy_conn.authenticate(&p.alice).await.unwrap();
    let result = send_message(
        &p.db_alice,
        &mut lossy_conn,
        &p.alice,
        &p.alice_contact,
        b"are you there?",
    )
    .await;
    assert!(result.is_err(), "no Ack, so the send reports failure");

    let history = p.db_alice.list_messages(conv).unwrap();
    assert!(
        history.iter().any(|m| m.content == b"are you there?"),
        "VULNERABILITY: a send that failed (or whose Ack was lost after the server stored it) \
         is missing from the sender's history -- the recipient may have it, the sender has no \
         record of it and no way to resend it"
    );
    let failed = history
        .iter()
        .find(|m| m.content == b"are you there?")
        .unwrap();
    assert_eq!(failed.retry_reason, Some(RetryReason::SendFailed));
    assert!(matches!(result, Err(Error::NotSent { .. })));

    // Retry over a working connection: sent, unflagged, received once.
    let retried = retry_message(
        &p.db_alice,
        &mut p.alice_conn,
        &p.alice,
        &p.alice_contact,
        &failed.id,
    )
    .await
    .unwrap();
    assert_eq!(retried.id, failed.id, "the same message, updated in place");
    assert_eq!(retried.retry_reason, None);
    let got = receive_pending(&p.db_bob, &mut p.bob_conn, &p.bob, &p.bob_contact)
        .await
        .unwrap();
    assert_eq!(got.messages.len(), 1);
    assert_eq!(got.messages[0].content, b"are you there?");
}

/// The lost-Ack case where the first attempt *did* reach the recipient:
/// the resend carries the same message id, so the recipient doesn't show
/// it twice -- and still acknowledges it, so the sender sees it delivered.
#[tokio::test]
async fn a_resend_the_recipient_already_has_is_not_shown_twice() {
    let url = spawn_server().await;
    let mut p = paired(&url, "60b").await;
    let conv = conversation_id_for(&p.alice, &p.alice_contact);

    let mut sent = send_message(
        &p.db_alice,
        &mut p.alice_conn,
        &p.alice,
        &p.alice_contact,
        b"once only",
    )
    .await
    .unwrap();
    // The server stored it, but pretend the Ack was lost.
    sent.retry_reason = Some(RetryReason::SendFailed);
    p.db_alice.save_message(conv, &sent).unwrap();

    retry_message(
        &p.db_alice,
        &mut p.alice_conn,
        &p.alice,
        &p.alice_contact,
        &sent.id,
    )
    .await
    .unwrap();

    let got = receive_pending(&p.db_bob, &mut p.bob_conn, &p.bob, &p.bob_contact)
        .await
        .unwrap();
    assert_eq!(
        got.messages.len(),
        1,
        "the resend is not shown as a new message"
    );
    let bob_conv = conversation_id_for(&p.bob, &p.bob_contact);
    let bob_history: Vec<_> = p
        .db_bob
        .list_messages(bob_conv)
        .unwrap()
        .into_iter()
        .filter(|m| !m.sender_is_local)
        .collect();
    assert_eq!(bob_history.len(), 1, "one copy in the recipient's history");

    // Bob acknowledged the resend's envelope, so Alice's copy is confirmed.
    receive_pending(&p.db_alice, &mut p.alice_conn, &p.alice, &p.alice_contact)
        .await
        .unwrap();
    let alice_copy = p.db_alice.load_message(conv, &sent.id).unwrap().unwrap();
    assert!(
        alice_copy.delivered,
        "the resend's acknowledgement confirms delivery"
    );
    assert_eq!(alice_copy.retry_reason, None);
}

/// DRA-0062: a message written while the app has no connection at all is
/// kept, flagged for retry, and delivered normally once retried.
#[tokio::test]
async fn a_message_written_offline_is_kept_and_sent_on_retry() {
    let url = spawn_server().await;
    let mut p = paired(&url, "62").await;

    let offline =
        save_unsent_message(&p.db_alice, &p.alice, &p.alice_contact, b"written offline").unwrap();
    assert_eq!(offline.retry_reason, Some(RetryReason::SendFailed));
    assert_eq!(
        offline.send_n, None,
        "nothing is encrypted until it's actually sent"
    );

    retry_message(
        &p.db_alice,
        &mut p.alice_conn,
        &p.alice,
        &p.alice_contact,
        &offline.id,
    )
    .await
    .unwrap();
    let got = receive_pending(&p.db_bob, &mut p.bob_conn, &p.bob, &p.bob_contact)
        .await
        .unwrap();
    assert_eq!(got.messages.len(), 1);
    assert_eq!(got.messages[0].content, b"written offline");
}
