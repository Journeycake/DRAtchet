//! A retry that keeps failing, then succeeds.
//!
//! Every send attempt commits the ratchet before it goes out (DRA-0059), so
//! each failed attempt uses up one chain position, and the recipient has to
//! skip past those positions when the message finally arrives. These tests
//! fail sends for real -- the connection to a real server is cut mid-session
//! -- retry them on the dead connection, then retry once the server is
//! reachable again.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use dratchet_app::{
    add_contact_by_username, announce_wipe_policy, generate_pairing_code, list_messages,
    open_account, publish_own_bundle, receive_first_contact_attempts, receive_pending,
    request_conversation_wipe, retry_message, send_message, Error,
};
use dratchet_client::net::Connection;
use dratchet_core::account::Account;
use dratchet_core::ratchet::DEFAULT_MAX_SKIP;
use dratchet_server::protocol::{FetchOwnPrekeyCount, FrameTag};
use dratchet_store::{Contact, Db, Message, RetryReason};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::AbortHandle;

async fn spawn_server() -> String {
    let (router, _state) = dratchet_server::app();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    format!("ws://{addr}/v1/ws")
}

/// A TCP forwarder in front of the real server. `cut` drops every
/// connection through it -- what a client sees when the network or the
/// server goes away mid-session.
struct CuttableLink {
    url: String,
    links: Arc<Mutex<Vec<AbortHandle>>>,
}

impl CuttableLink {
    async fn to(server_url: &str) -> Self {
        let upstream = server_url
            .trim_start_matches("ws://")
            .split('/')
            .next()
            .unwrap()
            .to_string();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let links = Arc::new(Mutex::new(Vec::new()));
        let accepted = links.clone();
        tokio::spawn(async move {
            loop {
                let (mut down, _) = listener.accept().await.unwrap();
                let upstream = upstream.clone();
                let link = tokio::spawn(async move {
                    let mut up = TcpStream::connect(&upstream).await.unwrap();
                    let _ = tokio::io::copy_bidirectional(&mut down, &mut up).await;
                });
                accepted.lock().unwrap().push(link.abort_handle());
            }
        });
        Self {
            url: format!("ws://{addr}/v1/ws"),
            links,
        }
    }

    async fn cut(&self) {
        for link in self.links.lock().unwrap().drain(..) {
            link.abort();
        }
        // Let the aborted tasks drop their sockets.
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
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
    url: String,
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
        url: url.to_string(),
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

/// Sends `content` from Alice over a connection that is cut first, then
/// retries it `failed_retries` more times on that dead connection. Returns
/// the message, still flagged.
async fn send_through_an_outage(p: &Pair, content: &[u8], failed_retries: usize) -> Message {
    let link = CuttableLink::to(&p.url).await;
    let mut conn = Connection::connect(&link.url).await.unwrap();
    conn.authenticate(&p.alice).await.unwrap();
    link.cut().await;

    let message =
        match send_message(&p.db_alice, &mut conn, &p.alice, &p.alice_contact, content).await {
            Err(Error::NotSent { message, .. }) => *message,
            other => panic!("the link is cut, so the send must fail: {other:?}"),
        };
    for attempt in 0..failed_retries {
        match retry_message(
            &p.db_alice,
            &mut conn,
            &p.alice,
            &p.alice_contact,
            &message.id,
        )
        .await
        {
            Err(Error::NotSent { message: m, .. }) => {
                assert_eq!(m.id, message.id);
                assert_eq!(
                    m.retry_reason,
                    Some(RetryReason::SendFailed),
                    "attempt {attempt}: still flagged for retry"
                );
            }
            other => panic!("attempt {attempt} on a dead connection must fail: {other:?}"),
        }
    }
    message
}

#[tokio::test]
async fn a_retry_that_keeps_failing_still_delivers_once_the_server_is_back() {
    let url = spawn_server().await;
    let mut p = paired(&url, "r3a").await;

    let message = send_through_an_outage(&p, b"through the outage", 3).await;

    // The server is reachable again (Alice's other connection never went
    // through the cut link).
    let delivered = retry_message(
        &p.db_alice,
        &mut p.alice_conn,
        &p.alice,
        &p.alice_contact,
        &message.id,
    )
    .await
    .unwrap();
    assert_eq!(delivered.retry_reason, None);

    let got = receive_pending(&p.db_bob, &mut p.bob_conn, &p.bob, &p.bob_contact)
        .await
        .unwrap();
    assert_eq!(got.messages.len(), 1, "exactly one copy arrives");
    assert_eq!(got.messages[0].content, b"through the outage");

    // The conversation carries on normally afterwards.
    send_message(
        &p.db_alice,
        &mut p.alice_conn,
        &p.alice,
        &p.alice_contact,
        b"and after",
    )
    .await
    .unwrap();
    let got = receive_pending(&p.db_bob, &mut p.bob_conn, &p.bob, &p.bob_contact)
        .await
        .unwrap();
    assert_eq!(got.messages.len(), 1);
    assert_eq!(got.messages[0].content, b"and after");
    assert_eq!(
        list_messages(&p.db_bob, &p.bob, &p.bob_contact)
            .unwrap()
            .len(),
        2
    );
}

#[tokio::test]
async fn many_failed_attempts_during_an_outage_do_not_break_the_conversation() {
    let url = spawn_server().await;
    let mut p = paired(&url, "r3b").await;

    // More failed attempts than the recipient will skip over.
    let failed = DEFAULT_MAX_SKIP as usize + 20;
    let message = send_through_an_outage(&p, b"after a long outage", failed).await;

    let delivered = retry_message(
        &p.db_alice,
        &mut p.alice_conn,
        &p.alice,
        &p.alice_contact,
        &message.id,
    )
    .await
    .unwrap();
    let got = receive_pending(&p.db_bob, &mut p.bob_conn, &p.bob, &p.bob_contact)
        .await
        .unwrap();
    assert!(
        got.messages
            .iter()
            .any(|m| m.content == b"after a long outage"),
        "VULNERABILITY: after {failed} failed attempts on a dead connection, the retry that \
         reached the server is undecryptable for the recipient -- every failed attempt used up a \
         chain position, and the gap now exceeds the recipient's skip limit ({DEFAULT_MAX_SKIP})"
    );

    // Only the first attempt -- the one that discovered the connection was
    // gone -- used a chain position.
    assert_eq!(
        delivered.send_n,
        message.send_n.map(|n| n + 1),
        "attempts on a connection already known to be lost must not use chain positions"
    );

    // And the conversation still works in both directions.
    send_message(
        &p.db_alice,
        &mut p.alice_conn,
        &p.alice,
        &p.alice_contact,
        b"still here",
    )
    .await
    .unwrap();
    let got = receive_pending(&p.db_bob, &mut p.bob_conn, &p.bob, &p.bob_contact)
        .await
        .unwrap();
    assert_eq!(got.messages.len(), 1);
    assert_eq!(got.messages[0].content, b"still here");
    send_message(
        &p.db_bob,
        &mut p.bob_conn,
        &p.bob,
        &p.bob_contact,
        b"got them",
    )
    .await
    .unwrap();
    let got = receive_pending(&p.db_alice, &mut p.alice_conn, &p.alice, &p.alice_contact)
        .await
        .unwrap();
    assert_eq!(got.messages.len(), 1);
    assert_eq!(got.messages[0].content, b"got them");
}

/// Guard: the other ratchet senders don't spend a chain position on a
/// connection that is already lost either.
#[tokio::test]
async fn other_ratchet_sends_on_a_lost_connection_use_no_chain_position() {
    let url = spawn_server().await;
    let mut p = paired(&url, "r3c").await;
    let link = CuttableLink::to(&url).await;
    let mut conn = Connection::connect(&link.url).await.unwrap();
    conn.authenticate(&p.alice).await.unwrap();
    link.cut().await;
    // Discover the loss.
    let _ = conn
        .send(FrameTag::FetchOwnPrekeyCount, &FetchOwnPrekeyCount {})
        .await;
    let _ = conn.recv_raw().await;
    assert!(conn.is_lost());

    let conv = conversation_id_for(&p.alice, &p.alice_contact);
    let before = p.db_alice.load_ratchet(conv).unwrap().unwrap().export();
    for _ in 0..3 {
        assert!(matches!(
            announce_wipe_policy(
                &p.db_alice,
                &mut conn,
                &p.alice,
                &p.alice_contact,
                true,
                false
            )
            .await,
            Err(Error::Connection(_))
        ));
        assert!(matches!(
            request_conversation_wipe(&p.db_alice, &mut conn, &p.alice, &p.alice_contact).await,
            Err(Error::Connection(_))
        ));
    }
    let after = p.db_alice.load_ratchet(conv).unwrap().unwrap().export();
    assert!(*before == *after, "the ratchet must be untouched");

    // A healthy connection is unaffected.
    send_message(
        &p.db_alice,
        &mut p.alice_conn,
        &p.alice,
        &p.alice_contact,
        b"fine",
    )
    .await
    .unwrap();
    let got = receive_pending(&p.db_bob, &mut p.bob_conn, &p.bob, &p.bob_contact)
        .await
        .unwrap();
    assert_eq!(got.messages[0].content, b"fine");
}
