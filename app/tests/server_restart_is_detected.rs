//! DRA-0064: a server restart silently lost every queued message.
//!
//! Mailboxes live only in the server's memory (audit scenario 9). A
//! restart, redeploy or crash dropped every message waiting to be
//! collected, for every user at once, and told nobody: senders kept
//! seeing "sent", recipients never got them.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use dratchet_app::{
    add_contact_by_username, generate_pairing_code, list_messages, note_server_boot, open_account,
    publish_own_bundle, receive_first_contact_attempts, receive_pending, retry_message,
    send_message, Error,
};
use dratchet_client::net::Connection;
use dratchet_core::account::Account;
use dratchet_server::protocol::{BundleResult, FetchBundle, FrameTag};
use dratchet_store::{Contact, Db, RetryReason};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

async fn spawn_server() -> String {
    let (router, _state) = dratchet_server::app();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    format!("ws://{addr}/v1/ws")
}

/// A server running the way `dratchetd` does -- its directory persisted to
/// a file -- in its own runtime on its own thread, so it can be crashed:
/// `crash` drops the runtime, which closes every connection and loses
/// everything held only in memory (the mailboxes), as a killed process
/// would. Restarting it on the same address from the same file is a real
/// restart as far as clients can tell.
struct ServerProcess {
    addr: SocketAddr,
    stop: Option<oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl ServerProcess {
    fn start(addr: SocketAddr, directory: &Path) -> Self {
        let listener = std::net::TcpListener::bind(addr).unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let directory: PathBuf = directory.to_path_buf();
        let (stop, stopped) = oneshot::channel::<()>();
        let thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let (router, _state) = dratchet_server::app_with_directory_db(&directory).unwrap();
                let listener = TcpListener::from_std(listener).unwrap();
                tokio::select! {
                    served = axum::serve(listener, router) => served.unwrap(),
                    _ = stopped => {}
                }
            });
            runtime.shutdown_timeout(Duration::from_secs(5));
        });
        Self {
            addr,
            stop: Some(stop),
            thread: Some(thread),
        }
    }

    fn url(&self) -> String {
        format!("ws://{}/v1/ws", self.addr)
    }

    /// Kill the process and start it again on the same address from the
    /// same directory file.
    fn crash_and_restart(mut self, directory: &Path) -> Self {
        let _ = self.stop.take().unwrap().send(());
        self.thread.take().unwrap().join().unwrap();
        Self::start(self.addr, directory)
    }
}

impl Drop for ServerProcess {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
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

/// Gap closed after DRA-0064: the tests above stand a fresh server in for
/// the restarted one. Here the same server, with its directory persisted
/// as `dratchetd` keeps it, is crashed and restarted on the same address;
/// the sender's existing connection dies, it reconnects to the same URL,
/// and the retry is delivered.
#[tokio::test]
async fn a_crashed_and_restarted_server_is_detected_and_the_retry_is_delivered() {
    let dir = tempfile::tempdir().unwrap();
    let directory = dir.path().join("directory.redb");
    let server = ServerProcess::start("127.0.0.1:0".parse().unwrap(), &directory);
    let url = server.url();
    let mut p = paired(&url, "64c").await;
    note_server_boot(&p.db_alice, &p.alice, &p.alice_conn).unwrap();
    note_server_boot(&p.db_bob, &p.bob, &p.bob_conn).unwrap();
    let conv = conversation_id_for(&p.alice, &p.alice_contact);

    let sent = send_message(
        &p.db_alice,
        &mut p.alice_conn,
        &p.alice,
        &p.alice_contact,
        b"queued when it crashed",
    )
    .await
    .unwrap();

    let _server = server.crash_and_restart(&directory);

    // Both clients' connections died with the old process.
    let died = receive_pending(&p.db_alice, &mut p.alice_conn, &p.alice, &p.alice_contact).await;
    assert!(
        matches!(died, Err(Error::Connection(_))),
        "got {:?}",
        died.err()
    );
    assert!(p.alice_conn.is_lost());

    // Alice reconnects to the same address, as the desktop app does.
    let mut alice_conn = Connection::connect(&url).await.unwrap();
    alice_conn.authenticate(&p.alice).await.unwrap();
    assert_eq!(
        note_server_boot(&p.db_alice, &p.alice, &alice_conn).unwrap(),
        1,
        "the restart is detected and the queued message flagged"
    );
    assert_eq!(
        p.db_alice
            .load_message(conv, &sent.id)
            .unwrap()
            .unwrap()
            .retry_reason,
        Some(RetryReason::ServerRestarted)
    );
    let mut bob_conn = Connection::connect(&url).await.unwrap();
    bob_conn.authenticate(&p.bob).await.unwrap();
    // Bob had nothing unconfirmed, so nothing of his is flagged.
    assert_eq!(note_server_boot(&p.db_bob, &p.bob, &bob_conn).unwrap(), 0);

    // It really is the same server restarted: the persisted directory
    // still resolves Alice's handle to her identity...
    let alice_profile = p.db_alice.load_own_profile().unwrap().unwrap();
    bob_conn
        .send(
            FrameTag::FetchBundle,
            &FetchBundle {
                username: alice_profile.username.clone(),
                discriminator: alice_profile.discriminator,
            },
        )
        .await
        .unwrap();
    let (_, result): (_, BundleResult) = bob_conn.recv().await.unwrap();
    let bundle = result.bundle.expect("the directory still has Alice");
    assert_eq!(
        bundle.identity_key,
        p.alice.identity.export_public_key().unwrap()
    );
    // ...while the queued message was lost with the old process.
    let got = receive_pending(&p.db_bob, &mut bob_conn, &p.bob, &p.bob_contact)
        .await
        .unwrap();
    assert!(
        got.messages.is_empty(),
        "the mailbox did not survive the crash"
    );

    let retried = retry_message(
        &p.db_alice,
        &mut alice_conn,
        &p.alice,
        &p.alice_contact,
        &sent.id,
    )
    .await
    .unwrap();
    assert_eq!(retried.retry_reason, None);

    let got = receive_pending(&p.db_bob, &mut bob_conn, &p.bob, &p.bob_contact)
        .await
        .unwrap();
    assert_eq!(got.messages.len(), 1);
    assert_eq!(got.messages[0].content, b"queued when it crashed");

    // Bob's receipt comes back through the restarted server.
    receive_pending(&p.db_alice, &mut alice_conn, &p.alice, &p.alice_contact)
        .await
        .unwrap();
    assert!(
        p.db_alice
            .load_message(conv, &sent.id)
            .unwrap()
            .unwrap()
            .delivered
    );
}

/// The other side of a restart: Bob collected the message just before the
/// crash, but his delivery receipt was still queued for Alice and was lost
/// with it. Alice's copy is flagged; retrying it is harmless -- Bob drops
/// the duplicate and acknowledges it, which clears Alice's flag.
#[tokio::test]
async fn a_message_collected_just_before_the_crash_is_not_shown_twice_after_a_retry() {
    let dir = tempfile::tempdir().unwrap();
    let directory = dir.path().join("directory.redb");
    let server = ServerProcess::start("127.0.0.1:0".parse().unwrap(), &directory);
    let url = server.url();
    let mut p = paired(&url, "64d").await;
    note_server_boot(&p.db_alice, &p.alice, &p.alice_conn).unwrap();
    let conv = conversation_id_for(&p.alice, &p.alice_contact);

    let sent = send_message(
        &p.db_alice,
        &mut p.alice_conn,
        &p.alice,
        &p.alice_contact,
        b"collected, receipt lost",
    )
    .await
    .unwrap();
    let got = receive_pending(&p.db_bob, &mut p.bob_conn, &p.bob, &p.bob_contact)
        .await
        .unwrap();
    assert_eq!(got.messages.len(), 1);

    let _server = server.crash_and_restart(&directory);

    let mut alice_conn = Connection::connect(&url).await.unwrap();
    alice_conn.authenticate(&p.alice).await.unwrap();
    assert_eq!(
        note_server_boot(&p.db_alice, &p.alice, &alice_conn).unwrap(),
        1
    );
    retry_message(
        &p.db_alice,
        &mut alice_conn,
        &p.alice,
        &p.alice_contact,
        &sent.id,
    )
    .await
    .unwrap();

    let mut bob_conn = Connection::connect(&url).await.unwrap();
    bob_conn.authenticate(&p.bob).await.unwrap();
    let got = receive_pending(&p.db_bob, &mut bob_conn, &p.bob, &p.bob_contact)
        .await
        .unwrap();
    assert!(
        got.messages.is_empty(),
        "the resend is recognised and not shown"
    );
    assert_eq!(
        list_messages(&p.db_bob, &p.bob, &p.bob_contact)
            .unwrap()
            .len(),
        1
    );

    receive_pending(&p.db_alice, &mut alice_conn, &p.alice, &p.alice_contact)
        .await
        .unwrap();
    let alice_copy = p.db_alice.load_message(conv, &sent.id).unwrap().unwrap();
    assert!(alice_copy.delivered);
    assert_eq!(alice_copy.retry_reason, None);
}
