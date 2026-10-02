//! `docs/adr/0001`: the client side of Server Epochs against a relay that
//! persists queued mail. A clean restart keeps the epoch, so nothing is
//! flagged; a crash starts a new one, and only messages not yet confirmed
//! Delivered are offered for Retry. Clients also wait out the relay's
//! advertised save interval for their checkmark.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use dratchet_app::{
    add_contact_by_username, generate_pairing_code, note_server_boot, open_account,
    publish_own_bundle, receive_first_contact_attempts, receive_pending, send_message,
};
use dratchet_client::net::Connection;
use dratchet_core::account::Account;
use dratchet_server::config::MailPersistence;
use dratchet_store::{Contact, Db, RetryReason};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

/// A relay with its directory and queued mail persisted, in its own
/// runtime so it can be stopped cleanly or crashed.
struct Relay {
    addr: SocketAddr,
    stop: Option<oneshot::Sender<bool>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Relay {
    fn start(addr: SocketAddr, root: PathBuf, interval: Duration) -> Self {
        let listener = std::net::TcpListener::bind(addr).unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop, stopped) = oneshot::channel::<bool>();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let mail = MailPersistence {
                    fragment_dirs: vec![root.join("f1"), root.join("f2")],
                    index_db: root.join("index.redb"),
                    key: [7; 32],
                    flush_interval: interval,
                };
                let (router, state) = dratchet_server::app_with_mail_store(
                    Some(&root.join("directory.redb")),
                    &mail,
                    1 << 24,
                )
                .unwrap();
                let listener = TcpListener::from_std(listener).unwrap();
                ready_tx.send(()).unwrap();
                let graceful = tokio::select! {
                    served = axum::serve(listener, router) => { served.unwrap(); false }
                    graceful = stopped => graceful.unwrap_or(false),
                };
                if graceful {
                    dratchet_server::flush::shutdown(&state).await;
                }
            });
            runtime.shutdown_timeout(Duration::from_secs(5));
        });
        ready_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        Relay {
            addr,
            stop: Some(stop),
            thread: Some(thread),
        }
    }

    fn url(&self) -> String {
        format!("ws://{}/v1/ws", self.addr)
    }

    fn stop(mut self, graceful: bool) -> SocketAddr {
        let _ = self.stop.take().unwrap().send(graceful);
        self.thread.take().unwrap().join().unwrap();
        self.addr
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(false);
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

async fn reconnect(url: &str, account: &Account) -> Connection {
    let mut conn = Connection::connect(url).await.unwrap();
    conn.authenticate(account).await.unwrap();
    conn
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

#[tokio::test(flavor = "multi_thread")]
async fn a_clean_restart_flags_nothing_and_a_crash_flags_only_undelivered_messages() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_path_buf();
    let relay = Relay::start("127.0.0.1:0".parse().unwrap(), root.clone(), Duration::ZERO);
    let url = relay.url();
    let mut p = paired(&url, "e1").await;
    note_server_boot(&p.db_alice, &p.alice, &p.alice_conn).unwrap();
    let conv = conversation_id_for(&p.alice, &p.alice_contact);

    // m1 is Delivered (Bob collects it and his receipt comes back).
    let alice_view = p
        .db_alice
        .load_contact(&p.alice_contact.fingerprint)
        .unwrap()
        .unwrap();
    let m1 = send_message(&p.db_alice, &mut p.alice_conn, &p.alice, &alice_view, b"m1")
        .await
        .unwrap();
    for _ in 0..2 {
        let bob_view = p
            .db_bob
            .load_contact(&p.bob_contact.fingerprint)
            .unwrap()
            .unwrap();
        receive_pending(&p.db_bob, &mut p.bob_conn, &p.bob, &bob_view)
            .await
            .unwrap();
        let alice_view = p
            .db_alice
            .load_contact(&p.alice_contact.fingerprint)
            .unwrap()
            .unwrap();
        receive_pending(&p.db_alice, &mut p.alice_conn, &p.alice, &alice_view)
            .await
            .unwrap();
    }
    assert!(
        p.db_alice
            .load_message(conv, &m1.id)
            .unwrap()
            .unwrap()
            .delivered
    );
    // m2 is only Accepted: on the relay's disk, not yet collected.
    let alice_view = p
        .db_alice
        .load_contact(&p.alice_contact.fingerprint)
        .unwrap()
        .unwrap();
    let m2 = send_message(&p.db_alice, &mut p.alice_conn, &p.alice, &alice_view, b"m2")
        .await
        .unwrap();

    // A clean restart: same epoch, nothing flagged.
    let addr = relay.stop(true);
    let relay = Relay::start(addr, root.clone(), Duration::ZERO);
    let conn = reconnect(&url, &p.alice).await;
    assert_eq!(
        note_server_boot(&p.db_alice, &p.alice, &conn).unwrap(),
        0,
        "a clean restart lost nothing, so nothing is offered for Retry"
    );

    // A crash: new epoch, only the undelivered message is flagged.
    let addr = relay.stop(false);
    let _relay = Relay::start(addr, root, Duration::ZERO);
    let conn = reconnect(&url, &p.alice).await;
    assert_eq!(note_server_boot(&p.db_alice, &p.alice, &conn).unwrap(), 1);
    assert_eq!(
        p.db_alice
            .load_message(conv, &m2.id)
            .unwrap()
            .unwrap()
            .retry_reason,
        Some(RetryReason::ServerRestarted)
    );
    assert_eq!(
        p.db_alice
            .load_message(conv, &m1.id)
            .unwrap()
            .unwrap()
            .retry_reason,
        None,
        "a Delivered message is never offered for Retry"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_client_waits_out_the_relays_save_interval_for_its_checkmark() {
    let dir = tempfile::tempdir().unwrap();
    let relay = Relay::start(
        "127.0.0.1:0".parse().unwrap(),
        dir.path().to_path_buf(),
        Duration::from_secs(4),
    );
    let db = Arc::new(temp_db());
    let account = open_account(&db).unwrap();
    let mut conn = Connection::connect(&relay.url()).await.unwrap();
    // A short timeout of its own, shorter than the relay's save interval.
    conn.set_request_timeout(Duration::from_secs(2));
    conn.authenticate(&account).await.unwrap();
    assert_eq!(
        conn.request_timeout(),
        Duration::from_secs(6),
        "the advertised save interval is added to the client's wait"
    );
    conn.send(
        dratchet_server::protocol::FrameTag::MailboxWrite,
        &dratchet_server::protocol::MailboxWrite {
            mailbox_id: vec![3; 16],
            envelope: vec![1, 2, 3],
            ttl: 3600,
        },
    )
    .await
    .unwrap();
    let (tag, ack): (_, dratchet_server::protocol::Ack) = conn.recv().await.unwrap();
    assert!(tag == dratchet_server::protocol::FrameTag::Ack && ack.ok);
}
