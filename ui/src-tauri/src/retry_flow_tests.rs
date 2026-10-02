//! The desktop layer of the retry flows (DRA-0060..0065), run for real:
//! the Tauri commands are invoked through IPC exactly as `+page.svelte`
//! invokes them (argument names included), and `poll_loop` runs as it does
//! in the app, on `tauri::test`'s mock runtime instead of a window system.
//! Everything talks to a real `dratchet_server`.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use dratchet_app::{
    add_contact_by_username, generate_pairing_code, note_server_boot, publish_own_bundle,
    receive_first_contact_attempts, receive_pending, EXPIRY_GRACE_SECS, MAILBOX_TTL_SECS,
};
use dratchet_store::RetryReason;
use serde_json::{json, Value};
use tauri::ipc::{CallbackFn, InvokeBody};
use tauri::test::{
    get_ipc_response, mock_builder, mock_context, noop_assets, MockRuntime, INVOKE_KEY,
};
use tauri::webview::InvokeRequest;
use tauri::{Listener, WebviewWindow, WebviewWindowBuilder};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

use super::*;

/// Commands and `poll_loop` run on Tauri's own async runtime, so the
/// servers and connections the tests set up live there too.
fn on_runtime<F: std::future::Future>(future: F) -> F::Output {
    tauri::async_runtime::block_on(future)
}

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

/// Alice (whose side the desktop app runs) paired with Bob (driven
/// directly through `dratchet_app`).
struct Pair {
    alice_db: Db,
    alice: Account,
    alice_conn: Connection,
    alice_contact: Contact,
    bob_db: Db,
    bob: Account,
    bob_conn: Connection,
    bob_contact: Contact,
}

async fn paired(url: &str, tag: &str) -> Pair {
    let alice_db = temp_db();
    let mut alice = open_account(&alice_db).unwrap();
    let mut alice_conn = Connection::connect(url).await.unwrap();
    alice_conn.authenticate(&alice).await.unwrap();
    let alice_profile = publish_own_bundle(
        &alice_db,
        &mut alice_conn,
        &mut alice,
        &format!("alice{tag}"),
    )
    .await
    .unwrap();
    let bob_db = temp_db();
    let mut bob = open_account(&bob_db).unwrap();
    let mut bob_conn = Connection::connect(url).await.unwrap();
    bob_conn.authenticate(&bob).await.unwrap();
    let bob_profile = publish_own_bundle(&bob_db, &mut bob_conn, &mut bob, &format!("bob{tag}"))
        .await
        .unwrap();
    let code = generate_pairing_code(&bob_db).unwrap().code;
    let alice_contact = add_contact_by_username(
        &alice_db,
        &mut alice_conn,
        &alice,
        &alice_profile,
        &bob_profile.username,
        bob_profile.discriminator,
        &code,
    )
    .await
    .unwrap();
    let bob_contact = receive_first_contact_attempts(&bob_db, &mut bob_conn, &mut bob)
        .await
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    Pair {
        alice_db,
        alice,
        alice_conn,
        alice_contact,
        bob_db,
        bob,
        bob_conn,
        bob_contact,
    }
}

fn app_state(db: Db, account: Account, conn: Option<Connection>, server_url: &str) -> AppState {
    let status = if conn.is_some() {
        ConnectionStatusDto::Connected
    } else {
        ConnectionStatusDto::Reconnecting
    };
    AppState {
        db,
        db_path: PathBuf::new(),
        server_url: server_url.to_string(),
        account: Arc::new(Mutex::new(account)),
        conn: Arc::new(Mutex::new(conn)),
        own_discriminator_change_notice: StdMutex::new(None),
        peer_profile_change_notices: StdMutex::new(Vec::new()),
        connection_status: StdMutex::new(status),
    }
}

fn desktop_app(state: AppState) -> (tauri::App<MockRuntime>, WebviewWindow<MockRuntime>) {
    let app = mock_builder()
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            list_messages,
            send_message,
            retry_message
        ])
        .build(mock_context(noop_assets()))
        .unwrap();
    let webview = WebviewWindowBuilder::new(&app, "main", Default::default())
        .build()
        .unwrap();
    (app, webview)
}

/// Invoke a command the way the frontend does.
fn invoke(webview: &WebviewWindow<MockRuntime>, cmd: &str, args: Value) -> Result<Value, Value> {
    get_ipc_response(
        webview,
        InvokeRequest {
            cmd: cmd.into(),
            callback: CallbackFn(0),
            error: CallbackFn(1),
            url: "tauri://localhost".parse().unwrap(),
            body: InvokeBody::Json(args),
            headers: Default::default(),
            invoke_key: INVOKE_KEY.to_string(),
        },
    )
    .map(|body| body.deserialize::<Value>().unwrap())
}

fn conversation(state: &AppState, contact: &Contact) -> [u8; 16] {
    let account = on_runtime(state.account.lock());
    dratchet_core::conversation_id(
        account.identity.fingerprint().as_bytes(),
        &contact.fingerprint,
    )
}

/// Connect `state` to `url` the way `poll_loop` does.
fn connect_now(state: &AppState, url: &str) {
    on_runtime(async {
        let mut account = state.account.lock().await;
        let (conn, _) = connect_authenticate_and_reconcile(url, &state.db, &mut account)
            .await
            .unwrap();
        *state.conn.lock().await = Some(conn);
    });
}

/// Wait up to `limit` for `done`, checking every 100ms.
fn wait_until(limit: Duration, mut done: impl FnMut() -> bool) -> bool {
    let deadline = std::time::Instant::now() + limit;
    while std::time::Instant::now() < deadline {
        if done() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    done()
}

/// A TCP forwarder in front of a real server; `cut` drops every connection
/// through it, as a network or server failure mid-session would.
struct CuttableLink {
    url: String,
    links: Arc<StdMutex<Vec<tokio::task::AbortHandle>>>,
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
        let links = Arc::new(StdMutex::new(Vec::new()));
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
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// A server run the way `dratchetd` runs (directory persisted), in its own
/// runtime on its own thread so it can be crashed and restarted on the
/// same address -- see `app/tests/server_restart_is_detected.rs`.
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
        let directory = directory.to_path_buf();
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

/// Offline: Send keeps the message (flagged), Retry says "not connected"
/// and changes nothing, and once connected Retry delivers it.
#[test]
fn a_message_sent_offline_is_kept_and_the_retry_command_delivers_it() {
    let (url, p) = on_runtime(async {
        let url = spawn_server().await;
        let p = paired(&url, "u1").await;
        (url, p)
    });
    let Pair {
        alice_db,
        alice,
        alice_contact,
        bob_db,
        bob,
        mut bob_conn,
        bob_contact,
        ..
    } = p;
    let fingerprint = hex::encode(&alice_contact.fingerprint);
    let (app, webview) = desktop_app(app_state(alice_db, alice, None, &url));

    let sent = invoke(
        &webview,
        "send_message",
        json!({ "fingerprint": fingerprint, "content": "written offline" }),
    )
    .expect("an offline send is kept, not refused");
    assert_eq!(sent["content"], "written offline");
    assert_eq!(sent["retry_reason"], "send_failed");

    let still_offline = invoke(
        &webview,
        "retry_message",
        json!({ "fingerprint": fingerprint, "messageId": sent["id"] }),
    );
    assert_eq!(still_offline, Err(json!(NOT_CONNECTED)));

    connect_now(&app.state::<AppState>(), &url);
    let retried = invoke(
        &webview,
        "retry_message",
        json!({ "fingerprint": fingerprint, "messageId": sent["id"] }),
    )
    .unwrap();
    assert_eq!(retried["id"], sent["id"]);
    assert_eq!(retried["retry_reason"], Value::Null);

    let got = on_runtime(receive_pending(&bob_db, &mut bob_conn, &bob, &bob_contact)).unwrap();
    assert_eq!(got.messages.len(), 1);
    assert_eq!(got.messages[0].content, b"written offline");

    let listed = invoke(
        &webview,
        "list_messages",
        json!({ "fingerprint": fingerprint }),
    )
    .unwrap();
    let messages = listed["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 1, "one message, updated in place");
    assert_eq!(messages[0]["retry_reason"], Value::Null);
}

/// The connection dies mid-session: Send and Retry return the message
/// flagged (not an error), attempts on the dead connection use no further
/// chain positions (DRA-0065), and Retry delivers once reconnected.
#[test]
fn a_send_that_fails_mid_flight_comes_back_flagged_and_is_delivered_on_retry() {
    let (url, link, p) = on_runtime(async {
        let url = spawn_server().await;
        let p = paired(&url, "u2").await;
        let link = CuttableLink::to(&url).await;
        (url, link, p)
    });
    let Pair {
        alice_db,
        alice,
        alice_contact,
        bob_db,
        bob,
        mut bob_conn,
        bob_contact,
        ..
    } = p;
    let doomed = on_runtime(async {
        let mut conn = Connection::connect(&link.url).await.unwrap();
        conn.authenticate(&alice).await.unwrap();
        conn
    });
    let fingerprint = hex::encode(&alice_contact.fingerprint);
    let (app, webview) = desktop_app(app_state(alice_db, alice, Some(doomed), &url));
    let state = app.state::<AppState>();
    let conv = conversation(&state, &alice_contact);
    on_runtime(link.cut());

    let sent = invoke(
        &webview,
        "send_message",
        json!({ "fingerprint": fingerprint, "content": "mid-flight" }),
    )
    .expect("a failed send comes back as the saved message, not an error");
    assert_eq!(sent["retry_reason"], "send_failed");
    let id = hex::decode(sent["id"].as_str().unwrap()).unwrap();
    let first_n = state.db.load_message(conv, &id).unwrap().unwrap().send_n;

    for _ in 0..3 {
        let again = invoke(
            &webview,
            "retry_message",
            json!({ "fingerprint": fingerprint, "messageId": sent["id"] }),
        )
        .expect("a failed retry comes back as the message, still flagged");
        assert_eq!(again["retry_reason"], "send_failed");
    }

    connect_now(&state, &url);
    let retried = invoke(
        &webview,
        "retry_message",
        json!({ "fingerprint": fingerprint, "messageId": sent["id"] }),
    )
    .unwrap();
    assert_eq!(retried["retry_reason"], Value::Null);
    assert_eq!(
        state.db.load_message(conv, &id).unwrap().unwrap().send_n,
        first_n.map(|n| n + 1),
        "only the attempt that found the connection dead used a chain position"
    );

    let got = on_runtime(receive_pending(&bob_db, &mut bob_conn, &bob, &bob_contact)).unwrap();
    assert_eq!(got.messages.len(), 1);
    assert_eq!(got.messages[0].content, b"mid-flight");
}

/// DRA-0063 in the app: the background loop flags a message past the
/// mailbox lifetime -- while offline -- tells the frontend, and the list
/// shows it as expired; Retry then delivers it.
#[test]
fn the_poll_loop_flags_an_expired_send_and_tells_the_frontend() {
    let (url, p) = on_runtime(async {
        let url = spawn_server().await;
        let p = paired(&url, "u3").await;
        (url, p)
    });
    let Pair {
        alice_db,
        alice,
        mut alice_conn,
        alice_contact,
        bob_db,
        bob,
        mut bob_conn,
        bob_contact,
    } = p;
    // Sent for real, never collected; then backdated past the lifetime.
    let mut sent = on_runtime(dratchet_app::send_message(
        &alice_db,
        &mut alice_conn,
        &alice,
        &alice_contact,
        b"nobody collected this",
    ))
    .unwrap();
    let conv = dratchet_core::conversation_id(
        alice.identity.fingerprint().as_bytes(),
        &alice_contact.fingerprint,
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    sent.last_sent_at = Some(now - u64::from(MAILBOX_TTL_SECS) - EXPIRY_GRACE_SECS - 60);
    alice_db.save_message(conv, &sent).unwrap();
    drop(alice_conn);

    // Offline: the loop can't reach anything, and checks anyway.
    let (app, webview) = desktop_app(app_state(alice_db, alice, None, "ws://127.0.0.1:1/v1/ws"));
    let (tx, inbox_updated) = mpsc::channel();
    app.listen_any(INBOX_UPDATED_EVENT, move |_| {
        let _ = tx.send(());
    });
    tauri::async_runtime::spawn(poll_loop(app.handle().clone()));

    inbox_updated
        .recv_timeout(Duration::from_secs(10))
        .expect("the loop tells the frontend something changed");
    let state = app.state::<AppState>();
    assert_eq!(
        state
            .db
            .load_message(conv, &sent.id)
            .unwrap()
            .unwrap()
            .retry_reason,
        Some(RetryReason::Expired)
    );
    let fingerprint = hex::encode(&alice_contact.fingerprint);
    let listed = invoke(
        &webview,
        "list_messages",
        json!({ "fingerprint": fingerprint }),
    )
    .unwrap();
    assert_eq!(listed["messages"][0]["retry_reason"], "expired");

    connect_now(&state, &url);
    let retried = invoke(
        &webview,
        "retry_message",
        json!({ "fingerprint": fingerprint, "messageId": hex::encode(&sent.id) }),
    )
    .unwrap();
    assert_eq!(retried["retry_reason"], Value::Null);
    // The test server never really discarded the original, so Bob has two
    // envelopes for it; he shows one.
    let got = on_runtime(receive_pending(&bob_db, &mut bob_conn, &bob, &bob_contact)).unwrap();
    assert_eq!(got.messages.len(), 1);
    assert_eq!(got.messages[0].content, b"nobody collected this");
}

/// DRA-0064 in the app: the server crashes and restarts on the same
/// address; the background loop notices the dead connection, reconnects,
/// detects the restart and flags the lost message; Retry delivers it.
#[test]
fn the_poll_loop_detects_a_server_restart_and_retry_delivers_the_lost_message() {
    let dir = tempfile::tempdir().unwrap();
    let directory = dir.path().join("directory.redb");
    let server = ServerProcess::start("127.0.0.1:0".parse().unwrap(), &directory);
    let url = server.url();
    let p = on_runtime(paired(&url, "u4"));
    let Pair {
        alice_db,
        alice,
        alice_conn,
        alice_contact,
        bob_db,
        bob,
        bob_contact,
        ..
    } = p;
    // As at startup: the boot id of the server the app connected to.
    note_server_boot(&alice_db, &alice, &alice_conn).unwrap();
    let fingerprint = hex::encode(&alice_contact.fingerprint);
    let (app, webview) = desktop_app(app_state(alice_db, alice, Some(alice_conn), &url));
    let state = app.state::<AppState>();
    let conv = conversation(&state, &alice_contact);

    let sent = invoke(
        &webview,
        "send_message",
        json!({ "fingerprint": fingerprint, "content": "queued when it crashed" }),
    )
    .unwrap();
    assert_eq!(sent["retry_reason"], Value::Null, "the server accepted it");
    let id = hex::decode(sent["id"].as_str().unwrap()).unwrap();

    tauri::async_runtime::spawn(poll_loop(app.handle().clone()));
    std::thread::sleep(Duration::from_millis(500));
    let _server = server.crash_and_restart(&directory);

    let reconnected = wait_until(Duration::from_secs(20), || {
        let flagged = state
            .db
            .load_message(conv, &id)
            .unwrap()
            .unwrap()
            .retry_reason
            == Some(RetryReason::ServerRestarted);
        let connected = *state.connection_status.lock().unwrap() == ConnectionStatusDto::Connected;
        flagged && connected
    });
    assert!(
        reconnected,
        "the loop reconnects and flags the message the restart lost"
    );
    let after = state.db.load_message(conv, &id).unwrap().unwrap();
    assert!(
        !after.uncertain,
        "flagged for retry, not also shown as merely uncertain"
    );

    let listed = invoke(
        &webview,
        "list_messages",
        json!({ "fingerprint": fingerprint }),
    )
    .unwrap();
    assert_eq!(listed["messages"][0]["retry_reason"], "server_restarted");
    let retried = invoke(
        &webview,
        "retry_message",
        json!({ "fingerprint": fingerprint, "messageId": sent["id"] }),
    )
    .unwrap();
    assert_eq!(retried["retry_reason"], Value::Null);

    // Bob reads the way the app's loop does: his current contact record
    // each pass, a few passes (a pass that switches mailboxes reads the
    // new one on the next).
    let got = on_runtime(async {
        let mut bob_conn = Connection::connect(&url).await.unwrap();
        bob_conn.authenticate(&bob).await.unwrap();
        let mut got = Vec::new();
        for _ in 0..3 {
            let current = bob_db
                .load_contact(&bob_contact.fingerprint)
                .unwrap()
                .unwrap();
            let received = receive_pending(&bob_db, &mut bob_conn, &bob, &current)
                .await
                .unwrap();
            got.extend(received.messages.into_iter().map(|m| m.content));
        }
        got
    });
    assert_eq!(got, vec![b"queued when it crashed".to_vec()]);
}
