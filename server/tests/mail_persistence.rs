//! `docs/adr/0001`: optional relay mail persistence and Server Epochs, run
//! against a real server that is stopped cleanly or crashed and restarted
//! on the same address from the same files.

mod common;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use common::TestClient;
use dratchet_core::account::Account;
use dratchet_server::config::MailPersistence;
use dratchet_server::protocol::*;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

struct Store {
    _dir: tempfile::TempDir,
    root: PathBuf,
}

impl Store {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        Store { _dir: dir, root }
    }

    fn dirs(&self) -> Vec<PathBuf> {
        ["a", "b", "c"].iter().map(|d| self.root.join(d)).collect()
    }

    fn settings(&self, key: [u8; 32], interval: Duration) -> MailPersistence {
        MailPersistence {
            fragment_dirs: self.dirs(),
            index_db: self.root.join("index.redb"),
            key,
            flush_interval: interval,
        }
    }

    fn fragments(&self) -> Vec<PathBuf> {
        let mut out = Vec::new();
        for dir in self.dirs() {
            if let Ok(rd) = std::fs::read_dir(&dir) {
                for e in rd {
                    let path = e.unwrap().path();
                    if path.extension().is_some_and(|x| x == "frag") {
                        out.push(path);
                    }
                }
            }
        }
        out
    }
}

/// A relay with mailbox persistence, in its own runtime so it can be
/// stopped cleanly (final save) or crashed (runtime dropped mid-flight).
struct Relay {
    addr: SocketAddr,
    stop: Option<oneshot::Sender<bool>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Relay {
    fn start(addr: SocketAddr, mail: MailPersistence, memory_limit: u64) -> Self {
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
                let (router, state) =
                    dratchet_server::app_with_mail_store(None, &mail, memory_limit).unwrap();
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

    /// Stop the process: `graceful` runs the final save first; otherwise
    /// it's a crash.
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

/// Connect and authenticate, returning the client and the epoch it was
/// told (`server_boot_id`, `server_epoch`, `save_interval_ms`).
async fn connect(url: &str, account: &Account) -> (TestClient, AuthChallenge) {
    let mut client = TestClient::connect(url).await;
    let (_, challenge): (_, AuthChallenge) = client.recv().await;
    let signature = account
        .identity
        .sign_auth_challenge(&challenge.nonce)
        .unwrap();
    client
        .send(
            FrameTag::AuthResponse,
            &AuthResponse {
                identity_key: account.identity.export_public_key().unwrap(),
                signature,
            },
        )
        .await;
    let (tag, ack): (_, Ack) = client.recv().await;
    assert!(tag == FrameTag::Ack && ack.ok);
    (client, challenge)
}

async fn write(client: &mut TestClient, mailbox: [u8; 16], envelope: &[u8]) -> (FrameTag, Vec<u8>) {
    client
        .send(
            FrameTag::MailboxWrite,
            &MailboxWrite {
                mailbox_id: mailbox.to_vec(),
                envelope: envelope.to_vec(),
                ttl: 3600,
            },
        )
        .await;
    let raw = client.recv_raw().await;
    let (tag, body) = split_tag(&raw).unwrap();
    (tag, body.to_vec())
}

async fn fetch(client: &mut TestClient, mailbox: [u8; 16]) -> Vec<Vec<u8>> {
    client
        .send(
            FrameTag::MailboxFetch,
            &MailboxFetch {
                mailbox_id: mailbox.to_vec(),
            },
        )
        .await;
    let (_, entries): (_, MailboxEntries) = client.recv().await;
    entries.entries.into_iter().map(|e| e.envelope).collect()
}

fn envelope(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 + 3) as u8).collect()
}

const KEY: [u8; 32] = [0x42; 32];
const MAILBOX: [u8; 16] = [0x5a; 16];

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[tokio::test(flavor = "multi_thread")]
async fn accepted_mail_survives_a_clean_restart_in_the_same_epoch() {
    let store = Store::new();
    let alice = Account::generate().unwrap();
    let bob = Account::generate().unwrap();
    let relay = Relay::start(
        "127.0.0.1:0".parse().unwrap(),
        store.settings(KEY, Duration::from_secs(1)),
        1 << 20,
    );
    let (mut a, before) = connect(&relay.url(), &alice).await;
    assert_eq!(
        before.save_interval_ms, 1000,
        "the save interval is advertised"
    );
    let sent = envelope(300);
    let (tag, _) = write(&mut a, MAILBOX, &sent).await;
    assert_eq!(tag, FrameTag::Ack);

    // Split into one Fragment per directory, none holding the envelope.
    let fragments = store.fragments();
    assert_eq!(
        fragments.len(),
        3,
        "one Fragment in each of the three directories"
    );
    for f in &fragments {
        let bytes = std::fs::read(f).unwrap();
        assert!(
            !contains(&bytes, &sent[..32]),
            "Fragments hold only sealed bytes"
        );
    }

    let addr = relay.stop(true);
    let relay = Relay::start(addr, store.settings(KEY, Duration::from_secs(1)), 1 << 20);
    let (mut b, after) = connect(&relay.url(), &bob).await;
    assert_eq!(
        after.server_boot_id, before.server_boot_id,
        "a clean shutdown that finished its last save keeps the epoch"
    );
    assert_eq!(fetch(&mut b, MAILBOX).await, vec![sent]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_crash_starts_a_new_epoch_but_keeps_what_was_accepted() {
    let store = Store::new();
    let alice = Account::generate().unwrap();
    let bob = Account::generate().unwrap();
    let relay = Relay::start(
        "127.0.0.1:0".parse().unwrap(),
        store.settings(KEY, Duration::from_secs(1)),
        1 << 20,
    );
    let (mut a, before) = connect(&relay.url(), &alice).await;
    let sent = envelope(200);
    let started = Instant::now();
    assert_eq!(write(&mut a, MAILBOX, &sent).await.0, FrameTag::Ack);
    assert!(
        started.elapsed() >= Duration::from_millis(100),
        "the checkmark waits for a save"
    );

    let addr = relay.stop(false);
    let relay = Relay::start(addr, store.settings(KEY, Duration::from_secs(1)), 1 << 20);
    let (mut b, after) = connect(&relay.url(), &bob).await;
    assert_ne!(
        after.server_boot_id, before.server_boot_id,
        "a run that ended without its final save starts a new epoch"
    );
    assert_eq!(after.server_epoch, before.server_epoch + 1);
    assert_eq!(
        fetch(&mut b, MAILBOX).await,
        vec![sent],
        "anything acknowledged was already on disk"
    );
}

async fn damaged_store_case(damage: impl FnOnce(&Store)) {
    let store = Store::new();
    let alice = Account::generate().unwrap();
    let bob = Account::generate().unwrap();
    let relay = Relay::start(
        "127.0.0.1:0".parse().unwrap(),
        store.settings(KEY, Duration::from_secs(1)),
        1 << 20,
    );
    let (mut a, before) = connect(&relay.url(), &alice).await;
    assert_eq!(
        write(&mut a, MAILBOX, &envelope(200)).await.0,
        FrameTag::Ack
    );
    let addr = relay.stop(true);

    damage(&store);

    let relay = Relay::start(addr, store.settings(KEY, Duration::from_secs(1)), 1 << 20);
    let (mut b, after) = connect(&relay.url(), &bob).await;
    assert_ne!(
        after.server_boot_id, before.server_boot_id,
        "mail that couldn't be rebuilt was lost, so the epoch advances"
    );
    assert!(
        fetch(&mut b, MAILBOX).await.is_empty(),
        "the damaged entry is dropped"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_missing_fragment_drops_the_entry_and_advances_the_epoch() {
    damaged_store_case(|store| {
        let f = store
            .fragments()
            .into_iter()
            .find(|p| p.starts_with(store.root.join("b")));
        std::fs::remove_file(f.unwrap()).unwrap();
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_corrupted_fragment_fails_its_checksum_and_advances_the_epoch() {
    damaged_store_case(|store| {
        let f = store.fragments().into_iter().next().unwrap();
        let mut bytes = std::fs::read(&f).unwrap();
        bytes[0] ^= 0xff;
        std::fs::write(&f, bytes).unwrap();
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_different_key_discards_the_store_and_advances_the_epoch() {
    let store = Store::new();
    let alice = Account::generate().unwrap();
    let bob = Account::generate().unwrap();
    let relay = Relay::start(
        "127.0.0.1:0".parse().unwrap(),
        store.settings(KEY, Duration::from_secs(1)),
        1 << 20,
    );
    let (mut a, before) = connect(&relay.url(), &alice).await;
    assert_eq!(
        write(&mut a, MAILBOX, &envelope(200)).await.0,
        FrameTag::Ack
    );
    let addr = relay.stop(true);

    let relay = Relay::start(
        addr,
        store.settings([0x17; 32], Duration::from_secs(1)),
        1 << 20,
    );
    let (mut b, after) = connect(&relay.url(), &bob).await;
    assert_ne!(after.server_boot_id, before.server_boot_id);
    assert!(fetch(&mut b, MAILBOX).await.is_empty());
    assert!(
        store.fragments().is_empty(),
        "the unreadable store's Fragments are removed"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn memory_at_half_its_limit_saves_without_waiting_for_the_interval() {
    let store = Store::new();
    let alice = Account::generate().unwrap();
    let relay = Relay::start(
        "127.0.0.1:0".parse().unwrap(),
        store.settings(KEY, Duration::from_secs(15)),
        1000,
    );
    let (mut a, _) = connect(&relay.url(), &alice).await;
    let started = Instant::now();
    assert_eq!(
        write(&mut a, MAILBOX, &envelope(600)).await.0,
        FrameTag::Ack
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "over half the memory area triggers an immediate save, not the 15 s one"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_full_memory_area_refuses_without_saying_why() {
    let store = Store::new();
    let alice = Account::generate().unwrap();
    let relay = Relay::start(
        "127.0.0.1:0".parse().unwrap(),
        store.settings(KEY, Duration::from_secs(1)),
        1000,
    );
    let (mut a, _) = connect(&relay.url(), &alice).await;
    let (tag, body) = write(&mut a, MAILBOX, &envelope(1100)).await;
    assert_eq!(tag, FrameTag::Error);
    let err: ErrorFrame = decode_body(&body).unwrap();
    assert_eq!(err.code, ErrorCode::Unspecified);
    let message = err.message.to_lowercase();
    assert!(
        !message.contains("memory") && !message.contains("full") && !message.contains("limit"),
        "the refusal must not describe the relay's state, got {:?}",
        err.message
    );
}

/// A fragment directory the store didn't create, already holding other
/// files, must be left alone: an operator who points `fragment_dirs` at
/// the wrong (shared) directory gets an error, not changed permissions and
/// deleted files.
#[cfg(unix)]
#[test]
fn a_store_never_takes_over_a_directory_it_did_not_create() {
    use std::os::unix::fs::PermissionsExt;
    let store = Store::new();
    let shared = store.root.join("shared");
    std::fs::create_dir_all(&shared).unwrap();
    std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o755)).unwrap();
    let someone_elses = shared.join("report.frag");
    std::fs::write(&someone_elses, b"not the relay's").unwrap();

    let mut mail = store.settings(KEY, Duration::from_secs(1));
    mail.fragment_dirs = vec![store.root.join("a"), shared.clone()];
    let opened =
        dratchet_server::mailstore::MailStore::open(&mail.index_db, &mail.fragment_dirs, &KEY);

    let mode = std::fs::metadata(&shared).unwrap().permissions().mode() & 0o777;
    assert!(
        someone_elses.exists() && mode == 0o755,
        "VULNERABILITY: opening the mail store changed a directory it didn't create (mode now \
         {mode:o}) or deleted a file in it (still there: {})",
        someone_elses.exists()
    );
    assert!(
        opened.is_err(),
        "the store refuses a directory that isn't its own"
    );
}

/// Guard: a directory the store created (or adopted while empty) keeps
/// working across restarts.
#[test]
fn the_store_reopens_directories_it_created() {
    let store = Store::new();
    let mail = store.settings(KEY, Duration::from_secs(1));
    for _ in 0..2 {
        let opened =
            dratchet_server::mailstore::MailStore::open(&mail.index_db, &mail.fragment_dirs, &KEY);
        assert!(opened.is_ok(), "{:?}", opened.err());
    }
    let empty = store.root.join("empty-existing");
    std::fs::create_dir_all(&empty).unwrap();
    let mut adopt = store.settings(KEY, Duration::from_secs(1));
    adopt.fragment_dirs = vec![store.root.join("a"), empty];
    adopt.index_db = store.root.join("index2.redb");
    assert!(dratchet_server::mailstore::MailStore::open(
        &adopt.index_db,
        &adopt.fragment_dirs,
        &KEY
    )
    .is_ok());
}

fn pending(entry_id: u8) -> dratchet_server::mailstore::PendingEntry {
    dratchet_server::mailstore::PendingEntry {
        mailbox_id: MAILBOX,
        entry_id: [entry_id; 16],
        envelope: envelope(300),
        expires_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600,
        written_by: [0x11; 32],
    }
}

#[cfg(unix)]
#[test]
fn one_directory_named_twice_is_refused_rather_than_losing_every_entry() {
    use dratchet_server::mailstore::MailStore;
    let store = Store::new();
    let real = store.root.join("a");
    std::fs::create_dir_all(&real).unwrap();
    let alias = store.root.join("alias");
    std::os::unix::fs::symlink(&real, &alias).unwrap();
    let mut mail = store.settings(KEY, Duration::from_secs(1));
    mail.fragment_dirs = vec![real.clone(), alias];

    let first = MailStore::open(&mail.index_db, &mail.fragment_dirs, &KEY);
    if let Ok(opened) = first {
        opened.store.save(&[pending(1)]).unwrap();
        opened.store.mark_clean_shutdown().unwrap();
        drop(opened);
        let reopened = MailStore::open(&mail.index_db, &mail.fragment_dirs, &KEY).unwrap();
        let readable = matches!(reopened.store.read_envelope(&[1; 16]), Ok(Some(_)));
        panic!(
            "VULNERABILITY: two names for one fragment directory were accepted; after a clean \
             restart the saved entry is {}",
            if readable {
                "still readable"
            } else {
                "gone (its other Fragment was swept as an orphan)"
            }
        );
    }
    assert!(
        first_err_mentions_same_directory(&mail),
        "the store names the aliased directories"
    );
}

fn first_err_mentions_same_directory(mail: &MailPersistence) -> bool {
    dratchet_server::mailstore::MailStore::open(&mail.index_db, &mail.fragment_dirs, &KEY)
        .err()
        .is_some_and(|e| e.to_string().contains("are the same directory"))
}
