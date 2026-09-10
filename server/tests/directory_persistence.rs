//! Real end-to-end proof of `server/src/persistence.rs`: the directory
//! must survive a real process restart, not just an in-memory-state
//! reset. "Restart" here means dropping the whole `axum::serve` task and
//! `Arc<AppState>` and building a genuinely fresh one from the same
//! on-disk file via `dratchet_server::app_with_directory_db` — as close
//! to a real `dratchetd` restart as an in-process test can get. No
//! mocks, matching this project's standing rule.

mod common;

use common::*;
use dratchet_server::protocol::*;
use tokio::net::TcpListener;

/// Returns the URL plus the task's `JoinHandle` — a real `redb::Database`
/// holds an exclusive file lock for as long as anything keeps its
/// `AppState` alive, which includes the spawned `axum::serve` task even
/// after every local variable referencing it is dropped. Simulating a
/// restart against the *same* file therefore requires `.abort()`ing that
/// task first, not just letting local variables go out of scope.
async fn spawn_server_at(directory_db: &std::path::Path) -> (String, tokio::task::JoinHandle<()>) {
    let (router, _state) =
        dratchet_server::app_with_directory_db(directory_db).expect("open the directory db");
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, router).await.expect("server task");
    });
    (format!("ws://{addr}/v1/ws"), handle)
}

/// Like `spawn_server_at`, but for reopening a file a just-aborted
/// server held: `handle.abort().await` guarantees the task future (and
/// the `Arc<AppState>`/`redb::Database` it owned) has been dropped, but
/// redb's underlying OS file lock has been observed to take a little
/// longer than that to actually release — so retry briefly rather than
/// either racing on a bare reopen or padding every restart test with an
/// arbitrary fixed sleep.
async fn spawn_server_at_after_restart(
    directory_db: &std::path::Path,
) -> (String, tokio::task::JoinHandle<()>) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        match dratchet_server::app_with_directory_db(directory_db) {
            Ok((router, _state)) => {
                let listener = TcpListener::bind("127.0.0.1:0")
                    .await
                    .expect("bind ephemeral port");
                let addr = listener.local_addr().unwrap();
                let handle = tokio::spawn(async move {
                    axum::serve(listener, router).await.expect("server task");
                });
                return (format!("ws://{addr}/v1/ws"), handle);
            }
            Err(e) if std::time::Instant::now() < deadline => {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                let _ = e;
            }
            Err(e) => panic!("reopen the directory db after restart: still failing after 2s: {e}"),
        }
    }
}

#[tokio::test]
async fn a_registration_survives_a_real_restart() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("directory.redb");

    let (_account, bundle) = fresh_account_and_bundle("alice", 4821, 3);
    let (url, handle) = spawn_server_at(&db_path).await;
    let mut publisher = TestClient::connect(&url).await;
    publisher.skip_challenge().await;
    publisher
        .send(
            FrameTag::PublishBundle,
            &PublishBundle {
                bundle: bundle.clone(),
            },
        )
        .await;
    let (tag, ack): (_, Ack) = publisher.recv().await;
    assert_eq!(tag, FrameTag::Ack);
    assert!(ack.ok);
    drop(publisher);
    // Abort the task rather than let it merely go out of scope — a real
    // `redb::Database` holds an exclusive file lock for as long as
    // anything keeps its `AppState` alive, which the running task does
    // regardless of what local variables reference it.
    handle.abort();
    let _ = handle.await;

    let (url, _handle) = spawn_server_at_after_restart(&db_path).await;
    let mut fetcher = TestClient::connect(&url).await;
    fetcher.skip_challenge().await;
    fetcher
        .send(
            FrameTag::FetchBundle,
            &FetchBundle {
                username: "alice".into(),
                discriminator: 4821,
            },
        )
        .await;
    let (tag, result): (_, BundleResult) = fetcher.recv().await;
    assert_eq!(tag, FrameTag::BundleResult);
    let fetched = result
        .bundle
        .expect("alice's registration must survive the restart");
    assert_eq!(fetched.username, "alice");
    assert_eq!(fetched.discriminator, 4821);
    assert_eq!(fetched.identity_key, bundle.identity_key);
    assert!(
        fetched.one_time_prekey.is_some(),
        "the persisted one-time-prekey pool must have survived too"
    );
}

#[tokio::test]
async fn a_second_registration_after_restart_cannot_steal_a_persisted_username() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("directory.redb");

    let (_alice, alice_bundle) = fresh_account_and_bundle("alice", 1234, 1);
    let (url, handle) = spawn_server_at(&db_path).await;
    let mut publisher = TestClient::connect(&url).await;
    publisher.skip_challenge().await;
    publisher
        .send(
            FrameTag::PublishBundle,
            &PublishBundle {
                bundle: alice_bundle,
            },
        )
        .await;
    let (tag, ack): (_, Ack) = publisher.recv().await;
    assert_eq!(tag, FrameTag::Ack);
    assert!(ack.ok);
    drop(publisher);
    handle.abort();
    let _ = handle.await;

    // Restart, then a different identity tries to register under the
    // exact same handle a squatter would target if the directory had
    // forgotten it — this is precisely the gap `persistence` closes.
    let (url, _handle) = spawn_server_at_after_restart(&db_path).await;
    let (_squatter, mut squatter_bundle) = fresh_account_and_bundle("squatter-unused", 1, 1);
    squatter_bundle.username = "alice".into();
    squatter_bundle.discriminator = 1234;
    squatter_bundle.registration_pow = Some(dratchet_server::abuse::solve_registration_pow(
        "alice",
        1234,
        &squatter_bundle.identity_key,
    ));

    let mut squatter_client = TestClient::connect(&url).await;
    squatter_client.skip_challenge().await;
    squatter_client
        .send(
            FrameTag::PublishBundle,
            &PublishBundle {
                bundle: squatter_bundle,
            },
        )
        .await;
    let (tag, err): (_, ErrorFrame) = squatter_client.recv().await;
    assert_eq!(tag, FrameTag::Error);
    assert_eq!(
        err.message,
        dratchet_server::error::Error::UsernameTaken.to_string()
    );
}
