//! Real end-to-end proof of `dratchet_app::replenish_prekeys_if_low`
//! (`docs/ARCHITECTURE.md` §3.4): a real account registers, a real peer
//! connection drains its one-time-prekey pool via `FetchBundle` the same
//! way any initiator would, and replenishment only republishes once the
//! pool has actually drained to the threshold — never before, and always
//! back to a full batch.

use std::sync::Arc;

use dratchet_app::{open_account, publish_own_bundle, replenish_prekeys_if_low};
use dratchet_client::net::Connection;
use dratchet_server::protocol::*;
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

async fn own_prekey_count(conn: &mut Connection) -> u32 {
    conn.send(FrameTag::FetchOwnPrekeyCount, &FetchOwnPrekeyCount {})
        .await
        .unwrap();
    let (_, count): (_, OwnPrekeyCount) = conn.recv().await.unwrap();
    count.remaining
}

/// A fresh `Connection` (and so a fresh rate-limiter bucket,
/// `server/src/abuse.rs`'s `FetchRateLimiter` — keyed by `(requester
/// connection, target)`, capacity 5) per fetch: draining more than 5
/// prekeys on one connection would otherwise start hitting
/// `Error::RateLimited` partway through, which is a real, separate
/// server behavior this test has no interest in exercising.
async fn drain_prekeys(url: &str, username: &str, discriminator: u16, n: usize) {
    for _ in 0..n {
        let mut fetcher = Connection::connect(url).await.unwrap();
        let (_, _challenge): (_, AuthChallenge) = fetcher.recv().await.unwrap();
        fetcher
            .send(
                FrameTag::FetchBundle,
                &FetchBundle {
                    username: username.to_string(),
                    discriminator,
                },
            )
            .await
            .unwrap();
        let (_, result): (_, BundleResult) = fetcher.recv().await.unwrap();
        assert!(
            result.bundle.unwrap().one_time_prekey.is_some(),
            "expected a one-time prekey to still be available to drain"
        );
    }
}

#[tokio::test]
async fn replenishes_once_the_pool_has_actually_drained_to_the_threshold() {
    let url = spawn_server().await;
    let db = Arc::new(temp_db());
    let mut account = open_account(&db).unwrap();
    let mut conn = Connection::connect(&url).await.unwrap();
    conn.authenticate(&account).await.unwrap();
    let profile = publish_own_bundle(&db, &mut conn, &mut account, "prekeytest")
        .await
        .unwrap();

    assert_eq!(own_prekey_count(&mut conn).await, 10);

    // Drain down to 4 remaining — above the threshold (3), so this must
    // be a no-op.
    drain_prekeys(&url, &profile.username, profile.discriminator, 6).await;
    assert_eq!(own_prekey_count(&mut conn).await, 4);
    let replenished = replenish_prekeys_if_low(&db, &mut conn, &mut account)
        .await
        .unwrap();
    assert!(!replenished, "4 remaining is still above the threshold");
    assert_eq!(
        own_prekey_count(&mut conn).await,
        4,
        "a no-op check must not have touched the pool"
    );

    // Drain one more — now at 3, exactly the threshold, which must
    // trigger a real replenish back to a full batch.
    drain_prekeys(&url, &profile.username, profile.discriminator, 1).await;
    assert_eq!(own_prekey_count(&mut conn).await, 3);
    let replenished = replenish_prekeys_if_low(&db, &mut conn, &mut account)
        .await
        .unwrap();
    assert!(replenished, "3 remaining is at the threshold");
    assert_eq!(
        own_prekey_count(&mut conn).await,
        10,
        "replenishing must restore a full batch"
    );

    // Immediately after, it's a no-op again.
    let replenished = replenish_prekeys_if_low(&db, &mut conn, &mut account)
        .await
        .unwrap();
    assert!(!replenished);
}

#[tokio::test]
async fn is_a_no_op_before_the_device_has_ever_registered() {
    let url = spawn_server().await;
    let db = Arc::new(temp_db());
    let mut account = open_account(&db).unwrap();
    let mut conn = Connection::connect(&url).await.unwrap();
    conn.authenticate(&account).await.unwrap();

    let replenished = replenish_prekeys_if_low(&db, &mut conn, &mut account)
        .await
        .unwrap();
    assert!(!replenished);
}
