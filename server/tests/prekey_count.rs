//! Real end-to-end proof of `FetchOwnPrekeyCount` — the query
//! `ARCHITECTURE.md` §3.4's replenishment mechanism is built on: an
//! authenticated connection can see how many of its *own* one-time
//! prekeys the directory still has unconsumed, and nothing about
//! anyone else's.

mod common;

use common::*;
use dratchet_server::protocol::*;

#[tokio::test]
async fn reports_the_real_batch_size_then_reflects_consumption() {
    let url = spawn_server().await;
    let (account, bundle) = fresh_account_and_bundle("carol", 5555, 3);

    let mut owner = TestClient::connect(&url).await;
    owner.authenticate(&account).await;
    owner
        .send(FrameTag::PublishBundle, &PublishBundle { bundle })
        .await;
    let (tag, _ack): (_, Ack) = owner.recv().await;
    assert_eq!(tag, FrameTag::Ack);

    owner
        .send(FrameTag::FetchOwnPrekeyCount, &FetchOwnPrekeyCount {})
        .await;
    let (tag, count): (_, OwnPrekeyCount) = owner.recv().await;
    assert_eq!(tag, FrameTag::OwnPrekeyCount);
    assert_eq!(count.remaining, 3);

    // A different connection fetching the bundle (as any initiator would)
    // consumes from the same pool `FetchOwnPrekeyCount` reports on.
    let mut fetcher = TestClient::connect(&url).await;
    fetcher.skip_challenge().await;
    for _ in 0..2 {
        fetcher
            .send(
                FrameTag::FetchBundle,
                &FetchBundle {
                    username: "carol".into(),
                    discriminator: 5555,
                },
            )
            .await;
        let (tag, result): (_, BundleResult) = fetcher.recv().await;
        assert_eq!(tag, FrameTag::BundleResult);
        assert!(result.bundle.unwrap().one_time_prekey.is_some());
    }

    owner
        .send(FrameTag::FetchOwnPrekeyCount, &FetchOwnPrekeyCount {})
        .await;
    let (_, count): (_, OwnPrekeyCount) = owner.recv().await;
    assert_eq!(
        count.remaining, 1,
        "two of the original three must have been consumed"
    );
}

#[tokio::test]
async fn an_authenticated_identity_that_never_registered_sees_zero() {
    let url = spawn_server().await;
    let account = dratchet_core::account::Account::generate().unwrap();

    let mut client = TestClient::connect(&url).await;
    client.authenticate(&account).await;
    client
        .send(FrameTag::FetchOwnPrekeyCount, &FetchOwnPrekeyCount {})
        .await;
    let (tag, count): (_, OwnPrekeyCount) = client.recv().await;
    assert_eq!(tag, FrameTag::OwnPrekeyCount);
    assert_eq!(count.remaining, 0);
}

#[tokio::test]
async fn never_reports_a_different_identitys_prekey_count() {
    let url = spawn_server().await;
    let (alice_account, alice_bundle) = fresh_account_and_bundle("alice-count", 1111, 7);
    let (bob_account, bob_bundle) = fresh_account_and_bundle("bob-count", 2222, 1);

    let mut alice = TestClient::connect(&url).await;
    alice.authenticate(&alice_account).await;
    alice
        .send(
            FrameTag::PublishBundle,
            &PublishBundle {
                bundle: alice_bundle,
            },
        )
        .await;
    let (_, _ack): (_, Ack) = alice.recv().await;

    let mut bob = TestClient::connect(&url).await;
    bob.authenticate(&bob_account).await;
    bob.send(
        FrameTag::PublishBundle,
        &PublishBundle { bundle: bob_bundle },
    )
    .await;
    let (_, _ack): (_, Ack) = bob.recv().await;

    // Each connection only ever sees its own count (7 vs 1), never the
    // other's — there is no way to name a target identity in the request
    // at all, so this mostly guards against a future regression that adds
    // one.
    bob.send(FrameTag::FetchOwnPrekeyCount, &FetchOwnPrekeyCount {})
        .await;
    let (_, bob_count): (_, OwnPrekeyCount) = bob.recv().await;
    assert_eq!(bob_count.remaining, 1);

    alice
        .send(FrameTag::FetchOwnPrekeyCount, &FetchOwnPrekeyCount {})
        .await;
    let (_, alice_count): (_, OwnPrekeyCount) = alice.recv().await;
    assert_eq!(alice_count.remaining, 7);
}
