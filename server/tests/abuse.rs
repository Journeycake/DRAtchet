//! Directory abuse resistance (Phase 1.2, `ARCHITECTURE.md` §11.8) — tested
//! end-to-end against the real, running service, same discipline as
//! `integration.rs`/`adversarial.rs`: username-squatting/impersonation
//! resistance (registration proof-of-work, ownership enforcement) and
//! prekey-fetch rate limiting. `crate::abuse`'s own unit tests cover the
//! rate limiter and proof-of-work primitives in isolation; these tests
//! cover them wired into the actual `PublishBundle`/`FetchBundle` dispatch
//! path.

mod common;

use common::*;
use dratchet_server::abuse::solve_registration_pow;
use dratchet_server::protocol::*;

#[tokio::test]
async fn publishing_a_brand_new_username_without_proof_of_work_is_rejected() {
    let url = spawn_server().await;
    let (_account, mut bundle) = fresh_account_and_bundle("newuser", 1, 0);
    bundle.registration_pow = None; // the fixture solves one by default; strip it back off

    let mut client = TestClient::connect(&url).await;
    client.skip_challenge().await;
    client
        .send(FrameTag::PublishBundle, &PublishBundle { bundle })
        .await;
    let (tag, _err): (_, ErrorFrame) = client.recv().await;
    assert_eq!(tag, FrameTag::Error);

    // And it must not have been stored despite the rejection.
    let mut fetcher = TestClient::connect(&url).await;
    fetcher.skip_challenge().await;
    fetcher
        .send(
            FrameTag::FetchBundle,
            &FetchBundle {
                username: "newuser".into(),
                discriminator: 1,
            },
        )
        .await;
    let (_, result): (_, BundleResult) = fetcher.recv().await;
    assert!(
        result.bundle.is_none(),
        "a rejected registration must not be stored"
    );
}

#[tokio::test]
async fn publishing_a_brand_new_username_with_a_wrong_proof_of_work_solution_is_rejected() {
    let url = spawn_server().await;
    let (_account, mut bundle) = fresh_account_and_bundle("newuser2", 1, 0);
    // A solution solved for a *different* username never verifies for this one.
    bundle.registration_pow = Some(solve_registration_pow(
        "someone-else",
        1,
        &bundle.identity_key,
    ));

    let mut client = TestClient::connect(&url).await;
    client.skip_challenge().await;
    client
        .send(FrameTag::PublishBundle, &PublishBundle { bundle })
        .await;
    let (tag, _err): (_, ErrorFrame) = client.recv().await;
    assert_eq!(tag, FrameTag::Error);
}

#[tokio::test]
async fn publishing_a_brand_new_username_with_a_valid_proof_of_work_solution_succeeds() {
    let url = spawn_server().await;
    // fresh_account_and_bundle already solves a correct proof-of-work for a
    // brand-new username — the golden path every other test relies on.
    let (_account, bundle) = fresh_account_and_bundle("newuser3", 1, 0);

    let mut client = TestClient::connect(&url).await;
    client.skip_challenge().await;
    client
        .send(FrameTag::PublishBundle, &PublishBundle { bundle })
        .await;

    let mut fetcher = TestClient::connect(&url).await;
    fetcher.skip_challenge().await;
    fetcher
        .send(
            FrameTag::FetchBundle,
            &FetchBundle {
                username: "newuser3".into(),
                discriminator: 1,
            },
        )
        .await;
    let (_, result): (_, BundleResult) = fetcher.recv().await;
    assert!(
        result.bundle.is_some(),
        "a validly-registered bundle must be stored"
    );
}

#[tokio::test]
async fn rotating_an_already_owned_bundle_never_requires_proof_of_work() {
    let url = spawn_server().await;
    let (_account, mut bundle) = fresh_account_and_bundle("rotator", 1, 3);

    let mut client = TestClient::connect(&url).await;
    client.skip_challenge().await;
    client
        .send(
            FrameTag::PublishBundle,
            &PublishBundle {
                bundle: bundle.clone(),
            },
        )
        .await;

    // Republish the *same* signed prekey (so the bundle's own signatures,
    // which cover `signed_prekey_id`/`signed_prekey`, stay valid — this
    // test isn't exercising bundle-signature verification) with no
    // proof-of-work at all, but with `signed_prekey_expires_at` changed —
    // a field no signature covers, so it's a safe way to observe whether
    // this second publish actually took effect or was silently rejected.
    bundle.registration_pow = None;
    bundle.signed_prekey_expires_at = 999_999;
    client
        .send(FrameTag::PublishBundle, &PublishBundle { bundle })
        .await;

    // Fetch on the *same* connection, after the two publishes above — this
    // is guaranteed to observe both, since one WebSocket connection's
    // frames are dispatched strictly in the order they were sent (unlike
    // fetching from a separate, unrelated connection, which has no such
    // ordering guarantee relative to another connection's in-flight
    // writes).
    client
        .send(
            FrameTag::FetchBundle,
            &FetchBundle {
                username: "rotator".into(),
                discriminator: 1,
            },
        )
        .await;
    let (_, result): (_, BundleResult) = client.recv().await;
    assert_eq!(
        result
            .bundle
            .expect("bundle should still be found")
            .signed_prekey_expires_at,
        999_999,
        "the second publish (no proof-of-work, since this identity already owns the username) \
         should have taken effect, not been rejected"
    );
}

#[tokio::test]
async fn a_second_identity_cannot_steal_an_already_registered_username() {
    let url = spawn_server().await;
    let (_first, first_bundle) = fresh_account_and_bundle("contested", 42, 0);
    let (_second, second_bundle) = fresh_account_and_bundle("contested", 42, 0);
    // Both fixtures independently solve valid proof-of-work for their own
    // identity key over the same (username, discriminator) — proof-of-work
    // alone must not be enough to take over an already-claimed username.

    let mut first_client = TestClient::connect(&url).await;
    first_client.skip_challenge().await;
    first_client
        .send(
            FrameTag::PublishBundle,
            &PublishBundle {
                bundle: first_bundle.clone(),
            },
        )
        .await;

    let mut second_client = TestClient::connect(&url).await;
    second_client.skip_challenge().await;
    second_client
        .send(
            FrameTag::PublishBundle,
            &PublishBundle {
                bundle: second_bundle,
            },
        )
        .await;
    let (tag, _err): (_, ErrorFrame) = second_client.recv().await;
    assert_eq!(
        tag,
        FrameTag::Error,
        "a different identity must not be able to claim a taken username"
    );

    // The original owner's bundle must be unaffected.
    let mut fetcher = TestClient::connect(&url).await;
    fetcher.skip_challenge().await;
    fetcher
        .send(
            FrameTag::FetchBundle,
            &FetchBundle {
                username: "contested".into(),
                discriminator: 42,
            },
        )
        .await;
    let (_, result): (_, BundleResult) = fetcher.recv().await;
    assert_eq!(
        result.bundle.unwrap().identity_key,
        first_bundle.identity_key
    );
}

#[tokio::test]
async fn fetch_bundle_is_rate_limited_per_requester_and_target_beyond_a_burst() {
    let url = spawn_server().await;
    let (_publisher, bundle) = fresh_account_and_bundle("target", 1, 0);

    let mut publisher = TestClient::connect(&url).await;
    publisher.skip_challenge().await;
    publisher
        .send(FrameTag::PublishBundle, &PublishBundle { bundle })
        .await;

    let mut fetcher = TestClient::connect(&url).await;
    fetcher.skip_challenge().await;

    let mut saw_rate_limited = false;
    for _ in 0..20 {
        fetcher
            .send(
                FrameTag::FetchBundle,
                &FetchBundle {
                    username: "target".into(),
                    discriminator: 1,
                },
            )
            .await;
        let raw = fetcher.recv_raw().await;
        let (tag, _body) = split_tag(&raw).expect("valid frame from the server");
        if tag == FrameTag::Error {
            saw_rate_limited = true;
            break;
        }
        assert_eq!(tag, FrameTag::BundleResult);
    }
    assert!(
        saw_rate_limited,
        "bursting fetches against the same target must eventually be rate-limited"
    );
}

#[tokio::test]
async fn fetch_rate_limit_on_one_target_does_not_block_fetching_a_different_target() {
    let url = spawn_server().await;
    let (_a, bundle_a) = fresh_account_and_bundle("targetA", 1, 0);
    let (_b, bundle_b) = fresh_account_and_bundle("targetB", 1, 0);

    // Publish and fetch all on *one* connection throughout — a WebSocket
    // connection's own frames are dispatched strictly in the order sent, so
    // this sidesteps any question of whether a publish on one connection is
    // guaranteed visible yet to a fetch on a different, unrelated
    // connection (no such cross-connection ordering guarantee exists, and
    // isn't what this test is about — see `rotating_an_already_owned_...`
    // above, which specifically relies on same-connection ordering too).
    let mut client = TestClient::connect(&url).await;
    client.skip_challenge().await;
    client
        .send(FrameTag::PublishBundle, &PublishBundle { bundle: bundle_a })
        .await;
    client
        .send(FrameTag::PublishBundle, &PublishBundle { bundle: bundle_b })
        .await;

    // Exhaust the budget against target A on this connection...
    let mut got_rate_limited = false;
    for _ in 0..20 {
        client
            .send(
                FrameTag::FetchBundle,
                &FetchBundle {
                    username: "targetA".into(),
                    discriminator: 1,
                },
            )
            .await;
        let raw = client.recv_raw().await;
        let (tag, _body) = split_tag(&raw).expect("valid frame from the server");
        if tag == FrameTag::Error {
            got_rate_limited = true;
            break;
        }
    }
    assert!(
        got_rate_limited,
        "bursting fetches against target A should have been rate-limited"
    );

    // ...target B, never fetched before, must still have its own budget.
    client
        .send(
            FrameTag::FetchBundle,
            &FetchBundle {
                username: "targetB".into(),
                discriminator: 1,
            },
        )
        .await;
    let (tag, result): (_, BundleResult) = client.recv().await;
    assert_eq!(tag, FrameTag::BundleResult);
    assert!(
        result.bundle.is_some(),
        "a different, never-fetched target must not be affected"
    );
}
