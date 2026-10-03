//! Penetration-test finding DRA-0045 (round 7, denial of service +
//! unsolicited contact).
//!
//! `ws.rs`'s `RendezvousOffer`/`RendezvousAnswer` arms relay a
//! client-supplied payload straight into *any* other connected identity's
//! outbound channel, selected by a `peer_fingerprint` the sender chooses
//! freely. DRA-0026 capped how large one such payload may be, and its own
//! doc comment records what it did **not** close: the relay happens
//! "with no relationship check and no rate limit either."
//!
//! So any authenticated identity — and authenticating is free, see
//! DRA-0044 — could ring any online user it liked, as fast as it liked,
//! at up to `MAX_SDP_LEN` + `MAX_ICE_CANDIDATES * MAX_ICE_CANDIDATE_LEN`
//! (~320 KiB) per frame, and every one of those frames landed in an
//! *unbounded* `mpsc` queue that grows as fast as the attacker writes and
//! only drains as fast as the victim's socket reads.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::*;
use dratchet_server::protocol::*;
use dratchet_server::state::AppState;
use tokio::net::TcpListener;

async fn spawn_server_with_state() -> (String, Arc<AppState>) {
    let (router, state) = dratchet_server::app();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.expect("server task");
    });
    (format!("ws://{addr}/v1/ws"), state)
}

/// A victim: authenticated, in the directory, and online.
async fn online_victim(url: &str, username: &str, discriminator: u16) -> (TestClient, Vec<u8>) {
    let (account, bundle) = fresh_account_and_bundle(username, discriminator, 4);
    let mut client = TestClient::connect(url).await;
    client.authenticate(&account).await;
    client
        .send(FrameTag::PublishBundle, &PublishBundle { bundle })
        .await;
    let (tag, ack): (_, Ack) = client.recv().await;
    assert_eq!(tag, FrameTag::Ack);
    assert!(ack.ok);
    (client, fingerprint_of(&account))
}

fn offer_to(peer_fingerprint: &[u8]) -> RendezvousOffer {
    RendezvousOffer {
        peer_fingerprint: peer_fingerprint.to_vec(),
        sdp_offer: "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\n".to_string(),
        ice_candidates: vec!["candidate:1 1 udp 1 127.0.0.1 9 typ host".to_string()],
    }
}

/// Did `client` receive anything within `window`? Used for the negative
/// half: a blocked relay must produce *no* frame at the victim, not a
/// different one.
async fn received_anything(client: &mut TestClient, window: Duration) -> bool {
    tokio::time::timeout(window, client.recv_raw())
        .await
        .is_ok()
}

#[tokio::test]
async fn a_stranger_cannot_ring_an_online_user_it_has_no_relationship_with() {
    let (url, _state) = spawn_server_with_state().await;
    let (mut victim, victim_fp) = online_victim(&url, "victim", 3001).await;

    // The attacker publishes nothing and never fetches the victim's
    // bundle -- it knows only the fingerprint, which is public.
    let stranger = dratchet_core::account::Account::generate().unwrap();
    let mut attacker = TestClient::connect(&url).await;
    attacker.authenticate(&stranger).await;

    attacker
        .send(FrameTag::RendezvousOffer, &offer_to(&victim_fp))
        .await;

    // The server must refuse the sender...
    let (tag, _body): (_, ErrorFrame) = attacker.recv().await;
    assert_eq!(
        tag,
        FrameTag::Error,
        "VULNERABILITY: the server relayed a rendezvous offer from an identity with no \
         relationship to the target -- any authenticated stranger could ring any online user, \
         as often as it liked, pushing ~320 KiB frames into that user's unbounded outbound queue"
    );

    // ...and nothing at all may reach the victim.
    assert!(
        !received_anything(&mut victim, Duration::from_millis(300)).await,
        "VULNERABILITY: an unsolicited rendezvous offer reached the victim's connection"
    );
}

#[tokio::test]
async fn a_real_peer_that_fetched_the_bundle_can_still_ring() {
    let (url, _state) = spawn_server_with_state().await;
    let (mut victim, victim_fp) = online_victim(&url, "callee", 3002).await;

    // A genuine caller does exactly what the protocol requires before it
    // could have any session with the callee at all: fetch their bundle.
    let caller = dratchet_core::account::Account::generate().unwrap();
    let mut caller_client = TestClient::connect(&url).await;
    caller_client.authenticate(&caller).await;
    caller_client
        .send(
            FrameTag::FetchBundle,
            &FetchBundle {
                username: "callee".to_string(),
                discriminator: 3002,
            },
        )
        .await;
    let (tag, result): (_, BundleResult) = caller_client.recv().await;
    assert_eq!(tag, FrameTag::BundleResult);
    assert!(result.bundle.is_some());

    caller_client
        .send(FrameTag::RendezvousOffer, &offer_to(&victim_fp))
        .await;

    let (tag, relayed): (_, RendezvousOffer) = victim.recv().await;
    assert_eq!(
        tag,
        FrameTag::RendezvousOffer,
        "the fix must not break a legitimate call: a caller that fetched the bundle may ring"
    );
    assert_eq!(
        relayed.peer_fingerprint,
        fingerprint_of(&caller),
        "the relayed offer must be attributed to the real sender"
    );

    let (tag, ack): (_, Ack) = caller_client.recv().await;
    assert_eq!(tag, FrameTag::Ack);
    assert!(ack.ok, "the caller must be told delivery happened");
}

#[tokio::test]
async fn ringing_is_rate_limited_even_for_a_legitimate_peer() {
    let (url, _state) = spawn_server_with_state().await;
    let (mut victim, victim_fp) = online_victim(&url, "flooded", 3003).await;

    let caller = dratchet_core::account::Account::generate().unwrap();
    let mut caller_client = TestClient::connect(&url).await;
    caller_client.authenticate(&caller).await;
    caller_client
        .send(
            FrameTag::FetchBundle,
            &FetchBundle {
                username: "flooded".to_string(),
                discriminator: 3003,
            },
        )
        .await;
    let (tag, _result): (_, BundleResult) = caller_client.recv().await;
    assert_eq!(tag, FrameTag::BundleResult);

    // Far more offers than any real negotiation needs. The budget must
    // run out well before the last one.
    let attempts = dratchet_server::abuse::RENDEZVOUS_RATE_LIMIT_CAPACITY as usize * 3;
    let mut refused = 0;
    for _ in 0..attempts {
        caller_client
            .send(FrameTag::RendezvousOffer, &offer_to(&victim_fp))
            .await;
        let raw = caller_client.recv_raw().await;
        let (tag, _) = split_tag(&raw).expect("valid frame");
        if tag == FrameTag::Error {
            refused += 1;
        }
        // Drain whatever actually made it to the victim so its own queue
        // doesn't influence the result.
        let _ = tokio::time::timeout(Duration::from_millis(5), victim.recv_raw()).await;
    }

    assert!(
        refused > 0,
        "VULNERABILITY: {attempts} back-to-back rendezvous offers were all relayed -- nothing \
         rate-limits how fast one identity may push relayed frames at another"
    );
}
