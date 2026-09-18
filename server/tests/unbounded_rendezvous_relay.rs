//! Penetration-test finding, DRA-0026 (round 4, denial of service —
//! amplification against another connected client), found auditing
//! `ws.rs`'s `RendezvousOffer`/`RendezvousAnswer` handlers for the same
//! size-bounding discipline every other client-supplied payload in this
//! file follows (`MailboxWrite`'s envelope: `state::MAX_ENVELOPE_LEN`,
//! DRA-0015; `PublishBundle`'s username/prekeys: DRA-0019/DRA-0024).
//! Nothing bounded `sdp_offer`/`sdp_answer`/`ice_candidates` at all.
//!
//! `relay_to_peer` forwards a `RendezvousOffer`/`RendezvousAnswer`
//! verbatim into the *target's* outbound channel with no relationship
//! check and no rate limit — so any authenticated identity could force
//! the server to relay an arbitrarily large payload straight at any
//! other currently-connected client, repeatedly, an amplification/DoS
//! vector against a target who never agreed to receive anything from the
//! sender.
//!
//! **Fixed**: `state::MAX_SDP_LEN` (64 KiB), `state::MAX_ICE_CANDIDATES`
//! (64), and `state::MAX_ICE_CANDIDATE_LEN` (4 KiB per candidate),
//! checked in `ws::validate_rendezvous_payload` before `relay_to_peer`
//! ever touches the target's connection.

mod common;

use common::*;
use dratchet_core::account::Account;
use dratchet_server::protocol::*;

#[tokio::test]
async fn an_oversized_sdp_offer_is_rejected_before_it_reaches_the_target() {
    let url = spawn_server().await;

    let alice = Account::generate().unwrap();
    let mut alice_conn = TestClient::connect(&url).await;
    alice_conn.authenticate(&alice).await;

    let mallory = Account::generate().unwrap();
    let mut mallory_conn = TestClient::connect(&url).await;
    mallory_conn.authenticate(&mallory).await;

    // 10 MiB "SDP offer" -- no real WebRTC offer is ever remotely this
    // size, but pre-fix, the server would relay every byte of it
    // straight at alice's live connection.
    let huge_sdp = "x".repeat(10 * 1024 * 1024);
    mallory_conn
        .send(
            FrameTag::RendezvousOffer,
            &RendezvousOffer {
                peer_fingerprint: alice.identity.fingerprint().as_bytes().to_vec(),
                sdp_offer: huge_sdp,
                ice_candidates: Vec::new(),
            },
        )
        .await;
    let (tag, err): (_, ErrorFrame) = mallory_conn.recv().await;
    assert_eq!(
        tag,
        FrameTag::Error,
        "FIX VERIFIED: an oversized SDP offer must be rejected outright, not relayed to the \
         target's live connection"
    );
    assert!(err.message.to_lowercase().contains("sdp"));
}

#[tokio::test]
async fn too_many_ice_candidates_are_rejected() {
    let url = spawn_server().await;

    let alice = Account::generate().unwrap();
    let mut alice_conn = TestClient::connect(&url).await;
    alice_conn.authenticate(&alice).await;

    let mallory = Account::generate().unwrap();
    let mut mallory_conn = TestClient::connect(&url).await;
    mallory_conn.authenticate(&mallory).await;

    let too_many: Vec<String> = (0..10_000).map(|i| format!("candidate-{i}")).collect();
    mallory_conn
        .send(
            FrameTag::RendezvousAnswer,
            &RendezvousAnswer {
                peer_fingerprint: alice.identity.fingerprint().as_bytes().to_vec(),
                sdp_answer: "ordinary-small-answer".to_string(),
                ice_candidates: too_many,
            },
        )
        .await;
    let (tag, _err): (_, ErrorFrame) = mallory_conn.recv().await;
    assert_eq!(
        tag,
        FrameTag::Error,
        "an excessive number of ICE candidates must be rejected"
    );
}

#[tokio::test]
async fn an_ordinary_small_rendezvous_offer_still_relays_normally() {
    let url = spawn_server().await;

    let alice = Account::generate().unwrap();
    let mut alice_conn = TestClient::connect(&url).await;
    alice_conn.authenticate(&alice).await;

    let bob = Account::generate().unwrap();
    let mut bob_conn = TestClient::connect(&url).await;
    bob_conn.authenticate(&bob).await;

    bob_conn
        .send(
            FrameTag::RendezvousOffer,
            &RendezvousOffer {
                peer_fingerprint: alice.identity.fingerprint().as_bytes().to_vec(),
                sdp_offer: "v=0\r\no=- 12345 2 IN IP4 127.0.0.1\r\n".to_string(),
                ice_candidates: vec![
                    "candidate:1 1 UDP 2130706431 127.0.0.1 12345 typ host".to_string()
                ],
            },
        )
        .await;

    let (tag, relayed): (_, RendezvousOffer) = alice_conn.recv().await;
    assert_eq!(
        tag,
        FrameTag::RendezvousOffer,
        "the fix must not be overly strict -- an ordinary, real-sized offer must still relay"
    );
    assert_eq!(
        relayed.peer_fingerprint,
        bob.identity.fingerprint().as_bytes()
    );
}
