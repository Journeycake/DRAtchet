//! An unsolicited frame pushed into a client's connection was read as the
//! reply to whatever request the client sent next.
//!
//! Every exchange on `net::Connection` is request/response, and `recv` took
//! the next frame off the socket whatever it was. But the server also
//! pushes frames nobody asked for: a `RendezvousOffer`/`RendezvousAnswer`
//! relayed from another account (`server/src/ws.rs`'s `relay_to_peer`),
//! and `PresenceUpdate`s to subscribers. Relaying a rendezvous frame needs
//! only fetch evidence: any account that knows the victim's handle can look
//! up their bundle and then push a frame into their live connection. The
//! victim's next request then read that frame as its reply, the real reply
//! stayed queued for the request after, and every exchange from then on
//! was one reply out of step until the connection was replaced.

use std::time::Duration;

use dratchet_app::{
    open_account, publish_own_bundle, receive_first_contact_attempts, replenish_prekeys_if_low,
};
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

/// Mallory looks Alice up by handle, then relays a rendezvous offer at
/// her live connection. Returns whether the server delivered it.
async fn push_offer_at(url: &str, username: &str, discriminator: u16, target: &[u8]) -> bool {
    let mallory_db = temp_db();
    let mallory = open_account(&mallory_db).unwrap();
    let mut conn = Connection::connect(url).await.unwrap();
    conn.authenticate(&mallory).await.unwrap();
    conn.send(
        FrameTag::FetchBundle,
        &FetchBundle {
            username: username.to_string(),
            discriminator,
        },
    )
    .await
    .unwrap();
    let (_, _bundle): (_, BundleResult) = conn.recv().await.unwrap();
    conn.send(
        FrameTag::RendezvousOffer,
        &RendezvousOffer {
            peer_fingerprint: target.to_vec(),
            sdp_offer: "v=0".to_string(),
            ice_candidates: Vec::new(),
        },
    )
    .await
    .unwrap();
    let (_, ack): (_, Ack) = conn.recv().await.unwrap();
    ack.ok
}

#[tokio::test]
async fn an_unsolicited_relayed_frame_does_not_knock_the_connection_out_of_step() {
    let url = spawn_server().await;
    let db = temp_db();
    let mut alice = open_account(&db).unwrap();
    let mut conn = Connection::connect(&url).await.unwrap();
    conn.authenticate(&alice).await.unwrap();
    let profile = publish_own_bundle(&db, &mut conn, &mut alice, "victim69")
        .await
        .unwrap();

    let delivered = push_offer_at(
        &url,
        &profile.username,
        profile.discriminator,
        alice.identity.fingerprint().as_bytes(),
    )
    .await;
    assert!(
        delivered,
        "the server relayed the offer into Alice's connection"
    );
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Alice carries on exactly as the desktop app's poll loop does.
    let mut failures = Vec::new();
    for round in 0..3 {
        if let Err(e) = replenish_prekeys_if_low(&db, &mut conn, &mut alice).await {
            failures.push(format!("round {round}, prekey check: {e}"));
        }
        if let Err(e) = receive_first_contact_attempts(&db, &mut conn, &mut alice).await {
            failures.push(format!("round {round}, inbox scan: {e}"));
        }
    }
    assert!(
        failures.is_empty(),
        "VULNERABILITY: one unsolicited frame pushed by another account was read as the reply \
         to Alice's next request, and every request after it got the previous one's reply: \
         {failures:#?}"
    );
}

/// Guard: the pushed frame isn't lost, just set aside; it's there for
/// whoever wants it, and it says who sent it.
#[tokio::test]
async fn a_pushed_frame_is_kept_for_take_pushes() {
    let url = spawn_server().await;
    let db = temp_db();
    let mut alice = open_account(&db).unwrap();
    let mut conn = Connection::connect(&url).await.unwrap();
    conn.authenticate(&alice).await.unwrap();
    let profile = publish_own_bundle(&db, &mut conn, &mut alice, "victim69b")
        .await
        .unwrap();
    assert!(
        push_offer_at(
            &url,
            &profile.username,
            profile.discriminator,
            alice.identity.fingerprint().as_bytes(),
        )
        .await
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
    replenish_prekeys_if_low(&db, &mut conn, &mut alice)
        .await
        .unwrap();

    let pushes = conn.take_pushes();
    assert_eq!(pushes.len(), 1);
    let (tag, body) = split_tag(&pushes[0]).unwrap();
    assert_eq!(tag, FrameTag::RendezvousOffer);
    let offer: RendezvousOffer = decode_body(body).unwrap();
    assert_eq!(offer.sdp_offer, "v=0");
    assert!(conn.take_pushes().is_empty(), "taken once");
}

/// Guard: a stream of pushed frames can't stretch a request's wait past
/// its timeout.
#[tokio::test]
async fn pushed_frames_do_not_extend_the_request_timeout() {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message as WsMessage;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
        // Read the request, never answer it, push a presence update every
        // 200 ms instead.
        let _ = ws.next().await;
        loop {
            let push = encode(
                FrameTag::PresenceUpdate,
                &PresenceUpdate {
                    identity_fingerprint: vec![1; 32],
                    state: 0,
                    last_seen: None,
                },
            );
            if ws.send(WsMessage::Binary(push)).await.is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    });
    let mut conn = Connection::connect(&format!("ws://{addr}/v1/ws"))
        .await
        .unwrap();
    conn.set_request_timeout(Duration::from_secs(1));
    conn.send(FrameTag::FetchOwnPrekeyCount, &FetchOwnPrekeyCount {})
        .await
        .unwrap();
    let started = std::time::Instant::now();
    let result = tokio::time::timeout(Duration::from_secs(5), conn.recv_raw()).await;
    assert!(
        matches!(result, Ok(Err(_))),
        "the request times out on schedule instead of waiting as long as pushes keep coming"
    );
    assert!(started.elapsed() < Duration::from_secs(3));
}
