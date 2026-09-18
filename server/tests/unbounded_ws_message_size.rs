//! Penetration-test finding, DRA-0030 (round 4, denial of service —
//! transport-layer resource exhaustion). Every application-layer cap in
//! `state.rs` (`MAX_ENVELOPE_LEN`, `MAX_SDP_LEN`, `MAX_USERNAME_LEN`, ...)
//! only runs *after* a WebSocket message has already been fully decoded
//! into memory by `axum`/`tokio-tungstenite` -- and `ws_handler` never set
//! either library's own message-size ceiling, so it silently defaulted to
//! 64 MiB, reachable by any TCP connection whether or not it had
//! authenticated yet (the `AuthResponse` check in `dispatch` only runs
//! after the frame is already fully buffered).
//!
//! **Fixed**: `ws_handler` now calls `.max_message_size(...)` and
//! `.max_frame_size(...)` with `state::MAX_WS_MESSAGE_BYTES` (1 MiB) on
//! every upgraded connection, before `handle_socket` ever sees a byte.

mod common;

use common::*;
use dratchet_core::account::Account;
use tokio_tungstenite::tungstenite::Message as WsMessage;

#[tokio::test]
async fn an_oversized_pre_auth_frame_is_rejected_at_the_transport_layer() {
    let url = spawn_server().await;
    let mut conn = TestClient::connect(&url).await;
    conn.skip_challenge().await;

    // 2 MiB: already far larger than the largest legitimate frame this
    // protocol ever sends (an ordinary RendezvousAnswer, DRA-0026's own
    // caps, tops out well under 320 KiB), but still 32x smaller than the
    // library's undocumented 64 MiB default -- exactly the gap this
    // finding closes. The client side has no size limit configured, so
    // this send always succeeds regardless of the fix; what's under test
    // is how the *server* reacts to receiving it.
    conn.send_raw(vec![0u8; 2 * 1024 * 1024]).await;

    // Post-fix, the server's own read side rejects the frame as soon as it
    // exceeds the configured ceiling and drops the connection -- the next
    // read here observes that as the connection closing (`None`) or an
    // explicit close frame. Pre-fix, neither happens: the oversized frame
    // is accepted in full, forwarded to `dispatch`, fails CBOR decoding
    // for an unrelated reason, and comes back as an ordinary `Error` frame
    // on a connection that stays open.
    let next = conn.recv_frame_or_close().await;
    let rejected_at_transport_layer = matches!(next, None | Some(WsMessage::Close(_)));
    assert!(
        rejected_at_transport_layer,
        "VULNERABILITY: a 2 MiB pre-auth frame was accepted without any transport-level \
         size limit (got {next:?} instead of the connection closing)"
    );
}

#[tokio::test]
async fn an_ordinary_connection_still_authenticates_normally() {
    let url = spawn_server().await;
    let account = Account::generate().unwrap();
    let mut conn = TestClient::connect(&url).await;
    // `authenticate` itself asserts the Ack came back ok -- the fix must
    // not be overly strict and break every real, ordinary-sized frame.
    conn.authenticate(&account).await;
}
