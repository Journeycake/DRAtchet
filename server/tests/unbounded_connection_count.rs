//! Penetration-test finding, DRA-0031 (round 4, denial of service —
//! unbounded connection count). DRA-0030 bounds a single message/frame,
//! but nothing bounded total concurrent connections: a flood of bare,
//! unauthenticated TCP connections -- cheap for an attacker, since no
//! bytes need to be sent past the initial WebSocket handshake -- could
//! still exhaust server memory/file descriptors one `tokio::spawn` task
//! and mpsc channel at a time, at whatever rate an attacker could open
//! sockets.
//!
//! **Fixed**: `AppState::active_connections`/`connection_cap`, checked in
//! `ws::ws_handler` before the HTTP upgrade completes; a connection past
//! the cap gets a plain `503 Service Unavailable` instead of a WebSocket
//! upgrade. Uses `AppState::new_with_connection_cap` (a small cap of 2)
//! so this proves real enforcement without needing to open thousands of
//! connections against the real 10,000-connection default.

use axum::routing::get;
use axum::Router;
use dratchet_server::state::AppState;
use tokio::net::TcpListener;
use tokio_tungstenite::connect_async;

async fn spawn_capped_server(cap: usize) -> String {
    let state = AppState::new_with_connection_cap(cap);
    let router = Router::new()
        .route("/v1/ws", get(dratchet_server::ws::ws_handler))
        .with_state(state);
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.expect("server task");
    });
    format!("ws://{addr}/v1/ws")
}

#[tokio::test]
async fn a_connection_past_the_cap_is_rejected_before_the_upgrade() {
    let url = spawn_capped_server(2).await;

    // Two connections fill the cap. Kept alive (not dropped) for the
    // whole test -- DRA-0031's counter decrements on disconnect, so
    // dropping either of these would silently make room again and the
    // third connect below would succeed for the wrong reason.
    let _first = connect_async(&url)
        .await
        .expect("first connection (1/2) should succeed");
    let _second = connect_async(&url)
        .await
        .expect("second connection (2/2) should succeed, filling the cap");

    // A brief yield so the server side has actually registered both
    // connections (the cap is checked against a counter incremented
    // inside the spawned `handle_socket` task, not synchronously with
    // the client's own `connect_async` returning).
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let third = connect_async(&url).await;
    assert!(
        third.is_err(),
        "VULNERABILITY: a third connection was accepted past a configured cap of 2 -- \
         connection count was never bounded at all"
    );
}

#[tokio::test]
async fn connections_under_the_cap_still_connect_normally() {
    let url = spawn_capped_server(2).await;
    let _first = connect_async(&url)
        .await
        .expect("the fix must not be overly strict -- an ordinary connection under the cap must still succeed");
}
