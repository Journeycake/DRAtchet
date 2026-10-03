//! DRA-0068: connecting to a server that accepts the TCP connection but
//! never answers must give up, not wait indefinitely.

use std::time::{Duration, Instant};

use dratchet_client::net::{Connection, NetError};
use tokio::net::TcpListener;

#[tokio::test]
async fn connecting_to_a_server_that_never_answers_gives_up() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            held.push(socket);
        }
    });

    let started = Instant::now();
    let attempt = tokio::time::timeout(
        Duration::from_secs(10),
        Connection::connect_with_timeout(&format!("ws://{addr}/v1/ws"), Duration::from_secs(1)),
    )
    .await;
    let Ok(result) = attempt else {
        panic!(
            "VULNERABILITY: connecting to a server that accepts but never answers was still \
             waiting after 10s"
        );
    };
    assert!(matches!(result, Err(NetError::Connection(_))));
    assert!(started.elapsed() < Duration::from_secs(5));
}
