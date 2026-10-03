//! DRA-0055 (residual-scope follow-up to DRA-0031, DRA-0044 and DRA-0050):
//! nothing limited connections per source address.
//!
//! DRA-0031's cap is global, so one address could fill all of it.
//! Authentication is self-certifying, so every connection can come online
//! as a brand-new identity, which walks straight past every per-identity
//! limiter (DRA-0050) and piles up throwaway state between pruning sweeps
//! (DRA-0044). The one thing a client can't mint for free is its network
//! address.
//!
//! These tests serve the router with connect info, as `src/main.rs` does,
//! so `ws_handler` sees each connection's peer address. Every connection
//! here comes from 127.0.0.1, i.e. one address.

mod common;

use std::net::SocketAddr;

use common::*;
use dratchet_server::address::{MAX_CONNECTIONS_PER_ADDRESS, NEW_CONNECTIONS_PER_ADDRESS_CAPACITY};
use tokio::net::TcpListener;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Error as WsError;

async fn spawn_server_with_peer_addresses() -> String {
    let (router, _state) = dratchet_server::app();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .expect("server task");
    });
    format!("ws://{addr}/v1/ws")
}

/// The refusal body for a connect attempt the server turned away, or
/// `None` if the upgrade went through.
fn refusal_body<S>(result: &Result<S, WsError>) -> Option<String> {
    match result {
        Ok(_) => None,
        Err(WsError::Http(response)) => Some(
            response
                .body()
                .as_ref()
                .map(|b| String::from_utf8_lossy(b).into_owned())
                .unwrap_or_default(),
        ),
        Err(e) => Some(format!("{e}")),
    }
}

#[tokio::test]
async fn one_address_cannot_hold_an_unbounded_share_of_connections() {
    let url = spawn_server_with_peer_addresses().await;

    // Held open for the whole test, so none of their slots are released.
    let mut held = Vec::new();
    for i in 0..MAX_CONNECTIONS_PER_ADDRESS {
        held.push(
            connect_async(&url)
                .await
                .unwrap_or_else(|e| panic!("connection {i} within the limit failed: {e}")),
        );
    }

    let one_more = connect_async(&url).await;
    let refusal = refusal_body(&one_more);
    assert!(
        refusal
            .as_deref()
            .is_some_and(|body| body.contains("concurrent")),
        "VULNERABILITY: address held {} connections and was still admitted another \
         (refusal: {refusal:?}) -- one source can fill DRA-0031's whole global cap",
        MAX_CONNECTIONS_PER_ADDRESS
    );
    drop(held);
}

#[tokio::test]
async fn one_address_cannot_mint_identities_as_fast_as_it_can_connect() {
    let url = spawn_server_with_peer_addresses().await;
    let attempts = NEW_CONNECTIONS_PER_ADDRESS_CAPACITY as usize * 2;

    let mut refused_for_rate = 0;
    for i in 0..attempts {
        let result = connect_async(&url).await;
        match refusal_body(&result) {
            Some(body) => {
                if body.contains("too fast") {
                    refused_for_rate += 1;
                }
            }
            None => {
                // Each admitted connection comes online as a fresh
                // identity, then leaves -- exactly the churn the
                // per-identity limiters can't see.
                let (ws, _) = result.unwrap();
                let mut client = TestClient::from_stream(ws);
                let (account, _bundle) = fresh_account_and_bundle("churn", 7000 + i as u16, 0);
                client.authenticate(&account).await;
                client.close().await;
            }
        }
    }

    assert!(
        refused_for_rate > 0,
        "VULNERABILITY: {attempts} back-to-back connections from one address each came online \
         as a new identity with none refused -- identities are free, so every per-identity \
         limiter is bypassed"
    );
}

/// Guard: ordinary use from one address -- several devices behind one
/// NAT, each connecting and authenticating -- is unaffected.
#[tokio::test]
async fn several_clients_behind_one_address_still_connect_and_authenticate() {
    let url = spawn_server_with_peer_addresses().await;
    let mut clients = Vec::new();
    for i in 0..5u16 {
        let mut client = TestClient::connect(&url).await;
        let (account, _bundle) = fresh_account_and_bundle("nat", 7100 + i, 0);
        client.authenticate(&account).await;
        clients.push(client);
    }
    // And a reconnect after closing one still works.
    clients.pop().unwrap().close().await;
    let mut again = TestClient::connect(&url).await;
    let (account, _bundle) = fresh_account_and_bundle("nat", 7199, 0);
    again.authenticate(&account).await;
}
