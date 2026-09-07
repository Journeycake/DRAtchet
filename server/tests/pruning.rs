//! Real end-to-end proof of `dratchet_server::pruning` (`server/src/pruning.rs`):
//! a mailbox entry that's written but never fetched again still gets
//! cleaned up, because the periodic sweep — not just the on-fetch
//! `prune_expired` call in `ws.rs::MailboxFetch` — is what catches it.
//! Mirrors `server/tests/breach.rs`'s style of inspecting the real,
//! running server's `AppState` directly, not just client-observable
//! behavior.

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

#[tokio::test]
async fn a_mailbox_entry_that_is_never_fetched_is_still_pruned_by_the_periodic_sweep() {
    let (url, state) = spawn_server_with_state().await;
    let (account, _bundle) = fresh_account_and_bundle("alice", 1, 0);

    let mut client = TestClient::connect(&url).await;
    client.authenticate(&account).await;

    let mailbox_id = [42u8; 16];
    client
        .send(
            FrameTag::MailboxWrite,
            &MailboxWrite {
                mailbox_id: mailbox_id.to_vec(),
                envelope: vec![1, 2, 3],
                ttl: 1, // 1 second — expires almost immediately
            },
        )
        .await;
    let (tag, ack): (_, Ack) = client.recv().await;
    assert_eq!(tag, FrameTag::Ack);
    assert!(ack.ok);

    // Confirm the entry is really there before the sweep has had any
    // chance to run — otherwise this test would trivially pass.
    {
        let inner = state.inner.read().await;
        assert_eq!(
            inner.mailboxes.get(&mailbox_id).map(Vec::len),
            Some(1),
            "the written entry should be present immediately after the write"
        );
    }

    // Short, test-scale durations — `main.rs` uses real minutes-scale
    // values in production, but `spawn_pruning_sweep` takes them as
    // parameters exactly so tests don't have to wait for those.
    dratchet_server::pruning::spawn_pruning_sweep(
        state.clone(),
        Duration::from_millis(50),
        Duration::from_secs(600),
    );

    // Past both the entry's 1-second TTL and several sweep intervals.
    tokio::time::sleep(Duration::from_millis(1_500)).await;

    let inner = state.inner.read().await;
    assert!(
        !inner.mailboxes.contains_key(&mailbox_id),
        "a mailbox that's written but never fetched again must still be pruned by the \
         periodic sweep, not just by the on-fetch prune_expired call in ws.rs"
    );
}
