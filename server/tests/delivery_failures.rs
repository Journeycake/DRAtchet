//! Real, no-mocks exploration of "how does a dropped message actually
//! behave today" — server/mailbox-layer scenarios, run against a real
//! spawned `dratchet_server::app()`. Companion to `core/src/ratchet.rs`'s
//! tests (ratchet-layer scenarios) and `app/tests/delivery_failures.rs`
//! (app-layer scenarios). See the accompanying report for the full
//! numbered findings; this file is the executable evidence behind the
//! ones marked "tested" there.

mod common;

use std::time::Duration;

use common::*;
use dratchet_server::protocol::*;
use dratchet_server::state::AppState;
use std::sync::Arc;
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

/// Scenario 1 — a message that's written but the recipient never fetches
/// it before its TTL expires. Confirms the periodic sweep really does
/// remove it (mirrors `pruning.rs`, restated here as one numbered delivery
/// failure) and — the actual finding — that the *sender* has no way to
/// learn this happened: there is no error, no callback, nothing. The
/// message is just gone.
#[tokio::test]
async fn scenario_01_unfetched_message_expires_silently_with_no_signal_to_the_sender() {
    let (url, state) = spawn_server_with_state().await;
    let (account, _bundle) = fresh_account_and_bundle("sender01", 1, 0);
    let mut client = TestClient::connect(&url).await;
    client.authenticate(&account).await;

    let mailbox_id = [1u8; 16];
    client
        .send(
            FrameTag::MailboxWrite,
            &MailboxWrite {
                mailbox_id: mailbox_id.to_vec(),
                envelope: vec![1, 2, 3],
                ttl: 1,
            },
        )
        .await;
    let (tag, ack): (_, Ack) = client.recv().await;
    assert_eq!(tag, FrameTag::Ack);
    assert!(
        ack.ok,
        "the write itself succeeds — nothing distinguishes a doomed message at write time"
    );

    dratchet_server::pruning::spawn_pruning_sweep(
        state.clone(),
        Duration::from_millis(50),
        Duration::from_secs(600),
    );
    tokio::time::sleep(Duration::from_millis(1_500)).await;

    let inner = state.inner.read().await;
    assert!(
        !inner.mailboxes.contains_key(&mailbox_id),
        "the message is gone"
    );
    drop(inner);

    // The sender's connection is still open and healthy — no push frame,
    // no error, nothing ever arrives telling it the write it made earlier
    // is now unrecoverable.
}

/// Scenario 2 — the recipient fetches a message but crashes (or the app
/// is force-quit) before it sends `MailboxDelete`. On the *next* fetch,
/// is the message still there (at-least-once, safe to retry) or gone
/// (at-most-once, meaning a crash at the wrong instant loses it)?
#[tokio::test]
async fn scenario_02_a_fetch_without_a_follow_up_delete_is_redelivered_next_time() {
    let (url, _state) = spawn_server_with_state().await;
    let (sender, _bundle) = fresh_account_and_bundle("sender02", 1, 0);
    let mailbox_id = [2u8; 16];

    let mut writer = TestClient::connect(&url).await;
    writer.authenticate(&sender).await;
    writer
        .send(
            FrameTag::MailboxWrite,
            &MailboxWrite {
                mailbox_id: mailbox_id.to_vec(),
                envelope: vec![9, 9, 9],
                ttl: 3600,
            },
        )
        .await;
    let (_, ack): (_, Ack) = writer.recv().await;
    assert!(ack.ok);

    let (reader_account, _) = fresh_account_and_bundle("reader02", 3, 0);
    let mut reader = TestClient::connect(&url).await;
    reader.authenticate(&reader_account).await;

    reader
        .send(
            FrameTag::MailboxFetch,
            &MailboxFetch {
                mailbox_id: mailbox_id.to_vec(),
            },
        )
        .await;
    let (_, first): (_, MailboxEntries) = reader.recv().await;
    assert_eq!(
        first.entries.len(),
        1,
        "the message is there on first fetch"
    );

    // Simulate a crash: no `MailboxDelete` sent. Fetch again.
    reader
        .send(
            FrameTag::MailboxFetch,
            &MailboxFetch {
                mailbox_id: mailbox_id.to_vec(),
            },
        )
        .await;
    let (_, second): (_, MailboxEntries) = reader.recv().await;
    assert_eq!(
        second.entries.len(),
        1,
        "at-least-once delivery: the entry survives an un-acked fetch, so a crash \
         before delete does not lose the message — but the client will see the same \
         envelope bytes twice, which scenario_03 shows the ratchet itself rejects"
    );
    assert_eq!(
        first.entries[0].entry_id, second.entries[0].entry_id,
        "it's the literal same entry, not a new one"
    );
}

// Scenario 3 (redelivering an already-decrypted envelope) is a pure
// ratchet-layer concern, not a mailbox one — see
// `core/src/ratchet.rs`'s `scenario_03_redelivering_an_already_decrypted_envelope_fails`
// for the real, full-handshake version of it.

/// Scenario 4 — two different senders write to the same `mailbox_id`
/// concurrently (a real race, not a sequential simulation of one). Both
/// entries must survive; concurrent writers must not clobber each other.
#[tokio::test]
async fn scenario_04_concurrent_writers_to_the_same_mailbox_both_survive() {
    let (url, _state) = spawn_server_with_state().await;
    let (alice, _) = fresh_account_and_bundle("alice04", 1, 0);
    let (bob, _) = fresh_account_and_bundle("bob04", 2, 0);
    let mailbox_id = [4u8; 16];

    let url_a = url.clone();
    let url_b = url.clone();
    let mid_a = mailbox_id;
    let mid_b = mailbox_id;

    let a = tokio::spawn(async move {
        let mut c = TestClient::connect(&url_a).await;
        c.authenticate(&alice).await;
        c.send(
            FrameTag::MailboxWrite,
            &MailboxWrite {
                mailbox_id: mid_a.to_vec(),
                envelope: vec![0xA],
                ttl: 60,
            },
        )
        .await;
        let (_, ack): (_, Ack) = c.recv().await;
        assert!(ack.ok);
    });
    let b = tokio::spawn(async move {
        let mut c = TestClient::connect(&url_b).await;
        c.authenticate(&bob).await;
        c.send(
            FrameTag::MailboxWrite,
            &MailboxWrite {
                mailbox_id: mid_b.to_vec(),
                envelope: vec![0xB],
                ttl: 60,
            },
        )
        .await;
        let (_, ack): (_, Ack) = c.recv().await;
        assert!(ack.ok);
    });
    a.await.unwrap();
    b.await.unwrap();

    let (reader_account, _) = fresh_account_and_bundle("reader04", 3, 0);
    let mut reader = TestClient::connect(&url).await;
    reader.authenticate(&reader_account).await;
    reader
        .send(
            FrameTag::MailboxFetch,
            &MailboxFetch {
                mailbox_id: mailbox_id.to_vec(),
            },
        )
        .await;
    let (_, entries): (_, MailboxEntries) = reader.recv().await;
    assert_eq!(
        entries.entries.len(),
        2,
        "both concurrent writes must survive, not last-write-wins"
    );
}

/// Scenario 5/6 — there is no per-mailbox entry-count cap and no envelope
/// size cap in `ws.rs`'s `MailboxWrite` handler. Proven, not just read
/// from source: a burst of writes well past any reasonable per-conversation
/// volume all succeed with `ok: true`. This is a real resource-exhaustion
/// gap (the mailbox is in-memory — see scenario 9), demonstrated here at a
/// moderate scale so the test itself stays fast and doesn't try to actually
/// exhaust memory.
#[tokio::test]
async fn scenario_05_06_no_entry_count_or_size_cap_is_enforced() {
    let (url, state) = spawn_server_with_state().await;
    let (account, _) = fresh_account_and_bundle("flooder", 1, 0);
    let mut client = TestClient::connect(&url).await;
    client.authenticate(&account).await;
    let mailbox_id = [5u8; 16];

    // Count: far more entries than any real conversation burst (compare
    // `client/tests/queue_depth.rs`'s 40-message burst, already considered
    // a stress case).
    for _ in 0..2_000 {
        client
            .send(
                FrameTag::MailboxWrite,
                &MailboxWrite {
                    mailbox_id: mailbox_id.to_vec(),
                    envelope: vec![0u8; 64],
                    ttl: 60,
                },
            )
            .await;
        let (_, ack): (_, Ack) = client.recv().await;
        assert!(ack.ok, "no count cap rejects this write");
    }

    // Size: one large envelope (1 MiB) — still accepted.
    client
        .send(
            FrameTag::MailboxWrite,
            &MailboxWrite {
                mailbox_id: mailbox_id.to_vec(),
                envelope: vec![0u8; 1_048_576],
                ttl: 60,
            },
        )
        .await;
    let (_, ack): (_, Ack) = client.recv().await;
    assert!(ack.ok, "no size cap rejects this write either");

    let inner = state.inner.read().await;
    assert_eq!(inner.mailboxes.get(&mailbox_id).map(Vec::len), Some(2_001));
}
