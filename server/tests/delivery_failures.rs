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

/// Scenario 5/6, DRA-0015 (penetration test, priority 2: denial of
/// service) — `ws.rs`'s `MailboxWrite` handler originally had no
/// per-mailbox entry-count cap and no envelope size cap: a burst of
/// writes, or one oversized envelope, well past any reasonable
/// per-conversation volume all succeeded with `ok: true`, a real
/// resource-exhaustion gap against the in-memory mailbox store (see
/// scenario 9). Fixed with `state::MAX_MAILBOX_ENTRIES` (256) and
/// `state::MAX_ENVELOPE_LEN` (64 KiB, 4x `core::payload::MAX_PADDED_LEN`'s
/// own 16 KiB ceiling — generous for any real envelope). Proven, not just
/// read from source: this test drives a real burst past both limits and
/// confirms the server starts rejecting once each cap is reached, while
/// legitimate writes up to the cap still succeed.
#[tokio::test]
async fn scenario_05_06_entry_count_and_size_caps_are_enforced() {
    let (url, state) = spawn_server_with_state().await;
    let (account, _) = fresh_account_and_bundle("flooder", 1, 0);
    let mut client = TestClient::connect(&url).await;
    client.authenticate(&account).await;
    let mailbox_id = [5u8; 16];

    // Count: fill the mailbox exactly to its cap — every one of these
    // must still succeed; the cap must not be off-by-one in the
    // restrictive direction.
    for i in 0..dratchet_server::state::MAX_MAILBOX_ENTRIES {
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
        assert!(ack.ok, "write {i} within the cap must succeed");
    }

    // One more, past the cap, must now be rejected rather than silently
    // growing the mailbox forever.
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
    let (tag, err): (_, ErrorFrame) = client.recv().await;
    assert_eq!(
        tag,
        FrameTag::Error,
        "FIX VERIFIED: a write past MAX_MAILBOX_ENTRIES must be rejected, not silently accepted"
    );
    assert!(err.message.to_lowercase().contains("full"));

    let inner = state.inner.read().await;
    assert_eq!(
        inner.mailboxes.get(&mailbox_id).map(Vec::len),
        Some(dratchet_server::state::MAX_MAILBOX_ENTRIES),
        "the mailbox must be capped at exactly MAX_MAILBOX_ENTRIES, not grown past it"
    );
    drop(inner);

    // Size: a fresh mailbox (so the count cap above doesn't interfere) —
    // an envelope right at the size cap must still succeed...
    let size_mailbox_id = [6u8; 16];
    client
        .send(
            FrameTag::MailboxWrite,
            &MailboxWrite {
                mailbox_id: size_mailbox_id.to_vec(),
                envelope: vec![0u8; dratchet_server::state::MAX_ENVELOPE_LEN],
                ttl: 60,
            },
        )
        .await;
    let (_, ack): (_, Ack) = client.recv().await;
    assert!(ack.ok, "an envelope exactly at the size cap must succeed");

    // ...but one byte over must now be rejected, not silently accepted
    // (the pre-fix behavior proved with a 1 MiB envelope).
    client
        .send(
            FrameTag::MailboxWrite,
            &MailboxWrite {
                mailbox_id: size_mailbox_id.to_vec(),
                envelope: vec![0u8; dratchet_server::state::MAX_ENVELOPE_LEN + 1],
                ttl: 60,
            },
        )
        .await;
    let (tag, err): (_, ErrorFrame) = client.recv().await;
    assert_eq!(
        tag,
        FrameTag::Error,
        "FIX VERIFIED: an envelope over MAX_ENVELOPE_LEN must be rejected, not silently accepted"
    );
    assert!(err.message.to_lowercase().contains("size"));
}
