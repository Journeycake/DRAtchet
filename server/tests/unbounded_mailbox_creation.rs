//! Penetration-test finding, DRA-0018 (round 2, priority 3: denial of
//! service against *all clients*, i.e. the server itself), following up
//! on the residual scope DRA-0015 already named but didn't close:
//! `MAX_MAILBOX_ENTRIES`/`MAX_ENTRIES_PER_WRITER_PER_MAILBOX` (DRA-0015/
//! DRA-0017) bound how much one *existing* mailbox can hold, but nothing
//! bounds how many *distinct* mailbox ids `Inner::mailboxes` can ever
//! hold at once. `MailboxWrite` requires no pre-existing relationship —
//! any authenticated identity can write to any 16-byte `mailbox_id`,
//! and a not-yet-seen id is inserted via `.entry(mailbox_id).or_default()`
//! with no check on the total number of keys already tracked.
//!
//! A single connection, looping `MailboxWrite` with a fresh random
//! `mailbox_id` each time, can therefore make the server allocate an
//! unbounded number of `HashMap` entries — each one, at the
//! `MAX_ENTRIES_PER_WRITER_PER_MAILBOX` cap, capable of holding up to
//! `MAX_ENTRIES_PER_WRITER_PER_MAILBOX * MAX_ENVELOPE_LEN` bytes (8 MiB).
//! This is not bounded by anything a legitimate client's usage pattern
//! would ever approach (a real client only ever writes to its own
//! bootstrap mailbox and the routing-id-derived mailboxes for contacts
//! it has actually paired with — at most a handful of distinct ids ever,
//! not thousands per second), and it affects every other client on the
//! server, not just one conversation — real memory exhaustion taking the
//! whole service down, not a single mailbox.
//!
//! Pre-fix, this test proved the *rate* of new-mailbox creation was
//! unthrottled: a burst of writes to freshly-random mailbox ids, well
//! past any real client's behavior, all succeeded immediately.
//!
//! **Fixed**: `crate::abuse::NewMailboxRateLimiter` (mirroring the
//! existing `FetchRateLimiter` exactly) gates how fast one authenticated
//! identity can originate brand-new mailbox ids — a token bucket
//! consumed only when the target `mailbox_id` doesn't already exist, so
//! ordinary traffic within an already-established conversation is
//! completely unaffected. This test now proves the fix: a burst up to
//! the bucket's capacity still succeeds immediately (real usage, e.g.
//! adding several new contacts at once, is never throttled), but the
//! next one is rejected.

mod common;

use std::sync::Arc;

use common::*;
use dratchet_core::account::Account;
use dratchet_server::protocol::*;
use dratchet_server::state::AppState;
use rand_core::{OsRng, RngCore};
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
async fn a_single_connection_cannot_create_unbounded_distinct_mailboxes() {
    let (url, state) = spawn_server_with_state().await;

    let attacker = Account::generate().unwrap();
    let mut conn = TestClient::connect(&url).await;
    conn.authenticate(&attacker).await;

    // A burst right up to the rate limiter's own capacity must still
    // succeed immediately -- real usage (e.g. adding several new
    // contacts at once) is never throttled. Keep the first id created,
    // to prove afterward that writing into an already-existing mailbox
    // is never affected by this limiter.
    let capacity = dratchet_server::abuse::NEW_MAILBOX_RATE_LIMIT_CAPACITY as usize;
    let mut first_mailbox_id = [0u8; 16];
    for i in 0..capacity {
        let mut mailbox_id = [0u8; 16];
        OsRng.fill_bytes(&mut mailbox_id);
        if i == 0 {
            first_mailbox_id = mailbox_id;
        }
        conn.send(
            FrameTag::MailboxWrite,
            &MailboxWrite {
                mailbox_id: mailbox_id.to_vec(),
                envelope: vec![0u8; 64],
                ttl: 3600,
            },
        )
        .await;
        let (_, ack): (_, Ack) = conn.recv().await;
        assert!(ack.ok, "write {i} within the burst capacity must succeed");
    }
    assert_eq!(state.inner.read().await.mailboxes.len(), capacity);

    // One more brand-new mailbox id, past the burst capacity, must now
    // be rejected -- this is the fix: no more unthrottled creation.
    let mut new_mailbox_id = [0u8; 16];
    OsRng.fill_bytes(&mut new_mailbox_id);
    conn.send(
        FrameTag::MailboxWrite,
        &MailboxWrite {
            mailbox_id: new_mailbox_id.to_vec(),
            envelope: vec![0u8; 64],
            ttl: 3600,
        },
    )
    .await;
    let (tag, err): (_, ErrorFrame) = conn.recv().await;
    assert_eq!(
        tag,
        FrameTag::Error,
        "FIX VERIFIED: a new mailbox past the rate limiter's burst capacity must be rejected, \
         closing the unbounded server-wide memory exhaustion this test originally demonstrated"
    );
    assert!(err.message.to_lowercase().contains("rate limit"));
    assert_eq!(
        state.inner.read().await.mailboxes.len(),
        capacity,
        "the rejected write must not have created a new mailbox entry"
    );

    // Writing again into an *already-existing* mailbox never touches
    // this budget at all -- ordinary conversation traffic is unaffected
    // even after the new-mailbox rate limit has been hit.
    conn.send(
        FrameTag::MailboxWrite,
        &MailboxWrite {
            mailbox_id: first_mailbox_id.to_vec(),
            envelope: vec![0u8; 64],
            ttl: 3600,
        },
    )
    .await;
    let (tag, ack): (_, Ack) = conn.recv().await;
    assert_eq!(
        tag,
        FrameTag::Ack,
        "a write into an already-existing mailbox must never be blocked by the new-mailbox \
         rate limiter, even once that limiter's own budget is exhausted"
    );
    assert!(ack.ok);
}
