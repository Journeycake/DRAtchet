//! Penetration-test finding DRA-0046 (round 7, denial of service --
//! a read operation with a write side effect).
//!
//! `ws.rs`'s `MailboxFetch` arm reached its entry list with
//! `inner.mailboxes.entry(mailbox_id).or_default()`. `or_default()`
//! *inserts*, so merely asking whether a mailbox has anything in it
//! created that mailbox -- for any 16-byte id the caller cared to name.
//!
//! That matters because originating a brand-new mailbox id is exactly
//! what DRA-0018's `NewMailboxRateLimiter` exists to meter, and it is
//! wired into `MailboxWrite` only. `MailboxFetch` has no rate limit of
//! any kind, so the cheapest path to creating unbounded server-side
//! mailbox state ran straight around the limiter built to stop it.
//!
//! `mailbox_id_belongs_to_someone_else` is no help: it rejects only ids
//! that are the *bootstrap* id of some other directory resident. Every
//! other id in the 2^128 space -- including every random one -- passes.

mod common;

use std::sync::Arc;

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
async fn fetching_a_mailbox_that_does_not_exist_does_not_create_it() {
    let (url, state) = spawn_server_with_state().await;
    let (account, _bundle) = fresh_account_and_bundle("reader", 7001, 0);

    let mut client = TestClient::connect(&url).await;
    client.authenticate(&account).await;

    // Ids the attacker simply made up. None is any account's bootstrap
    // id, so the ownership check waves every one of them through.
    const INVENTED: usize = 64;
    for i in 0..INVENTED {
        let mut mailbox_id = [0u8; 16];
        mailbox_id[0] = 0xF0;
        mailbox_id[1..9].copy_from_slice(&(i as u64).to_be_bytes());
        client
            .send(
                FrameTag::MailboxFetch,
                &MailboxFetch {
                    mailbox_id: mailbox_id.to_vec(),
                },
            )
            .await;
        let (tag, entries): (_, MailboxEntries) = client.recv().await;
        assert_eq!(tag, FrameTag::MailboxEntries);
        assert!(
            entries.entries.is_empty(),
            "a mailbox nobody ever wrote to must read back empty"
        );
    }

    let inner = state.inner.read().await;
    assert_eq!(
        inner.mailboxes.len(),
        0,
        "VULNERABILITY: {INVENTED} fetches of ids that never existed left {} mailboxes behind -- \
         `MailboxFetch` creates the mailbox it reads, so an unmetered read is the cheapest way \
         to allocate server state, going straight around DRA-0018's new-mailbox rate limiter on \
         the write path",
        inner.mailboxes.len(),
    );
}

/// The fix must not change what a fetch actually returns: a real mailbox
/// with a real entry still reads back normally, and is still there
/// afterwards.
#[tokio::test]
async fn a_real_mailbox_still_fetches_normally() {
    let (url, state) = spawn_server_with_state().await;
    let (writer, _b1) = fresh_account_and_bundle("writer", 7002, 0);
    let (reader, _b2) = fresh_account_and_bundle("recipient", 7003, 0);

    let mailbox_id = [0x5Au8; 16];

    let mut writer_client = TestClient::connect(&url).await;
    writer_client.authenticate(&writer).await;
    writer_client
        .send(
            FrameTag::MailboxWrite,
            &MailboxWrite {
                mailbox_id: mailbox_id.to_vec(),
                envelope: vec![9, 9, 9],
                ttl: 600,
            },
        )
        .await;
    let (tag, ack): (_, Ack) = writer_client.recv().await;
    assert_eq!(tag, FrameTag::Ack);
    assert!(ack.ok);

    let mut reader_client = TestClient::connect(&url).await;
    reader_client.authenticate(&reader).await;
    reader_client
        .send(
            FrameTag::MailboxFetch,
            &MailboxFetch {
                mailbox_id: mailbox_id.to_vec(),
            },
        )
        .await;
    let (tag, entries): (_, MailboxEntries) = reader_client.recv().await;
    assert_eq!(tag, FrameTag::MailboxEntries);
    assert_eq!(entries.entries.len(), 1, "the real entry must still arrive");
    assert_eq!(entries.entries[0].envelope, vec![9, 9, 9]);

    assert!(
        state.inner.read().await.mailboxes.contains_key(&mailbox_id),
        "a genuinely written mailbox must survive being fetched"
    );
}
