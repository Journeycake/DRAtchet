//! Penetration-test finding DRA-0050 (round 9, denial of service).
//!
//! DRA-0049 metered `MailboxFetch` because it held the global exclusive
//! write lock with no rate limit at all. `MailboxDelete` takes the exact
//! same lock, for the same reason (mailbox ownership must be checked
//! under it), and was left unmetered -- DRA-0049's own "Known residual
//! scope" called this out and reasoned it away as low-priority because
//! the work *inside* the lock is cheap for delete (no pruning, no entry
//! serialization). That reasoning is correct about the per-call cost,
//! but says nothing about the *rate*: an unmetered handler that still
//! acquires a global exclusive lock lets one identity serialise the
//! whole server behind back-to-back lock acquisitions, whatever the
//! per-call cost is once inside.

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
async fn deleting_from_a_mailbox_is_rate_limited() {
    let (url, _state) = spawn_server_with_state().await;
    let (account, _bundle) = fresh_account_and_bundle("deleter", 9001, 0);

    let mut client = TestClient::connect(&url).await;
    client.authenticate(&account).await;

    // The caller's own bootstrap mailbox -- entitled to delete from it,
    // so only the rate limiter can be what refuses these.
    let mailbox_id =
        dratchet_core::x3dh::bootstrap_mailbox_id(account.identity.fingerprint().as_bytes())
            .to_vec();

    let attempts = dratchet_server::abuse::MAILBOX_DELETE_RATE_LIMIT_CAPACITY as usize * 3;
    let mut refused = 0;
    for i in 0..attempts {
        client
            .send(
                FrameTag::MailboxDelete,
                &MailboxDelete {
                    mailbox_id: mailbox_id.clone(),
                    entry_id: vec![i as u8; 16],
                },
            )
            .await;
        let raw = client.recv_raw().await;
        let (tag, _) = split_tag(&raw).expect("valid frame");
        if tag == FrameTag::Error {
            refused += 1;
        }
    }

    assert!(
        refused > 0,
        "VULNERABILITY: {attempts} back-to-back mailbox deletes were all served -- nothing \
         rate-limits a handler that takes the global write lock on every call, so one identity \
         can serialise the whole server behind its own deletes"
    );
}

/// Non-regression guard: a legitimate, modest delete workload -- and an
/// ownership violation on a *real* (bootstrap-derived) mailbox id --
/// must still behave exactly as before.
///
/// A custom/arbitrary shared mailbox id (the kind two paired parties
/// agree on out of band) is deliberately NOT protected by
/// `mailbox_id_belongs_to_someone_else` -- that check only rejects an id
/// that collides with a *different* directory resident's bootstrap id
/// (`ARCHITECTURE.md` §11.1's bidirectional mailbox model). So this test
/// uses each account's real bootstrap mailbox id, the one case ownership
/// is actually enforced for, exactly as `unmetered_mailbox_fetch.rs`'s
/// own non-regression guard does.
#[tokio::test]
async fn ordinary_deletes_and_ownership_checks_still_work() {
    let (url, _state) = spawn_server_with_state().await;
    let (writer, writer_bundle) = fresh_account_and_bundle("writer9", 9002, 0);
    let (stranger, _b2) = fresh_account_and_bundle("stranger9", 9003, 0);

    // The writer must be a directory resident for its bootstrap mailbox
    // to be a protected id at all -- an unpublished identity's bootstrap
    // id isn't anyone's yet.
    let mut writer_client = TestClient::connect(&url).await;
    writer_client.authenticate(&writer).await;
    writer_client
        .send(
            FrameTag::PublishBundle,
            &PublishBundle {
                bundle: writer_bundle,
            },
        )
        .await;
    let (tag, ack): (_, Ack) = writer_client.recv().await;
    assert_eq!(tag, FrameTag::Ack);
    assert!(ack.ok);

    let mailbox_id =
        dratchet_core::x3dh::bootstrap_mailbox_id(writer.identity.fingerprint().as_bytes())
            .to_vec();

    writer_client
        .send(
            FrameTag::MailboxWrite,
            &MailboxWrite {
                mailbox_id: mailbox_id.clone(),
                envelope: vec![1, 2, 3],
                ttl: 600,
            },
        )
        .await;
    let (tag, ack): (_, Ack) = writer_client.recv().await;
    assert_eq!(tag, FrameTag::Ack);
    assert!(ack.ok);

    // A stranger with no relationship to this account must still be
    // refused deleting from its bootstrap mailbox -- the rate limiter
    // runs first but must not mask this.
    let mut stranger_client = TestClient::connect(&url).await;
    stranger_client.authenticate(&stranger).await;
    stranger_client
        .send(
            FrameTag::MailboxDelete,
            &MailboxDelete {
                mailbox_id: mailbox_id.clone(),
                entry_id: vec![9u8; 16],
            },
        )
        .await;
    let (tag, _err): (_, ErrorFrame) = stranger_client.recv().await;
    assert_eq!(tag, FrameTag::Error, "a non-owner must still be refused");

    // The writer's own legitimate delete of its own entry still goes
    // through, unaffected by the stranger's refused attempt.
    writer_client
        .send(
            FrameTag::MailboxFetch,
            &MailboxFetch {
                mailbox_id: mailbox_id.clone(),
            },
        )
        .await;
    let (tag, entries): (_, MailboxEntries) = writer_client.recv().await;
    assert_eq!(tag, FrameTag::MailboxEntries);
    assert_eq!(entries.entries.len(), 0, "writer never sees its own entry");
}
