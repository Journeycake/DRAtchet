//! Penetration-test finding DRA-0049 (round 8, denial of service).
//!
//! `ws.rs`'s `MailboxFetch` arm has no rate limit of any kind, and every
//! call takes the GLOBAL `Inner` WRITE lock and, inside it, runs
//! `mailbox_id_belongs_to_someone_else` -- which scans every key in the
//! directory. `MailboxWrite` is metered (DRA-0018), `FetchBundle` is
//! metered, and DRA-0045 metered the rendezvous relay; the fetch path was
//! left as the one unmetered handler, and it happens to be the most
//! expensive one per call.
//!
//! DRA-0046 closed the allocation a fetch caused and recorded the request
//! cost itself as still open. This is that follow-up.
//!
//! Because the lock is exclusive and the scan is O(directory), a single
//! authenticated identity issuing fetches back to back serialises the
//! whole server behind its own directory scans -- every other client's
//! writes, fetches and presence updates queue behind them. The directory
//! is never pruned (`pruning.rs`), so the per-call cost only ever grows.

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
async fn fetching_a_mailbox_is_rate_limited() {
    let (url, _state) = spawn_server_with_state().await;
    let (account, _bundle) = fresh_account_and_bundle("fetcher", 8001, 0);

    let mut client = TestClient::connect(&url).await;
    client.authenticate(&account).await;

    // A mailbox this caller is entitled to read -- so the only thing that
    // can refuse these is the rate limiter, not the ownership check.
    let mailbox_id = vec![0x11u8; 16];

    let attempts = dratchet_server::abuse::MAILBOX_FETCH_RATE_LIMIT_CAPACITY as usize * 3;
    let mut refused = 0;
    for _ in 0..attempts {
        client
            .send(
                FrameTag::MailboxFetch,
                &MailboxFetch {
                    mailbox_id: mailbox_id.clone(),
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
        "VULNERABILITY: {attempts} back-to-back mailbox fetches were all served -- nothing \
         rate-limits a handler that takes the global write lock and scans the entire directory \
         on every call, so one identity can serialise the whole server behind its own fetches"
    );
}

/// The non-regression half: the ownership check must keep working, and
/// keep working correctly with a populated directory — the fix replaces a
/// linear scan with an index, and an index that drifts from the directory
/// would silently stop protecting anyone.
#[tokio::test]
async fn ownership_is_still_enforced_against_a_populated_directory() {
    let (url, _state) = spawn_server_with_state().await;

    // Several real directory residents, so the lookup has to pick the
    // right one rather than trivially matching the only entry.
    let mut residents = Vec::new();
    for i in 0..5u16 {
        let (account, bundle) = fresh_account_and_bundle(&format!("resident{i}"), 8100 + i, 0);
        let mut c = TestClient::connect(&url).await;
        c.authenticate(&account).await;
        c.send(FrameTag::PublishBundle, &PublishBundle { bundle })
            .await;
        let (tag, ack): (_, Ack) = c.recv().await;
        assert_eq!(tag, FrameTag::Ack);
        assert!(ack.ok);
        residents.push((account, c));
    }

    // A stranger tries to read resident 3's bootstrap mailbox.
    let victim_fp: [u8; 32] = *residents[3].0.identity.fingerprint().as_bytes();
    let victim_bootstrap = dratchet_core::x3dh::bootstrap_mailbox_id(&victim_fp);

    let intruder = dratchet_core::account::Account::generate().unwrap();
    let mut intruder_client = TestClient::connect(&url).await;
    intruder_client.authenticate(&intruder).await;
    intruder_client
        .send(
            FrameTag::MailboxFetch,
            &MailboxFetch {
                mailbox_id: victim_bootstrap.to_vec(),
            },
        )
        .await;
    let (tag, _err): (_, ErrorFrame) = intruder_client.recv().await;
    assert_eq!(
        tag,
        FrameTag::Error,
        "a stranger must still be refused another account's bootstrap mailbox (DRA-0014)"
    );

    // And the rightful owner must still be able to read their own.
    let (owner_account, mut owner_client) = residents.remove(3);
    let own_bootstrap =
        dratchet_core::x3dh::bootstrap_mailbox_id(owner_account.identity.fingerprint().as_bytes());
    owner_client
        .send(
            FrameTag::MailboxFetch,
            &MailboxFetch {
                mailbox_id: own_bootstrap.to_vec(),
            },
        )
        .await;
    let (tag, entries): (_, MailboxEntries) = owner_client.recv().await;
    assert_eq!(
        tag,
        FrameTag::MailboxEntries,
        "the rightful owner must still be able to read their own bootstrap mailbox"
    );
    assert!(entries.entries.is_empty());
}
