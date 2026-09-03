//! Concurrency / load test against the real, running service — many
//! simultaneous clients hammering publish/fetch/mailbox/presence/rendezvous
//! at once, per the Phase 1.1 instruction to stress-test before moving on.
//!
//! Not a benchmark (no throughput numbers are asserted as a requirement) —
//! it's a correctness-under-load check: every response is validated exactly
//! as strictly as the sequential integration tests, just interleaved across
//! many concurrent connections sharing one `AppState` behind its `RwLock`.
//! A generous wall-clock ceiling guards against a pathological regression
//! (e.g. an accidental global lock serializing every connection) without
//! asserting a specific performance SLA.

mod common;

use common::*;
use dratchet_server::protocol::*;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Barrier;

const CLIENT_COUNT: usize = 40;
const ITERATIONS_PER_CLIENT: usize = 15;

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn many_concurrent_clients_publish_fetch_mailbox_presence_rendezvous_without_error() {
    let url = spawn_server().await;

    // Every account is generated up front so `FetchBundle`/`RendezvousOffer`
    // targets are all valid identities from iteration 0 — the load phase
    // exercises server concurrency, not account setup.
    let mut accounts = Vec::with_capacity(CLIENT_COUNT);
    let mut fingerprints = Vec::with_capacity(CLIENT_COUNT);
    for i in 0..CLIENT_COUNT {
        let (account, bundle) = fresh_account_and_bundle(&format!("stress{i}"), i as u16, 4);
        fingerprints.push(fingerprint_of(&account));
        accounts.push((account, bundle));
    }

    // Every client rendezvous-offers its ring neighbor, so a peer must
    // already be authenticated (present in the server's `connections` map)
    // before any offer targeting it can Ack ok. A barrier holds every task
    // at the start line until all `CLIENT_COUNT` have published+authed, so
    // the load phase begins with every peer already reachable.
    let start_barrier = Arc::new(Barrier::new(CLIENT_COUNT));
    // Every client rendezvous-offers its ring neighbor on every iteration,
    // so a neighbor that finishes its own loop early and disconnects would
    // make a still-running client's later offer legitimately Ack false —
    // a race in the test's ring topology, not a server bug. This second
    // barrier holds every connection open until all clients have sent their
    // last offer, before any of them is allowed to disconnect.
    let end_barrier = Arc::new(Barrier::new(CLIENT_COUNT));

    let started = Instant::now();
    let mut tasks = tokio::task::JoinSet::new();

    for (i, (account, bundle)) in accounts.into_iter().enumerate() {
        let url = url.clone();
        let fingerprints = fingerprints.clone();
        let start_barrier = start_barrier.clone();
        let end_barrier = end_barrier.clone();
        tasks.spawn(async move {
            let mut client = TestClient::connect(&url).await;
            client
                .send(FrameTag::PublishBundle, &PublishBundle { bundle })
                .await;
            client.authenticate(&account).await;

            start_barrier.wait().await;

            let peer_index = (i + 1) % fingerprints.len();
            let peer_fp = fingerprints[peer_index].clone();
            let peer_username = format!("stress{peer_index}");

            let mut ops = 0u32;

            for iter in 0..ITERATIONS_PER_CLIENT {
                // 1. Fetch the ring neighbor's bundle — always succeeds,
                //    every account published before the barrier released.
                client
                    .send(
                        FrameTag::FetchBundle,
                        &FetchBundle {
                            username: peer_username.clone(),
                            discriminator: peer_index as u16,
                        },
                    )
                    .await;
                let result: BundleResult = client.recv_skip_pushes(FrameTag::BundleResult).await;
                assert!(
                    result.bundle.is_some(),
                    "client {i} iter {iter}: peer bundle must be found"
                );
                ops += 1;

                // 2. Mailbox round trip against a private, per-(client,
                //    iteration) mailbox id — no cross-client collisions.
                let mailbox_id = {
                    let mut id = vec![0u8; 16];
                    id[0..8].copy_from_slice(&(i as u64).to_le_bytes());
                    id[8..16].copy_from_slice(&(iter as u64).to_le_bytes());
                    id
                };
                client
                    .send(
                        FrameTag::MailboxWrite,
                        &MailboxWrite {
                            mailbox_id: mailbox_id.clone(),
                            envelope: vec![i as u8; 32],
                            ttl: 60,
                        },
                    )
                    .await;
                let ack: Ack = client.recv_skip_pushes(FrameTag::Ack).await;
                assert!(
                    ack.ok,
                    "client {i} iter {iter}: mailbox write should succeed"
                );
                ops += 1;

                client
                    .send(
                        FrameTag::MailboxFetch,
                        &MailboxFetch {
                            mailbox_id: mailbox_id.clone(),
                        },
                    )
                    .await;
                let entries: MailboxEntries =
                    client.recv_skip_pushes(FrameTag::MailboxEntries).await;
                assert_eq!(
                    entries.entries.len(),
                    1,
                    "client {i} iter {iter}: exactly the one entry just written"
                );
                ops += 1;

                // 3. Presence announce — fire-and-forget, no response frame.
                let state = if iter % 2 == 0 { 1 } else { 0 };
                client
                    .send(FrameTag::PresenceAnnounce, &PresenceAnnounce { state })
                    .await;
                ops += 1;

                // 4. Rendezvous offer to the (already-authenticated,
                //    still-connected) ring neighbor — must always relay.
                client
                    .send(
                        FrameTag::RendezvousOffer,
                        &RendezvousOffer {
                            peer_fingerprint: peer_fp.clone(),
                            sdp_offer: format!("v=0 stress-{i}-{iter}"),
                            ice_candidates: vec![],
                        },
                    )
                    .await;
                let ack: Ack = client.recv_skip_pushes(FrameTag::Ack).await;
                assert!(
                    ack.ok,
                    "client {i} iter {iter}: peer is online, rendezvous must relay"
                );
                ops += 1;
            }

            end_barrier.wait().await;
            ops
        });
    }

    let mut total_ops = 0u64;
    let mut completed = 0usize;
    while let Some(res) = tasks.join_next().await {
        total_ops += res.expect("client task must not panic") as u64;
        completed += 1;
    }

    let elapsed = started.elapsed();
    assert_eq!(
        completed, CLIENT_COUNT,
        "every simulated client must finish"
    );

    let ops_per_sec = total_ops as f64 / elapsed.as_secs_f64();
    println!(
        "stress: {CLIENT_COUNT} clients x {ITERATIONS_PER_CLIENT} iterations = {total_ops} request/response round trips in {elapsed:?} ({ops_per_sec:.0} ops/sec)"
    );
    assert!(
        elapsed.as_secs() < 30,
        "stress test took suspiciously long: {elapsed:?} — possible lock contention regression"
    );
}
