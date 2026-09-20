//! Penetration-test finding DRA-0044 (round 7, denial of service --
//! unbounded server-side memory growth from throwaway identities).
//!
//! `Inner::presence` is a `HashMap<Fingerprint, PresenceState>` that
//! `ws.rs` writes on every authentication (`Online`) and again on every
//! disconnect (`Offline { last_seen }`), and that `pruning.rs`'s module
//! doc says is *never* swept: "`presence`, `subscriptions`, and
//! `fetch_evidence` are never touched here."
//!
//! Authenticating costs an attacker nothing but a locally generated
//! Ed25519 keypair and one signature over the server's nonce -- no
//! registration, no proof-of-work, no directory entry required. Every
//! distinct fingerprint that connects once therefore leaves a permanent
//! entry behind. DRA-0031's connection cap bounds how many sockets are
//! open *at once*; it does nothing about a client that connects,
//! authenticates, disconnects, and repeats with a fresh identity, which
//! also hands each new identity fresh per-identity rate-limit buckets.
//!
//! The entries are pure waste: presence for a fingerprint that is not in
//! the directory can never be *queried* by anyone, because
//! `PresenceSubscribe` requires `fetch_evidence`, which is only recorded
//! by a successful `FetchBundle` against a published bundle.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::*;
use dratchet_server::protocol::*;
use dratchet_server::state::{AppState, Fingerprint, PresenceState};
use tokio::net::TcpListener;

/// `common::fingerprint_of` hands back a `Vec<u8>`; `Inner::presence` is
/// keyed by the fixed-size `Fingerprint`.
fn fp_of(account: &dratchet_core::account::Account) -> Fingerprint {
    *account.identity.fingerprint().as_bytes()
}

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

/// Connect, authenticate as `account`, then drop the socket -- exactly
/// the cycle a throwaway identity performs.
async fn authenticate_then_disconnect(url: &str, account: &dratchet_core::account::Account) {
    let mut client = TestClient::connect(url).await;
    client.authenticate(account).await;
    drop(client);
}

/// Wait until the server has finished processing the disconnect for every
/// fingerprint in `fps` -- i.e. each is recorded `Offline`, not merely
/// present as `Online` from its authentication. Dropping the socket only
/// starts the teardown; without this the test would race it.
async fn wait_until_all_offline(state: &Arc<AppState>, fps: &[Fingerprint]) {
    for _ in 0..500 {
        {
            let inner = state.inner.read().await;
            if fps
                .iter()
                .all(|fp| matches!(inner.presence.get(fp), Some(PresenceState::Offline { .. })))
            {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("server never recorded every identity as Offline");
}

#[tokio::test]
async fn throwaway_identities_do_not_accumulate_presence_entries_forever() {
    let (url, state) = spawn_server_with_state().await;

    // A real account: publishes a bundle, so it is a directory resident
    // someone else could genuinely subscribe to. `SERVERS.md` §1.3's
    // "a disconnected identity's `last_seen` is retained" is about this
    // one, and must keep holding.
    let (real_account, real_bundle) = fresh_account_and_bundle("alice", 1111, 1);
    let real_fp = fp_of(&real_account);
    {
        let mut client = TestClient::connect(&url).await;
        client.authenticate(&real_account).await;
        client
            .send(
                FrameTag::PublishBundle,
                &PublishBundle {
                    bundle: real_bundle,
                },
            )
            .await;
        let (tag, ack): (_, Ack) = client.recv().await;
        assert_eq!(tag, FrameTag::Ack);
        assert!(ack.ok);
        drop(client);
    }

    // The attack: throwaway identities that authenticate and leave,
    // publishing nothing and being subscribed to by nobody.
    const THROWAWAYS: usize = 25;
    let mut throwaway_fps = Vec::new();
    for _ in 0..THROWAWAYS {
        let account = dratchet_core::account::Account::generate().unwrap();
        throwaway_fps.push(fp_of(&account));
        authenticate_then_disconnect(&url, &account).await;
    }

    let mut all_fps = throwaway_fps.clone();
    all_fps.push(real_fp);
    wait_until_all_offline(&state, &all_fps).await;

    // Before the sweep, every one of them is sitting in the map -- which
    // is what makes the assertion after the sweep meaningful rather than
    // vacuous.
    {
        let inner = state.inner.read().await;
        assert_eq!(
            inner.presence.len(),
            THROWAWAYS + 1,
            "sanity check: every identity that authenticated is in `presence` pre-sweep"
        );
    }

    // One real pruning pass, the same call `spawn_pruning_sweep` makes on
    // its timer in production.
    dratchet_server::pruning::sweep_once(&state, Duration::from_secs(60)).await;

    let inner = state.inner.read().await;
    for fp in &throwaway_fps {
        assert!(
            !inner.presence.contains_key(fp),
            "VULNERABILITY: a throwaway identity that published nothing and has no subscribers \
             left a permanent `presence` entry behind -- authenticating is free, so an attacker \
             cycling fresh identities grows this map without bound until the process is restarted"
        );
    }

    // The documented retention for a real account is untouched.
    assert!(
        matches!(
            inner.presence.get(&real_fp),
            Some(PresenceState::Offline { .. })
        ),
        "a directory-resident account's `last_seen` must still be retained (SERVERS.md §1.3)"
    );
}

/// The other two halves of DRA-0044: `fetch_evidence` (written by every
/// `FetchBundle`) and the subscriber sets inside `subscriptions` are
/// keyed by the *fetcher*/*subscriber*, which is entirely
/// attacker-chosen. A throwaway can therefore fetch a real account's
/// bundle, subscribe to it, and leave -- permanently enlarging both maps.
///
/// The subscriber set is the worse of the two: `ws.rs` clones it on every
/// single presence change of the victim (authenticate, disconnect,
/// `PresenceAnnounce`), so a pile of dead watchers turns each of the
/// victim's ordinary state changes into a proportionally more expensive
/// operation.
#[tokio::test]
async fn a_throwaway_subscriber_does_not_stay_attached_to_a_real_accounts_presence() {
    let (url, state) = spawn_server_with_state().await;

    // A real, directory-resident account to be watched.
    let (victim, victim_bundle) = fresh_account_and_bundle("victim", 2222, 4);
    let victim_fp = fp_of(&victim);
    let mut victim_client = TestClient::connect(&url).await;
    victim_client.authenticate(&victim).await;
    victim_client
        .send(
            FrameTag::PublishBundle,
            &PublishBundle {
                bundle: victim_bundle,
            },
        )
        .await;
    let (tag, ack): (_, Ack) = victim_client.recv().await;
    assert_eq!(tag, FrameTag::Ack);
    assert!(ack.ok);

    // A throwaway fetches the victim's bundle (recording fetch evidence),
    // subscribes on the strength of it, then vanishes.
    let throwaway = dratchet_core::account::Account::generate().unwrap();
    let throwaway_fp = fp_of(&throwaway);
    {
        let mut client = TestClient::connect(&url).await;
        client.authenticate(&throwaway).await;
        client
            .send(
                FrameTag::FetchBundle,
                &FetchBundle {
                    username: "victim".to_string(),
                    discriminator: 2222,
                },
            )
            .await;
        let (tag, result): (_, BundleResult) = client.recv().await;
        assert_eq!(tag, FrameTag::BundleResult);
        assert!(
            result.bundle.is_some(),
            "the victim's bundle must be fetchable"
        );

        client
            .send(
                FrameTag::PresenceSubscribe,
                &PresenceSubscribe {
                    identity_fingerprint: victim_fp.to_vec(),
                },
            )
            .await;
        // The subscribe replies with the target's current presence.
        let (tag, _update): (_, PresenceUpdate) = client.recv().await;
        assert_eq!(tag, FrameTag::PresenceUpdate);
        drop(client);
    }

    wait_until_all_offline(&state, &[throwaway_fp]).await;

    // Both are really there pre-sweep, so neither assertion below is
    // vacuous.
    {
        let inner = state.inner.read().await;
        assert!(inner.fetch_evidence.contains_key(&throwaway_fp));
        assert!(inner
            .subscriptions
            .get(&victim_fp)
            .is_some_and(|w| w.contains(&throwaway_fp)));
    }

    dratchet_server::pruning::sweep_once(&state, Duration::from_secs(60)).await;

    let inner = state.inner.read().await;
    assert!(
        !inner.fetch_evidence.contains_key(&throwaway_fp),
        "VULNERABILITY: a throwaway identity's `fetch_evidence` entry outlives it forever -- \
         fetching is all it takes to claim a permanent slot in a map nothing ever sweeps"
    );
    assert!(
        !inner
            .subscriptions
            .get(&victim_fp)
            .is_some_and(|w| w.contains(&throwaway_fp)),
        "VULNERABILITY: a throwaway subscriber stays attached to a real account's presence \
         forever, and the server clones that whole set on every one of the victim's presence \
         changes"
    );

    // The victim is still connected, so nothing of theirs was touched.
    assert!(
        inner.connections.contains_key(&victim_fp),
        "the victim's own live connection must be unaffected"
    );
}
