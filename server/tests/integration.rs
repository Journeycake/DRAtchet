//! End-to-end integration tests against the real, running Signaling &
//! Presence Service — two real accounts, real WebSocket connections,
//! publish -> fetch -> auth -> presence -> rendezvous -> mailbox, per the
//! Phase 1.1 exit gate ("two client stubs complete publish -> rendezvous
//! -> mailbox exchange against the real service").

mod common;

use common::*;
use dratchet_server::protocol::*;

#[tokio::test]
async fn publish_then_fetch_round_trips_a_bundle() {
    let url = spawn_server().await;
    let (_account, bundle) = fresh_account_and_bundle("alice", 4821, 3);

    let mut publisher = TestClient::connect(&url).await;
    publisher.skip_challenge().await;
    publisher
        .send(
            FrameTag::PublishBundle,
            &PublishBundle {
                bundle: bundle.clone(),
            },
        )
        .await;

    let mut fetcher = TestClient::connect(&url).await;
    fetcher.skip_challenge().await;
    fetcher
        .send(
            FrameTag::FetchBundle,
            &FetchBundle {
                username: "alice".into(),
                discriminator: 4821,
            },
        )
        .await;
    let (tag, result): (_, BundleResult) = fetcher.recv().await;
    assert_eq!(tag, FrameTag::BundleResult);
    let fetched = result.bundle.expect("bundle should be found");
    assert_eq!(fetched.username, "alice");
    assert_eq!(fetched.identity_key, bundle.identity_key);
    assert_eq!(fetched.signed_prekey, bundle.signed_prekey);
    assert!(
        fetched.one_time_prekey.is_some(),
        "a one-time prekey should have been consumed"
    );
}

/// Re-publishing under a *different* username (a rename) must release the
/// old `username#NNNN` — otherwise it stays permanently squatted in the
/// directory and, worse, a fetch by the old handle would return bundle
/// data whose own `username` field no longer matches what was looked up.
#[tokio::test]
async fn renaming_releases_the_old_username() {
    let url = spawn_server().await;
    let (_account, first_wire) = fresh_account_and_bundle("alice", 1, 1);

    let mut publisher = TestClient::connect(&url).await;
    publisher.skip_challenge().await;
    publisher
        .send(
            FrameTag::PublishBundle,
            &PublishBundle {
                bundle: first_wire.clone(),
            },
        )
        .await;
    let (_, _ack): (_, Ack) = publisher.recv().await;

    // Same identity, new username — a rename, not a fresh registration —
    // but it still needs its own registration proof-of-work, since the
    // server only waives that for an exact re-publish under the *same*
    // username#NNNN.
    let mut second_wire = first_wire.clone();
    second_wire.username = "alice2".to_string();
    second_wire.registration_pow = Some(dratchet_server::abuse::solve_registration_pow(
        &second_wire.username,
        second_wire.discriminator,
        &second_wire.identity_key,
    ));
    publisher
        .send(
            FrameTag::PublishBundle,
            &PublishBundle {
                bundle: second_wire,
            },
        )
        .await;
    let (_, _ack): (_, Ack) = publisher.recv().await;

    // Fetches go out over the *same* connection as the two publishes above
    // (rather than a fresh one) so frame ordering is guaranteed — the
    // server's read loop awaits each frame's dispatch fully before reading
    // the next one on a given connection, but gives no ordering guarantee
    // *across* connections.
    publisher
        .send(
            FrameTag::FetchBundle,
            &FetchBundle {
                username: "alice".into(),
                discriminator: 1,
            },
        )
        .await;
    let (_, result): (_, BundleResult) = publisher.recv().await;
    assert!(
        result.bundle.is_none(),
        "the old username must be released on rename, not left resolvable"
    );

    // The new handle resolves to the same identity.
    publisher
        .send(
            FrameTag::FetchBundle,
            &FetchBundle {
                username: "alice2".into(),
                discriminator: 1,
            },
        )
        .await;
    let (_, result): (_, BundleResult) = publisher.recv().await;
    let fetched = result.bundle.expect("new username should resolve");
    assert_eq!(fetched.username, "alice2");
    assert_eq!(fetched.identity_key, first_wire.identity_key);
}

#[tokio::test]
async fn fetching_an_unknown_username_returns_no_bundle_not_an_error() {
    let url = spawn_server().await;
    let mut client = TestClient::connect(&url).await;
    client.skip_challenge().await;
    client
        .send(
            FrameTag::FetchBundle,
            &FetchBundle {
                username: "nobody".into(),
                discriminator: 1,
            },
        )
        .await;
    let (tag, result): (_, BundleResult) = client.recv().await;
    assert_eq!(tag, FrameTag::BundleResult);
    assert!(result.bundle.is_none());
}

#[tokio::test]
async fn one_time_prekeys_are_consumed_exactly_once_across_repeated_fetches() {
    let url = spawn_server().await;
    let (_account, bundle) = fresh_account_and_bundle("bob", 1092, 2);

    let mut publisher = TestClient::connect(&url).await;
    publisher.skip_challenge().await;
    publisher
        .send(FrameTag::PublishBundle, &PublishBundle { bundle })
        .await;

    let mut fetcher = TestClient::connect(&url).await;
    fetcher.skip_challenge().await;

    let mut consumed_ids = std::collections::HashSet::new();
    for _ in 0..2 {
        fetcher
            .send(
                FrameTag::FetchBundle,
                &FetchBundle {
                    username: "bob".into(),
                    discriminator: 1092,
                },
            )
            .await;
        let (_, result): (_, BundleResult) = fetcher.recv().await;
        let otp = result
            .bundle
            .unwrap()
            .one_time_prekey
            .expect("should still have one available");
        assert!(
            consumed_ids.insert(otp.id),
            "the same one-time prekey id must not be handed out twice"
        );
    }

    // The batch had exactly 2 — a third fetch must come back with none.
    fetcher
        .send(
            FrameTag::FetchBundle,
            &FetchBundle {
                username: "bob".into(),
                discriminator: 1092,
            },
        )
        .await;
    let (_, result): (_, BundleResult) = fetcher.recv().await;
    assert!(
        result.bundle.unwrap().one_time_prekey.is_none(),
        "the batch should be exhausted"
    );
}

#[tokio::test]
async fn full_auth_handshake_succeeds_for_a_published_identity() {
    let url = spawn_server().await;
    let (account, bundle) = fresh_account_and_bundle("priya", 7734, 0);

    let mut client = TestClient::connect(&url).await;
    client.authenticate(&account).await;
    client
        .send(FrameTag::PublishBundle, &PublishBundle { bundle })
        .await;
    let (_, _ack): (_, Ack) = client.recv().await;
}

/// `AuthResponse` is self-certifying (`ws.rs`'s module doc) — this is the
/// capability that actually matters: an out-of-band-paired identity
/// (`ARCHITECTURE.md` §6.3a's session-routing-id pairing) never calls
/// `PublishBundle` at all, since it has no reason to be discoverable by
/// `username#NNNN`, only to authenticate so it can read/write the Tier 1
/// mailbox both sides already agreed on.
#[tokio::test]
async fn authentication_succeeds_with_no_prior_publish_bundle_at_all() {
    let url = spawn_server().await;
    let account = dratchet_core::account::Account::generate().unwrap();

    let mut client = TestClient::connect(&url).await;
    client.authenticate(&account).await;
}

#[tokio::test]
async fn presence_subscribe_requires_prior_fetch_evidence_then_delivers_updates() {
    let url = spawn_server().await;
    let (alice, alice_bundle) = fresh_account_and_bundle("alice", 1, 0);
    let (bob, bob_bundle) = fresh_account_and_bundle("bob", 2, 0);

    let mut alice_c = TestClient::connect(&url).await;
    alice_c.authenticate(&alice).await;
    alice_c
        .send(
            FrameTag::PublishBundle,
            &PublishBundle {
                bundle: alice_bundle,
            },
        )
        .await;
    let (_, _ack): (_, Ack) = alice_c.recv().await;

    let mut bob_c = TestClient::connect(&url).await;
    bob_c.authenticate(&bob).await;
    bob_c
        .send(
            FrameTag::PublishBundle,
            &PublishBundle { bundle: bob_bundle },
        )
        .await;
    let (_, _ack): (_, Ack) = bob_c.recv().await;

    // Alice must fetch Bob's bundle before she may subscribe to his presence.
    alice_c
        .send(
            FrameTag::FetchBundle,
            &FetchBundle {
                username: "bob".into(),
                discriminator: 2,
            },
        )
        .await;
    let (_, _r): (_, BundleResult) = alice_c.recv().await;

    alice_c
        .send(
            FrameTag::PresenceSubscribe,
            &PresenceSubscribe {
                identity_fingerprint: fingerprint_of(&bob),
            },
        )
        .await;
    // Bob is already online (from his own auth) — subscribing should sync current state immediately.
    let (tag, update): (_, PresenceUpdate) = alice_c.recv().await;
    assert_eq!(tag, FrameTag::PresenceUpdate);
    assert_eq!(update.identity_fingerprint, fingerprint_of(&bob));
    assert_eq!(update.state, 0, "bob should be reported online");

    // Bob announces "away" — Alice, subscribed, should be pushed the update.
    bob_c
        .send(FrameTag::PresenceAnnounce, &PresenceAnnounce { state: 1 })
        .await;
    let (tag, update): (_, PresenceUpdate) = alice_c.recv().await;
    assert_eq!(tag, FrameTag::PresenceUpdate);
    assert_eq!(update.state, 1);
}

#[tokio::test]
async fn rendezvous_offer_is_relayed_to_the_online_peer() {
    let url = spawn_server().await;
    let (alice, alice_bundle) = fresh_account_and_bundle("alice", 1, 0);
    let (bob, bob_bundle) = fresh_account_and_bundle("bob", 2, 0);

    let mut alice_c = TestClient::connect(&url).await;
    alice_c.authenticate(&alice).await;
    alice_c
        .send(
            FrameTag::PublishBundle,
            &PublishBundle {
                bundle: alice_bundle,
            },
        )
        .await;
    let (_, _ack): (_, Ack) = alice_c.recv().await;

    let mut bob_c = TestClient::connect(&url).await;
    bob_c.authenticate(&bob).await;
    bob_c
        .send(
            FrameTag::PublishBundle,
            &PublishBundle { bundle: bob_bundle },
        )
        .await;
    let (_, _ack): (_, Ack) = bob_c.recv().await;

    alice_c
        .send(
            FrameTag::RendezvousOffer,
            &RendezvousOffer {
                peer_fingerprint: fingerprint_of(&bob),
                sdp_offer: "v=0 fake-sdp-offer".into(),
                ice_candidates: vec!["candidate:1 udp".into()],
            },
        )
        .await;

    // Alice gets an Ack that delivery happened...
    let (tag, ack): (_, Ack) = alice_c.recv().await;
    assert_eq!(tag, FrameTag::Ack);
    assert!(ack.ok);

    // ...and Bob actually receives the relayed offer, attributed to Alice.
    let (tag, offer): (_, RendezvousOffer) = bob_c.recv().await;
    assert_eq!(tag, FrameTag::RendezvousOffer);
    assert_eq!(offer.peer_fingerprint, fingerprint_of(&alice));
    assert_eq!(offer.sdp_offer, "v=0 fake-sdp-offer");
}

#[tokio::test]
async fn rendezvous_to_an_offline_peer_acks_false_no_store_and_forward() {
    let url = spawn_server().await;
    let (alice, alice_bundle) = fresh_account_and_bundle("alice", 1, 0);
    let (bob, bob_bundle) = fresh_account_and_bundle("bob", 2, 0);

    let mut alice_c = TestClient::connect(&url).await;
    alice_c.authenticate(&alice).await;
    alice_c
        .send(
            FrameTag::PublishBundle,
            &PublishBundle {
                bundle: alice_bundle,
            },
        )
        .await;
    let (_, _ack): (_, Ack) = alice_c.recv().await;

    // Bob's bundle exists (published once, e.g. by a prior session) but he
    // has no live connection right now.
    let mut publisher = TestClient::connect(&url).await;
    publisher
        .send(
            FrameTag::PublishBundle,
            &PublishBundle { bundle: bob_bundle },
        )
        .await;

    alice_c
        .send(
            FrameTag::RendezvousOffer,
            &RendezvousOffer {
                peer_fingerprint: fingerprint_of(&bob),
                sdp_offer: "v=0".into(),
                ice_candidates: vec![],
            },
        )
        .await;
    let (tag, ack): (_, Ack) = alice_c.recv().await;
    assert_eq!(tag, FrameTag::Ack);
    assert!(
        !ack.ok,
        "rendezvous to an offline peer must not silently succeed"
    );
}

#[tokio::test]
async fn mailbox_write_fetch_delete_round_trips() {
    let url = spawn_server().await;
    let (alice, alice_bundle) = fresh_account_and_bundle("alice", 1, 0);

    let mut client = TestClient::connect(&url).await;
    client.authenticate(&alice).await;
    client
        .send(
            FrameTag::PublishBundle,
            &PublishBundle {
                bundle: alice_bundle,
            },
        )
        .await;
    let (_, _ack): (_, Ack) = client.recv().await;

    let mailbox_id = vec![9u8; 16];
    let envelope = vec![1, 2, 3, 4, 5];

    client
        .send(
            FrameTag::MailboxWrite,
            &MailboxWrite {
                mailbox_id: mailbox_id.clone(),
                envelope: envelope.clone(),
                ttl: 3600,
            },
        )
        .await;
    let (tag, ack): (_, Ack) = client.recv().await;
    assert_eq!(tag, FrameTag::Ack);
    assert!(ack.ok);

    client
        .send(
            FrameTag::MailboxFetch,
            &MailboxFetch {
                mailbox_id: mailbox_id.clone(),
            },
        )
        .await;
    let (tag, entries): (_, MailboxEntries) = client.recv().await;
    assert_eq!(tag, FrameTag::MailboxEntries);
    assert_eq!(entries.entries.len(), 1);
    assert_eq!(entries.entries[0].envelope, envelope);

    let entry_id = entries.entries[0].entry_id.clone();
    client
        .send(
            FrameTag::MailboxDelete,
            &MailboxDelete {
                mailbox_id: mailbox_id.clone(),
                entry_id,
            },
        )
        .await;
    let (tag, ack): (_, Ack) = client.recv().await;
    assert_eq!(tag, FrameTag::Ack);
    assert!(ack.ok);

    client
        .send(FrameTag::MailboxFetch, &MailboxFetch { mailbox_id })
        .await;
    let (_, entries): (_, MailboxEntries) = client.recv().await;
    assert!(
        entries.entries.is_empty(),
        "deleted entry must not still be fetchable"
    );
}

#[tokio::test]
async fn a_second_writer_can_deliver_to_a_mailbox_id_they_did_not_create() {
    // Mailbox ownership is capability-based by design (`SERVERS.md` §1.1,
    // §11.1 of ARCHITECTURE.md): knowing the ratchet-derived mailbox_id *is*
    // the authorization, so any authenticated connection may write to any
    // mailbox_id — this is not a bug, it's the point (a sender who isn't
    // the mailbox's eventual reader still needs to write to it).
    let url = spawn_server().await;
    let (sender, sender_bundle) = fresh_account_and_bundle("sender", 1, 0);
    let mut sender_c = TestClient::connect(&url).await;
    sender_c.authenticate(&sender).await;
    sender_c
        .send(
            FrameTag::PublishBundle,
            &PublishBundle {
                bundle: sender_bundle,
            },
        )
        .await;
    let (_, _ack): (_, Ack) = sender_c.recv().await;

    let mailbox_id = vec![42u8; 16];
    sender_c
        .send(
            FrameTag::MailboxWrite,
            &MailboxWrite {
                mailbox_id,
                envelope: vec![9],
                ttl: 60,
            },
        )
        .await;
    let (_, ack): (_, Ack) = sender_c.recv().await;
    assert!(ack.ok);
}
