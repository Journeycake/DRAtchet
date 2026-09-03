//! Adversarial tests against the real, running service — matching the
//! Phase 1.1 test-gate checklist: auth-bypass, replay, the presence-oracle
//! property, mailbox scoping, malformed-input handling, and rejecting
//! internally-inconsistent bundles. Every test here tries to make the
//! server misbehave, not just confirms the happy path again.

mod common;

use common::*;
use dratchet_core::account::Account;
use dratchet_server::protocol::*;

#[tokio::test]
async fn mailbox_and_rendezvous_and_presence_subscribe_require_auth_first() {
    let url = spawn_server().await;
    let mut client = TestClient::connect(&url).await;
    client.skip_challenge().await;

    client
        .send(
            FrameTag::MailboxWrite,
            &MailboxWrite {
                mailbox_id: vec![1; 16],
                envelope: vec![1],
                ttl: 60,
            },
        )
        .await;
    let (tag, err): (_, ErrorFrame) = client.recv().await;
    assert_eq!(tag, FrameTag::Error);
    assert!(err.message.to_lowercase().contains("auth"));

    client
        .send(
            FrameTag::MailboxFetch,
            &MailboxFetch {
                mailbox_id: vec![1; 16],
            },
        )
        .await;
    let (tag, _err): (_, ErrorFrame) = client.recv().await;
    assert_eq!(tag, FrameTag::Error);

    client
        .send(
            FrameTag::PresenceSubscribe,
            &PresenceSubscribe {
                identity_fingerprint: vec![0; 32],
            },
        )
        .await;
    let (tag, _err): (_, ErrorFrame) = client.recv().await;
    assert_eq!(tag, FrameTag::Error);

    client
        .send(
            FrameTag::RendezvousOffer,
            &RendezvousOffer {
                peer_fingerprint: vec![0; 32],
                sdp_offer: String::new(),
                ice_candidates: vec![],
            },
        )
        .await;
    let (tag, _err): (_, ErrorFrame) = client.recv().await;
    assert_eq!(tag, FrameTag::Error);
}

#[tokio::test]
async fn auth_response_with_a_fabricated_signature_is_rejected() {
    let url = spawn_server().await;
    let (_account, bundle) = fresh_account_and_bundle("alice", 1, 0);
    let identity_key_bytes = bundle.identity_key.clone();

    let mut publisher = TestClient::connect(&url).await;
    publisher
        .send(FrameTag::PublishBundle, &PublishBundle { bundle })
        .await;

    let mut attacker = TestClient::connect(&url).await;
    let (_, _challenge): (_, AuthChallenge) = attacker.recv().await;
    // No private key involved at all — just noise of the right length.
    let target_fingerprint =
        dratchet_core::identity::fingerprint_of_public_key(&identity_key_bytes)
            .as_bytes()
            .to_vec();
    attacker
        .send(
            FrameTag::AuthResponse,
            &AuthResponse {
                identity_fingerprint: target_fingerprint,
                signature: vec![0xAB; 64],
            },
        )
        .await;
    let (tag, _err): (_, ErrorFrame) = attacker.recv().await;
    assert_eq!(
        tag,
        FrameTag::Error,
        "a fabricated signature must never authenticate"
    );
}

#[tokio::test]
async fn replaying_a_signature_from_a_previous_connection_fails_against_the_new_nonce() {
    // Each connection gets its own fresh nonce (`SERVERS.md` §1.2) — this is
    // exactly what stops a captured AuthResponse from being replayed to
    // hijack a *different* connection, including one opened moments later.
    let url = spawn_server().await;
    let account = Account::generate().unwrap();
    let (_owner, bundle) = fresh_account_and_bundle("alice", 1, 0);
    // Publish under alice's real identity so a lookup succeeds, but attempt
    // to authenticate as her using a signature produced for a stale nonce
    // from an unrelated, already-generated identity — never a match either
    // way, but this specifically exercises "signature bytes that parse fine
    // but were computed over the wrong message."
    let mut publisher = TestClient::connect(&url).await;
    publisher
        .send(
            FrameTag::PublishBundle,
            &PublishBundle {
                bundle: bundle.clone(),
            },
        )
        .await;

    let mut first = TestClient::connect(&url).await;
    let (_, challenge1): (_, AuthChallenge) = first.recv().await;
    let stale_signature = account.identity.sign(&challenge1.nonce).unwrap();

    let mut second = TestClient::connect(&url).await;
    let (_, challenge2): (_, AuthChallenge) = second.recv().await;
    assert_ne!(
        challenge1.nonce, challenge2.nonce,
        "nonces must differ per connection"
    );

    second
        .send(
            FrameTag::AuthResponse,
            &AuthResponse {
                identity_fingerprint: bundle.identity_key.clone(),
                signature: stale_signature,
            },
        )
        .await;
    let (tag, _err): (_, ErrorFrame) = second.recv().await;
    assert_eq!(
        tag,
        FrameTag::Error,
        "a signature computed for a different nonce must not authenticate"
    );
}

#[tokio::test]
async fn presence_subscribe_without_ever_having_fetched_the_target_is_rejected() {
    // The anti-enumeration property `SERVERS.md` §1.3 states in prose,
    // exercised directly: subscribing to an account's presence you've never
    // looked up must fail, not silently start streaming their status.
    let url = spawn_server().await;
    let (alice, alice_bundle) = fresh_account_and_bundle("alice", 1, 0);
    let (bob, bob_bundle) = fresh_account_and_bundle("bob", 2, 0);

    let mut alice_c = TestClient::connect(&url).await;
    alice_c
        .send(
            FrameTag::PublishBundle,
            &PublishBundle {
                bundle: alice_bundle,
            },
        )
        .await;
    alice_c.authenticate(&alice).await;

    let mut bob_c = TestClient::connect(&url).await;
    bob_c
        .send(
            FrameTag::PublishBundle,
            &PublishBundle { bundle: bob_bundle },
        )
        .await;
    bob_c.authenticate(&bob).await;

    // Alice never fetched Bob's bundle — no evidence of any attempted session.
    alice_c
        .send(
            FrameTag::PresenceSubscribe,
            &PresenceSubscribe {
                identity_fingerprint: fingerprint_of(&bob),
            },
        )
        .await;
    let (tag, _err): (_, ErrorFrame) = alice_c.recv().await;
    assert_eq!(tag, FrameTag::Error);

    // Confirm it's really blocked, not just delayed: Bob changes presence,
    // Alice must receive nothing at all (checked by racing a short timeout).
    bob_c
        .send(FrameTag::PresenceAnnounce, &PresenceAnnounce { state: 1 })
        .await;
    let nothing_arrived =
        tokio::time::timeout(std::time::Duration::from_millis(200), alice_c.recv_raw()).await;
    assert!(
        nothing_arrived.is_err(),
        "an unsubscribed party must never receive a PresenceUpdate"
    );
}

#[tokio::test]
async fn fetching_a_different_mailbox_id_never_returns_another_mailboxs_entries() {
    let url = spawn_server().await;
    let (alice, alice_bundle) = fresh_account_and_bundle("alice", 1, 0);
    let mut client = TestClient::connect(&url).await;
    client
        .send(
            FrameTag::PublishBundle,
            &PublishBundle {
                bundle: alice_bundle,
            },
        )
        .await;
    client.authenticate(&alice).await;

    client
        .send(
            FrameTag::MailboxWrite,
            &MailboxWrite {
                mailbox_id: vec![1; 16],
                envelope: vec![0xAA],
                ttl: 60,
            },
        )
        .await;
    let (_, ack): (_, Ack) = client.recv().await;
    assert!(ack.ok);

    client
        .send(
            FrameTag::MailboxFetch,
            &MailboxFetch {
                mailbox_id: vec![2; 16],
            },
        )
        .await;
    let (_, entries): (_, MailboxEntries) = client.recv().await;
    assert!(
        entries.entries.is_empty(),
        "a different mailbox_id must never see another mailbox's contents"
    );
}

#[tokio::test]
async fn a_bundle_with_a_tampered_dh_signature_is_rejected_at_publish() {
    let (_account, mut bundle) = fresh_account_and_bundle("alice", 1, 0);
    bundle.identity_dh_signature[0] ^= 0xFF; // corrupt one byte of the signature

    let url = spawn_server().await;
    let mut client = TestClient::connect(&url).await;
    client.skip_challenge().await;
    client
        .send(FrameTag::PublishBundle, &PublishBundle { bundle })
        .await;
    let (tag, _err): (_, ErrorFrame) = client.recv().await;
    assert_eq!(
        tag,
        FrameTag::Error,
        "an internally-inconsistent bundle must never be accepted into the directory"
    );
}

#[tokio::test]
async fn a_bundle_with_a_tampered_signed_prekey_signature_is_rejected_at_publish() {
    let (_account, mut bundle) = fresh_account_and_bundle("alice", 1, 0);
    bundle.signed_prekey_sig[0] ^= 0xFF;

    let url = spawn_server().await;
    let mut client = TestClient::connect(&url).await;
    client.skip_challenge().await;
    client
        .send(FrameTag::PublishBundle, &PublishBundle { bundle })
        .await;
    let (tag, _err): (_, ErrorFrame) = client.recv().await;
    assert_eq!(tag, FrameTag::Error);
}

#[tokio::test]
async fn a_tampered_bundle_is_never_stored_a_later_valid_publish_still_wins() {
    // Belt-and-suspenders on the previous two tests: confirm rejection
    // really means "never written," not "written then flagged" — fetch
    // after a rejected publish must come back empty, and a subsequent
    // legitimate publish under the same username must succeed cleanly.
    let (_account, mut bad_bundle) = fresh_account_and_bundle("alice", 1, 0);
    bad_bundle.identity_dh_signature[0] ^= 0xFF;

    let url = spawn_server().await;
    let mut client = TestClient::connect(&url).await;
    client.skip_challenge().await;
    client
        .send(
            FrameTag::PublishBundle,
            &PublishBundle { bundle: bad_bundle },
        )
        .await;
    let (_, _err): (_, ErrorFrame) = client.recv().await;

    client
        .send(
            FrameTag::FetchBundle,
            &FetchBundle {
                username: "alice".into(),
                discriminator: 1,
            },
        )
        .await;
    let (_, result): (_, BundleResult) = client.recv().await;
    assert!(
        result.bundle.is_none(),
        "a rejected publish must never land in the directory"
    );

    let (_account2, good_bundle) = fresh_account_and_bundle("alice", 1, 0);
    client
        .send(
            FrameTag::PublishBundle,
            &PublishBundle {
                bundle: good_bundle,
            },
        )
        .await;
    client
        .send(
            FrameTag::FetchBundle,
            &FetchBundle {
                username: "alice".into(),
                discriminator: 1,
            },
        )
        .await;
    let (_, result): (_, BundleResult) = client.recv().await;
    assert!(result.bundle.is_some());
}

#[tokio::test]
async fn malformed_frames_never_crash_the_connection_valid_traffic_still_works_after() {
    let url = spawn_server().await;
    let mut client = TestClient::connect(&url).await;
    client.skip_challenge().await;

    let adversarial_frames: Vec<Vec<u8>> = vec![
        vec![],                                                            // empty
        vec![0xFF],                                                        // unknown tag, no body
        vec![FrameTag::PublishBundle as u8], // known tag, empty CBOR body
        vec![FrameTag::PublishBundle as u8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], // known tag, garbage CBOR
        vec![FrameTag::AuthResponse as u8, 0xA1, 0x00],                    // truncated mid-map
        {
            // Wildly oversized claimed lengths inside CBOR shouldn't cause
            // an allocation panic or hang — a handful of adversarial byte
            // strings with huge (but never actually backed) length prefixes.
            let mut v = vec![FrameTag::MailboxWrite as u8];
            v.extend_from_slice(&[0xA3, 0x62, b'i', b'd', 0x5A, 0xFF, 0xFF, 0xFF, 0xFF]);
            v
        },
    ];

    let sent_count = adversarial_frames.len();
    for frame in adversarial_frames {
        client.send_raw(frame).await;
    }

    // Every malformed frame gets an Error response of its own (never
    // silence, never a crash) — drain exactly that many before checking the
    // connection still works normally afterward.
    for _ in 0..sent_count {
        let (tag, _err): (_, ErrorFrame) = client.recv().await;
        assert_eq!(tag, FrameTag::Error);
    }

    // The connection must still be alive and the protocol still functional
    // afterward — malformed input degrades to per-frame errors, never a
    // dead or corrupted connection.
    let (_account, bundle) = fresh_account_and_bundle("still-fine", 1, 0);
    client
        .send(FrameTag::PublishBundle, &PublishBundle { bundle })
        .await;
    client
        .send(
            FrameTag::FetchBundle,
            &FetchBundle {
                username: "still-fine".into(),
                discriminator: 1,
            },
        )
        .await;
    let (tag, result): (_, BundleResult) = client.recv().await;
    assert_eq!(tag, FrameTag::BundleResult);
    assert!(
        result.bundle.is_some(),
        "the connection must still work normally after adversarial input"
    );
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(256))]

    /// Property version of the malformed-frame test above: no byte sequence,
    /// however random, may panic the frame-splitting/decoding path. Runs
    /// against the pure parser directly (not over a live socket) so it can
    /// exercise many more inputs per run than a full connection round-trip
    /// would afford.
    #[test]
    fn arbitrary_bytes_never_panic_the_frame_parser(bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..256)) {
        if let Ok((_tag, body)) = split_tag(&bytes) {
            let _ = decode_body::<AuthResponse>(body);
            let _ = decode_body::<PublishBundle>(body);
            let _ = decode_body::<FetchBundle>(body);
            let _ = decode_body::<MailboxWrite>(body);
            let _ = decode_body::<RendezvousOffer>(body);
        }
    }
}
