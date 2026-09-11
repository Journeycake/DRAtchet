//! Simulates the worst case for the Signaling & Presence Service's own design
//! claim (`server/README.md`: "it never sees plaintext, ratchet state, or
//! long-term private key material... it holds no durable state"): the server
//! process itself is fully breached — an attacker gets read access to
//! everything `AppState` holds, including mailbox entries still queued and
//! undelivered at the moment of the breach (the actual "message
//! confiscation" scenario, not just a snapshot of already-delivered
//! traffic).
//!
//! This isn't testable by trying to break ChaCha20-Poly1305 or X25519 from
//! scratch — that's not what a unit test can prove, any more than
//! `core/src/ratchet.rs`'s forward-secrecy tests literally invert SHA-256.
//! What *is* testable, and is exactly the right scope: the confiscated state
//! genuinely contains neither the plaintext nor the key material that would
//! be needed to recover it — not "recovering it is hard," but "the
//! ingredients simply aren't there," checked by direct inspection rather
//! than assumed from the type signatures alone.

mod common;

use std::sync::Arc;

use common::*;
use dratchet_core::prekey::{OneTimePrekeyPublic, PrekeyBundle, SignedPrekeyPublic};
use dratchet_core::ratchet::{RatchetState, DEFAULT_MAX_SKIP};
use dratchet_core::x3dh;
use dratchet_server::protocol::*;
use dratchet_server::state::AppState;
use tokio::net::TcpListener;
use x25519_dalek::PublicKey;

/// Like `common::spawn_server()`, but keeps the `AppState` handle instead of
/// discarding it — this file needs to read it back after the fact to play
/// the attacker who's just breached the process.
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

/// `FetchedBundleWire` (what a directory fetch actually returns over the
/// wire) -> `core::prekey::PrekeyBundle` (what `x3dh::initiate` needs) —
/// the same conversion `server/src/ws.rs::to_core_bundle` does internally,
/// reimplemented here since that function is private to the server crate.
fn to_core_bundle(wire: &FetchedBundleWire) -> PrekeyBundle {
    let identity_dh_public: [u8; 32] = wire.identity_dh_public.as_slice().try_into().unwrap();
    let signed_prekey_public: [u8; 32] = wire.signed_prekey.as_slice().try_into().unwrap();
    PrekeyBundle {
        identity_public_key: wire.identity_key.clone(),
        identity_dh_public: PublicKey::from(identity_dh_public),
        identity_dh_signature: wire.identity_dh_signature.clone(),
        signed_prekey: SignedPrekeyPublic {
            id: wire.signed_prekey_id,
            public: PublicKey::from(signed_prekey_public),
            signature: wire.signed_prekey_sig.clone(),
        },
        one_time_prekey: wire.one_time_prekey.as_ref().map(|otp| {
            let public: [u8; 32] = otp.key.as_slice().try_into().unwrap();
            OneTimePrekeyPublic {
                id: otp.id,
                public: PublicKey::from(public),
            }
        }),
    }
}

fn chat(text: &str) -> Vec<u8> {
    dratchet_core::payload::tag_and_pad(dratchet_core::payload::PAYLOAD_CHAT, text.as_bytes())
        .unwrap()
}

/// True if `needle`'s raw bytes appear anywhere in `haystack`, at any
/// alignment — the shape a forensic search over confiscated memory/disk
/// would actually take, not an exact-offset comparison.
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// Everything an attacker who fully breached the server process would walk
/// away with: every byte held by `AppState` that isn't purely operational
/// bookkeeping (open connections, rate-limiter counters — nothing textual
/// or key-shaped lives there). Built directly from the real, running
/// server's actual state, not a reconstruction.
async fn seize_everything(state: &AppState) -> (Vec<u8>, usize) {
    let inner = state.inner.read().await;
    let mut bytes = Vec::new();
    let mut mailbox_entry_count = 0;

    for bundle in inner.directory.values() {
        bytes.extend_from_slice(&bundle.bundle.identity_key);
        bytes.extend_from_slice(&bundle.bundle.identity_dh_public);
        bytes.extend_from_slice(&bundle.bundle.identity_dh_signature);
        bytes.extend_from_slice(&bundle.bundle.signed_prekey);
        bytes.extend_from_slice(&bundle.bundle.signed_prekey_sig);
        for otp in bundle.one_time_prekeys.values() {
            bytes.extend_from_slice(otp);
        }
    }
    for entries in inner.mailboxes.values() {
        for entry in entries {
            bytes.extend_from_slice(&entry.envelope);
            mailbox_entry_count += 1;
        }
    }

    (bytes, mailbox_entry_count)
}

#[tokio::test]
async fn breaching_the_server_yields_ciphertext_only_never_plaintext_or_private_keys() {
    let (url, state) = spawn_server_with_state().await;

    // Bob publishes a real bundle to the real directory (one one-time
    // prekey included) — the only part of this test where server-held data
    // is *supposed* to be visible to a breach: it's all public key
    // material by design.
    let (mut bob, bob_bundle) = fresh_account_and_bundle("bob", 7001, 1);
    let mut publisher = TestClient::connect(&url).await;
    publisher.skip_challenge().await;
    publisher
        .send(
            FrameTag::PublishBundle,
            &PublishBundle { bundle: bob_bundle },
        )
        .await;
    // PublishBundle has no success response (see `server/src/ws.rs`'s
    // dispatch: only failures produce an `Error` frame back) — matches the
    // existing `publish_then_fetch_round_trips_a_bundle` pattern in
    // `integration.rs`.

    // Alice fetches Bob's bundle over the real wire and runs X3DH as the
    // initiator — a real handshake, not a shortcut.
    let alice = dratchet_core::account::Account::generate().unwrap();
    let mut fetcher = TestClient::connect(&url).await;
    fetcher.skip_challenge().await;
    fetcher
        .send(
            FrameTag::FetchBundle,
            &FetchBundle {
                username: "bob".into(),
                discriminator: 7001,
            },
        )
        .await;
    let (tag, result): (_, BundleResult) = fetcher.recv().await;
    assert_eq!(tag, FrameTag::BundleResult);
    let fetched = result.bundle.expect("bob's bundle should be found");
    let core_bundle = to_core_bundle(&fetched);

    let init = x3dh::initiate(
        alice.identity_dh_secret(),
        alice.identity_dh_public,
        &core_bundle,
    )
    .unwrap();

    let conv_id = dratchet_core::conversation_id(
        alice.identity.fingerprint().as_bytes(),
        bob.identity.fingerprint().as_bytes(),
    );
    let mut alice_ratchet = RatchetState::init_as_initiator(
        conv_id,
        init.root_key,
        core_bundle.signed_prekey.public,
        DEFAULT_MAX_SKIP,
    )
    .unwrap();

    // Bob completes his side purely locally — this test isn't re-proving the
    // handshake transport (core/tests/x3dh_and_ratchet.rs and
    // client/tests/queue_depth.rs already do that); it's asking what the
    // *server* ends up holding once real ciphertext flows through it.
    let bob_otp_secret = init
        .message
        .used_one_time_prekey_id
        .and_then(|id| bob.take_one_time_prekey_secret(id));
    let bob_root_key = x3dh::respond(
        bob.identity_dh_secret(),
        bob.signed_prekey_secret(),
        bob_otp_secret.as_ref(),
        &init.message,
    );
    let mut bob_ratchet = RatchetState::init_as_responder(
        conv_id,
        bob_root_key,
        bob.signed_prekey_secret().clone(),
        DEFAULT_MAX_SKIP,
    )
    .unwrap();

    // Real, distinctive plaintext — the exact bytes the forensic search
    // below looks for. The first gets delivered and read normally; the rest
    // are deliberately left sitting in the mailbox, undelivered, at the
    // moment of the breach — the actual "message confiscation" case.
    let plaintexts = [
        "the launch code is 4815162342",
        "meet at the old bridge at midnight",
        "wire the funds to account 9981-2274",
        "her real name is redacted for a reason",
    ];
    let mailbox_id = conv_id.to_vec();
    let mut sender = TestClient::connect(&url).await;
    sender.authenticate(&alice).await;

    for text in &plaintexts {
        let envelope = alice_ratchet.encrypt(&chat(text)).unwrap();
        sender
            .send(
                FrameTag::MailboxWrite,
                &MailboxWrite {
                    mailbox_id: mailbox_id.clone(),
                    envelope: envelope.encode(),
                    ttl: 86_400,
                },
            )
            .await;
        let (tag, ack): (_, Ack) = sender.recv().await;
        assert_eq!(tag, FrameTag::Ack);
        assert!(ack.ok);
    }

    // Bob comes online and reads (then deletes) only the *first* message —
    // the rest stay queued, exactly as if Bob were offline when the breach
    // happens.
    let mut receiver = TestClient::connect(&url).await;
    receiver.authenticate(&bob).await;
    receiver
        .send(
            FrameTag::MailboxFetch,
            &MailboxFetch {
                mailbox_id: mailbox_id.clone(),
            },
        )
        .await;
    let (_, entries): (_, MailboxEntries) = receiver.recv().await;
    assert_eq!(entries.entries.len(), plaintexts.len());
    let first = &entries.entries[0];
    let envelope = dratchet_core::envelope::Envelope::decode(&first.envelope).unwrap();
    let (_, content) = bob_ratchet.decrypt_payload(&envelope).unwrap();
    let (_, expected) = dratchet_core::payload::untag_and_unpad(&chat(plaintexts[0])).unwrap();
    assert_eq!(content, expected);
    receiver
        .send(
            FrameTag::MailboxDelete,
            &MailboxDelete {
                mailbox_id: mailbox_id.clone(),
                entry_id: first.entry_id.clone(),
            },
        )
        .await;
    let (_, ack): (_, Ack) = receiver.recv().await;
    assert!(ack.ok);

    // --- The breach: full read access to everything the server holds. ---
    let (seized, mailbox_entry_count) = seize_everything(&state).await;

    // The worst case actually happened: undelivered ciphertext was present
    // at breach time, not already cleaned up — otherwise this test would
    // prove nothing.
    assert_eq!(
        mailbox_entry_count,
        plaintexts.len() - 1,
        "expected exactly the still-undelivered messages to be present in the breach"
    );

    for text in &plaintexts {
        assert!(
            !contains_bytes(&seized, text.as_bytes()),
            "plaintext {text:?} was found in confiscated server state — \
             the server saw content it must never see"
        );
    }

    let alice_dh_secret = alice.identity_dh_secret().to_bytes();
    let alice_signed_prekey_secret = alice.signed_prekey_secret().to_bytes();
    let bob_dh_secret = bob.identity_dh_secret().to_bytes();
    let bob_signed_prekey_secret = bob.signed_prekey_secret().to_bytes();
    for (who, secret) in [
        ("alice's identity DH secret", alice_dh_secret.as_slice()),
        (
            "alice's signed prekey secret",
            alice_signed_prekey_secret.as_slice(),
        ),
        ("bob's identity DH secret", bob_dh_secret.as_slice()),
        (
            "bob's signed prekey secret",
            bob_signed_prekey_secret.as_slice(),
        ),
    ] {
        assert!(
            !contains_bytes(&seized, secret),
            "{who} was found in confiscated server state — private key \
             material must never reach the server at all"
        );
    }
}
