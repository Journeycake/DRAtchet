//! Penetration-test finding, DRA-0019 (round 2, priority 3: denial of
//! service against *all clients* — a second, distinct route to the same
//! class of harm as DRA-0018, this time through the directory rather
//! than mailboxes), found auditing `ws.rs`'s `publish_bundle`/
//! `to_core_bundle` for any size or count validation on `PublishBundle`'s
//! fields. There is none on `username` (an arbitrary-length `String`) or
//! `one_time_prekeys` (an arbitrary-length `Vec`, each entry's `key`
//! itself an arbitrary-length `Vec<u8>` never checked against the 32
//! bytes a real X25519 public key actually is — only checked, lazily,
//! whichever individual key a later `FetchBundle` happens to consume).
//!
//! `PublishBundle` deliberately requires no authentication (self-verified
//! by the bundle's own signature chain — see `ws.rs`'s module doc), and
//! `Inner::directory` is explicitly documented
//! (`pruning.rs`'s module doc) as "unbounded-but-intentional, not a
//! pruning target" — meaning, unlike the mailbox store, **nothing ever
//! removes a directory entry**. A single oversized `PublishBundle`
//! therefore isn't a transient flood that self-heals on the next prune
//! sweep (DRA-0015's mailboxes) — it is permanently resident in server
//! memory (and on disk too, if directory persistence is enabled) for as
//! long as the server runs, unless an operator manually intervenes.
//!
//! The real one-time-prekey batch size any legitimate client actually
//! publishes is 10 (`app::ONE_TIME_PREKEY_BATCH`). Pre-fix, this test
//! proved a single `PublishBundle` could smuggle in a batch three orders
//! of magnitude larger than that, and the server accepted and stored
//! every one of them without question.
//!
//! **Fixed**: `state::MAX_ONE_TIME_PREKEYS_PER_PUBLISH` (100, 10x the
//! real batch size) and `state::MAX_USERNAME_LEN` (64), both checked in
//! `publish_bundle` before any signature verification or directory work.
//! Each individual key's byte length is also now checked against the
//! fixed 32 bytes a real X25519 public key always is, closing a second,
//! narrower gap: previously an oversized *individual* key could still
//! sit in the directory even within a small-enough batch, since nothing
//! validated a key's length until some later `FetchBundle` happened to
//! consume that exact one. This test now proves the fix: the huge batch
//! is rejected outright, while a batch right at the cap still succeeds.

mod common;

use std::sync::Arc;

use common::*;
use dratchet_core::account::Account;
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

fn bundle_with_otp_batch(
    account: &mut Account,
    username: &str,
    batch_size: u32,
) -> PrekeyBundleWire {
    // Generated before `publish_bundle`, matching real callers' own
    // ordering (`app::publish_own_bundle`).
    let otp_publics = account.generate_one_time_prekeys(batch_size);
    let core_bundle = account.publish_bundle(false).unwrap();
    let registration_pow = Some(dratchet_server::abuse::solve_registration_pow(
        username,
        1,
        &core_bundle.identity_public_key,
    ));
    let one_time_prekeys: Vec<OneTimePrekeyWire> = otp_publics
        .into_iter()
        .map(|otp| OneTimePrekeyWire {
            id: otp.id,
            key: otp.public.as_bytes().to_vec(),
        })
        .collect();
    PrekeyBundleWire {
        username: username.to_string(),
        discriminator: 1,
        identity_key: core_bundle.identity_public_key,
        identity_dh_public: core_bundle.identity_dh_public.as_bytes().to_vec(),
        identity_dh_signature: core_bundle.identity_dh_signature,
        signed_prekey_id: core_bundle.signed_prekey.id,
        signed_prekey: core_bundle.signed_prekey.public.as_bytes().to_vec(),
        signed_prekey_sig: core_bundle.signed_prekey.signature,
        signed_prekey_expires_at: 0,
        one_time_prekeys,
        registration_pow,
    }
}

#[tokio::test]
async fn a_single_publish_bundle_cannot_smuggle_in_a_huge_one_time_prekey_batch() {
    let (url, state) = spawn_server_with_state().await;

    // 10,000 one-time prekeys in a single publish -- 1,000x the real
    // batch size (10) any legitimate client ever sends at once -- must
    // now be rejected outright.
    let mut attacker = Account::generate().unwrap();
    let mut conn = TestClient::connect(&url).await;
    conn.authenticate(&attacker).await;
    let huge_wire = bundle_with_otp_batch(&mut attacker, "bloater", 10_000);
    conn.send(
        FrameTag::PublishBundle,
        &PublishBundle { bundle: huge_wire },
    )
    .await;
    let (tag, err): (_, ErrorFrame) = conn.recv().await;
    assert_eq!(
        tag,
        FrameTag::Error,
        "FIX VERIFIED: a PublishBundle with far more one-time prekeys than any real client \
         ever sends must be rejected, not permanently stored in the never-pruned directory"
    );
    assert!(err.message.to_lowercase().contains("many"));
    assert!(
        !state
            .inner
            .read()
            .await
            .directory
            .values()
            .any(|s| s.bundle.username == "bloater"),
        "a rejected publish must not create a directory entry at all"
    );

    // A batch right at the cap -- 10x the real batch size, still
    // comfortably generous -- must still succeed normally.
    let mut legit = Account::generate().unwrap();
    let mut legit_conn = TestClient::connect(&url).await;
    legit_conn.authenticate(&legit).await;
    let capacity = dratchet_server::state::MAX_ONE_TIME_PREKEYS_PER_PUBLISH as u32;
    let ok_wire = bundle_with_otp_batch(&mut legit, "legit-batch", capacity);
    legit_conn
        .send(FrameTag::PublishBundle, &PublishBundle { bundle: ok_wire })
        .await;
    let (tag, ack): (_, Ack) = legit_conn.recv().await;
    assert_eq!(tag, FrameTag::Ack);
    assert!(
        ack.ok,
        "a batch exactly at the cap must still succeed -- the fix must not be overly strict"
    );
}
