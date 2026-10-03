//! Penetration-test finding, DRA-0024 (round 3, priority 1: gaining access
//! to conversations via impersonation), found auditing `ws.rs`'s
//! `publish_bundle` for any restriction on `username`'s *character set*
//! (only its length was checked, by `state::MAX_USERNAME_LEN`, DRA-0019).
//!
//! Nothing stopped registering a `username` that's visually
//! indistinguishable from an already-taken one, under whatever
//! `discriminator` the attacker likes: Cyrillic `а` (U+0430, "CYRILLIC
//! SMALL LETTER A") renders identically to Latin `a` (U+0061) in every
//! font a real client would use, so `"аlice"` (Cyrillic `а`) and
//! `"alice"` (Latin `a`) are two entirely distinct, independently
//! registrable identities a human reader can't tell apart by eye —
//! `username#NNNN` display included, since the discriminator doesn't
//! disambiguate the *username* text itself.
//!
//! **Fixed**: `state::username_has_only_allowed_characters` — a narrow,
//! ASCII-only allowlist (`[A-Za-z0-9_-]`, non-empty), checked in
//! `publish_bundle` right alongside the existing length cap. Deliberately
//! narrow rather than a full Unicode confusables-skeleton solution (real
//! feature work, not a bounded fix) — this closes the specific homograph
//! attack outright for the ASCII case, at the accepted cost of non-ASCII
//! handles not being supported at all.

mod common;

use common::*;
use dratchet_core::account::Account;
use dratchet_server::protocol::*;

fn bundle_with_username(account: &Account, username: &str) -> PrekeyBundleWire {
    let core_bundle = account.publish_bundle(false).unwrap();
    let registration_pow = Some(dratchet_server::abuse::solve_registration_pow(
        username,
        1,
        &core_bundle.identity_public_key,
    ));
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
        one_time_prekeys: Vec::new(),
        registration_pow,
    }
}

#[tokio::test]
async fn a_cyrillic_lookalike_username_cannot_impersonate_a_real_one() {
    let url = spawn_server().await;

    // The real "alice" (Latin 'a'), registered first, exactly as a
    // legitimate user would.
    let alice = Account::generate().unwrap();
    let mut alice_conn = TestClient::connect(&url).await;
    alice_conn.authenticate(&alice).await;
    alice_conn
        .send(
            FrameTag::PublishBundle,
            &PublishBundle {
                bundle: bundle_with_username(&alice, "alice"),
            },
        )
        .await;
    let (tag, ack): (_, Ack) = alice_conn.recv().await;
    assert_eq!(tag, FrameTag::Ack);
    assert!(ack.ok, "the real, ASCII 'alice' must register normally");

    // An attacker registers a Cyrillic lookalike -- visually identical,
    // a distinct string, a distinct identity.
    let cyrillic_lookalike = "\u{0430}lice"; // Cyrillic а + "lice"
    assert_ne!(
        cyrillic_lookalike, "alice",
        "sanity check: the two strings really are different"
    );
    let mallory = Account::generate().unwrap();
    let mut mallory_conn = TestClient::connect(&url).await;
    mallory_conn.authenticate(&mallory).await;
    mallory_conn
        .send(
            FrameTag::PublishBundle,
            &PublishBundle {
                bundle: bundle_with_username(&mallory, cyrillic_lookalike),
            },
        )
        .await;
    let (tag, err): (_, ErrorFrame) = mallory_conn.recv().await;
    assert_eq!(
        tag,
        FrameTag::Error,
        "FIX VERIFIED: a visually-indistinguishable non-ASCII lookalike username must be \
         rejected outright, not registered as a separate, impersonation-capable identity"
    );
    assert!(err.message.to_lowercase().contains("ascii"));
}

#[tokio::test]
async fn an_empty_username_is_rejected() {
    let url = spawn_server().await;
    let account = Account::generate().unwrap();
    let mut conn = TestClient::connect(&url).await;
    conn.authenticate(&account).await;
    conn.send(
        FrameTag::PublishBundle,
        &PublishBundle {
            bundle: bundle_with_username(&account, ""),
        },
    )
    .await;
    let (tag, _err): (_, ErrorFrame) = conn.recv().await;
    assert_eq!(tag, FrameTag::Error, "an empty username must be rejected");
}

#[tokio::test]
async fn ordinary_ascii_usernames_with_underscores_and_hyphens_still_work() {
    let url = spawn_server().await;
    let account = Account::generate().unwrap();
    let mut conn = TestClient::connect(&url).await;
    conn.authenticate(&account).await;
    conn.send(
        FrameTag::PublishBundle,
        &PublishBundle {
            bundle: bundle_with_username(&account, "real_user-42"),
        },
    )
    .await;
    let (tag, ack): (_, Ack) = conn.recv().await;
    assert_eq!(tag, FrameTag::Ack);
    assert!(
        ack.ok,
        "the fix must not be overly strict -- ordinary ASCII handles with underscores/hyphens \
         must still register normally"
    );
}
