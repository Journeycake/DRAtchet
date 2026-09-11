//! Real end-to-end proof of `docs/ARCHITECTURE.md` §6.1's reclaim-on-
//! connect mechanism: the directory (`server/src/state.rs`) is in-memory
//! only, so a server restart forgets every registration, opening a window
//! in which someone else can claim a still-believed-owned
//! `username#NNNN` before the original device reconnects. Simulates a
//! restart with a second, independent `dratchet_server::app()` (fresh
//! state, same as a real restart would produce) and a squatter that
//! claims Alice's exact handle on it before Alice reconnects. No mocks,
//! matching this project's standing rule.

use std::sync::Arc;

use dratchet_app::{
    add_contact_by_username, announce_profile, generate_pairing_code, open_account,
    publish_own_bundle, receive_first_contact_attempts, receive_pending, reconcile_own_profile,
    ProfileReconciliation,
};
use dratchet_client::net::Connection;
use dratchet_core::account::Account;
use dratchet_server::abuse::solve_registration_pow;
use dratchet_server::protocol::{FrameTag, OneTimePrekeyWire, PrekeyBundleWire, PublishBundle};
use dratchet_store::Db;
use tokio::net::TcpListener;

async fn spawn_server() -> String {
    let (router, _state) = dratchet_server::app();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    format!("ws://{addr}/v1/ws")
}

fn temp_db() -> Db {
    let dir = tempfile::tempdir().unwrap().keep();
    Db::create(dir.join("test.redb"), "pw").unwrap()
}

/// Claim `username#discriminator` on `conn` with a brand-new, unrelated
/// account — simulating a squatter who reserves the exact handle Alice's
/// device still believes it owns, on a directory that has no memory of
/// her ever having registered it (a real restart, or here, a second,
/// independent server).
async fn squat(conn: &mut Connection, username: &str, discriminator: u16) {
    let mut squatter = Account::generate().unwrap();
    let otp_publics = squatter.generate_one_time_prekeys(1);
    let bundle = squatter.publish_bundle(false).unwrap();
    let wire = PrekeyBundleWire {
        username: username.to_string(),
        discriminator,
        identity_key: bundle.identity_public_key.clone(),
        identity_dh_public: bundle.identity_dh_public.as_bytes().to_vec(),
        identity_dh_signature: bundle.identity_dh_signature.clone(),
        signed_prekey_id: bundle.signed_prekey.id,
        signed_prekey: bundle.signed_prekey.public.as_bytes().to_vec(),
        signed_prekey_sig: bundle.signed_prekey.signature.clone(),
        signed_prekey_expires_at: 0,
        one_time_prekeys: otp_publics
            .into_iter()
            .map(|otp| OneTimePrekeyWire {
                id: otp.id,
                key: otp.public.as_bytes().to_vec(),
            })
            .collect(),
        registration_pow: Some(solve_registration_pow(
            username,
            discriminator,
            &bundle.identity_public_key,
        )),
    };
    conn.send(FrameTag::PublishBundle, &PublishBundle { bundle: wire })
        .await
        .unwrap();
    conn.recv_raw().await.unwrap();
}

#[tokio::test]
async fn a_squatted_handle_is_reclaimed_under_a_new_discriminator_and_broadcast_to_contacts() {
    let url1 = spawn_server().await;

    let db_alice = Arc::new(temp_db());
    let mut alice = open_account(&db_alice).unwrap();
    let mut alice_conn1 = Connection::connect(&url1).await.unwrap();
    alice_conn1.authenticate(&alice).await.unwrap();
    let alice_profile = publish_own_bundle(&db_alice, &mut alice_conn1, &mut alice, "alice")
        .await
        .unwrap();
    let old_discriminator = alice_profile.discriminator;

    let db_bob = Arc::new(temp_db());
    let mut bob = open_account(&db_bob).unwrap();
    let mut bob_conn1 = Connection::connect(&url1).await.unwrap();
    bob_conn1.authenticate(&bob).await.unwrap();
    let bob_profile = publish_own_bundle(&db_bob, &mut bob_conn1, &mut bob, "bob")
        .await
        .unwrap();

    // Pair Alice and Bob for real, and complete the routing-id exchange,
    // so there's a genuine established ratchet for `announce_profile` to
    // travel over — exactly the "already-Verified contact" precondition
    // `docs/ARCHITECTURE.md` §6.1 describes.
    let code = generate_pairing_code(&db_bob).unwrap();
    let alice_contact = add_contact_by_username(
        &db_alice,
        &mut alice_conn1,
        &alice,
        &alice_profile,
        &bob_profile.username,
        bob_profile.discriminator,
        &code.code,
    )
    .await
    .unwrap();
    let bob_new_contacts = receive_first_contact_attempts(&db_bob, &mut bob_conn1, &mut bob)
        .await
        .unwrap();
    let bob_contact = bob_new_contacts.into_iter().next().unwrap();

    receive_pending(&db_alice, &mut alice_conn1, &alice, &alice_contact)
        .await
        .unwrap();
    let alice_contact = db_alice
        .load_contact(&alice_contact.fingerprint)
        .unwrap()
        .unwrap();
    receive_pending(&db_bob, &mut bob_conn1, &bob, &bob_contact)
        .await
        .unwrap();

    // The "restart": a second, independent server with no memory of
    // either registration, on which a squatter claims Alice's exact old
    // handle before she gets a chance to reconnect.
    let url2 = spawn_server().await;
    let mut squatter_conn = Connection::connect(&url2).await.unwrap();
    squat(&mut squatter_conn, "alice", old_discriminator).await;

    // Alice reconnects and reconciles — the exact discriminator she
    // believed she owned is gone, so a *different* one is picked instead,
    // and she must be told.
    let mut alice_conn2 = Connection::connect(&url2).await.unwrap();
    alice_conn2.authenticate(&alice).await.unwrap();
    let reconciliation = reconcile_own_profile(&db_alice, &mut alice_conn2, &mut alice)
        .await
        .unwrap();
    let (old, new) = match reconciliation {
        ProfileReconciliation::DiscriminatorChanged { old, new } => (old, new),
        other => panic!("expected a discriminator change, got {other:?}"),
    };
    assert_eq!(old.username, "alice");
    assert_eq!(old.discriminator, old_discriminator);
    assert_eq!(new.username, "alice");
    assert_ne!(
        new.discriminator, old_discriminator,
        "the squatted discriminator must not be silently reused"
    );

    // Broadcasting the change requires zero key/ratchet changes — it's an
    // ordinary ratchet-encrypted control message over the conversation
    // that already exists.
    announce_profile(&db_alice, &mut alice_conn2, &alice, &alice_contact, &new)
        .await
        .unwrap();

    // Bob reconnects (to the same restarted server — no re-registration
    // needed just to read his own mailbox) and picks up the announcement.
    let mut bob_conn2 = Connection::connect(&url2).await.unwrap();
    bob_conn2.authenticate(&bob).await.unwrap();
    let alice_as_bob_knows_her = db_bob
        .load_contact(alice.identity.fingerprint().as_bytes())
        .unwrap()
        .unwrap();
    let outcome = receive_pending(&db_bob, &mut bob_conn2, &bob, &alice_as_bob_knows_her)
        .await
        .unwrap();

    assert_eq!(outcome.profile_changes.len(), 1);
    let notice = &outcome.profile_changes[0];
    assert_eq!(notice.fingerprint, alice.identity.fingerprint().as_bytes());
    assert_eq!(notice.old_handle, format!("alice#{old_discriminator:04}"));
    assert_eq!(notice.new_handle, format!("alice#{:04}", new.discriminator));

    let reloaded = db_bob
        .load_contact(alice.identity.fingerprint().as_bytes())
        .unwrap()
        .unwrap();
    assert_eq!(reloaded.username.as_deref(), Some("alice"));
    assert_eq!(reloaded.discriminator, Some(new.discriminator));
}

#[tokio::test]
async fn reconciling_an_unclaimed_handle_reclaims_it_unchanged() {
    let url1 = spawn_server().await;
    let db_alice = Arc::new(temp_db());
    let mut alice = open_account(&db_alice).unwrap();
    let mut alice_conn1 = Connection::connect(&url1).await.unwrap();
    alice_conn1.authenticate(&alice).await.unwrap();
    let profile = publish_own_bundle(&db_alice, &mut alice_conn1, &mut alice, "alice")
        .await
        .unwrap();

    // A "restart" with nobody squatting the old handle: reconciling
    // against a fresh server should reclaim exactly the same
    // username#discriminator, not silently reassign a new one.
    let url2 = spawn_server().await;
    let mut alice_conn2 = Connection::connect(&url2).await.unwrap();
    alice_conn2.authenticate(&alice).await.unwrap();
    let reconciliation = reconcile_own_profile(&db_alice, &mut alice_conn2, &mut alice)
        .await
        .unwrap();
    match reconciliation {
        ProfileReconciliation::Unchanged(reclaimed) => {
            assert_eq!(reclaimed.username, profile.username);
            assert_eq!(reclaimed.discriminator, profile.discriminator);
        }
        other => panic!("expected Unchanged, got {other:?}"),
    }
}

#[tokio::test]
async fn reconciling_before_ever_registering_is_a_no_op() {
    let url = spawn_server().await;
    let db = Arc::new(temp_db());
    let mut account = open_account(&db).unwrap();
    let mut conn = Connection::connect(&url).await.unwrap();
    conn.authenticate(&account).await.unwrap();
    let reconciliation = reconcile_own_profile(&db, &mut conn, &mut account)
        .await
        .unwrap();
    assert!(matches!(
        reconciliation,
        ProfileReconciliation::Unregistered
    ));
}
