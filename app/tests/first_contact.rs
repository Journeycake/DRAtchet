//! Real end-to-end proof of `docs/ARCHITECTURE.md` §6.4's pairing-code-
//! gated add-contact flow — two real accounts, real self-registration
//! (`publish_own_bundle`) against a real spawned `dratchet_server::app()`,
//! no mocks, matching this project's standing rule. Covers both the
//! success path and the specific property this design exists for: a
//! wrong or missing code must leave no trace at all, not just fail
//! visibly.

use std::sync::Arc;

use dratchet_app::{
    add_contact_by_username, generate_pairing_code, open_account, publish_own_bundle,
    receive_first_contact_attempts, receive_pending, rename_own_profile, send_message,
};
use dratchet_client::net::Connection;
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

#[tokio::test]
async fn correct_code_creates_a_verified_contact_on_both_sides_and_they_can_chat() {
    let url = spawn_server().await;

    let db_alice = Arc::new(temp_db());
    let mut alice = open_account(&db_alice).unwrap();
    let mut alice_conn = Connection::connect(&url).await.unwrap();
    alice_conn.authenticate(&alice).await.unwrap();
    let alice_profile = publish_own_bundle(&db_alice, &mut alice_conn, &mut alice, "alice")
        .await
        .unwrap();

    let db_bob = Arc::new(temp_db());
    let mut bob = open_account(&db_bob).unwrap();
    let mut bob_conn = Connection::connect(&url).await.unwrap();
    bob_conn.authenticate(&bob).await.unwrap();
    let bob_profile = publish_own_bundle(&db_bob, &mut bob_conn, &mut bob, "bob")
        .await
        .unwrap();

    // Bob generates a code and (in reality) reads it out to Alice over an
    // already-trusted channel — here, just handed directly to her call.
    let code = generate_pairing_code(&db_bob).unwrap();

    let alice_contact = add_contact_by_username(
        &db_alice,
        &mut alice_conn,
        &alice,
        &alice_profile,
        &bob_profile.username,
        bob_profile.discriminator,
        &code.code,
    )
    .await
    .unwrap();
    assert_eq!(alice_contact.username.as_deref(), Some("bob"));
    assert_eq!(
        alice_contact.verification_state,
        dratchet_store::VerificationState::Verified
    );

    let new_contacts = receive_first_contact_attempts(&db_bob, &mut bob_conn, &mut bob)
        .await
        .unwrap();
    assert_eq!(new_contacts.len(), 1, "bob should discover the attempt");
    let bob_contact = &new_contacts[0];
    assert_eq!(bob_contact.username.as_deref(), Some("alice"));
    assert_eq!(
        bob_contact.verification_state,
        dratchet_store::VerificationState::Verified
    );
    assert_eq!(
        bob_contact.fingerprint,
        alice.identity.fingerprint().as_bytes()
    );

    // The pairing code must be consumed — single-use, per §6.4.
    assert!(
        db_bob.load_pairing_code().unwrap().is_none(),
        "a matched code must be consumed"
    );

    // Routing-id exchange: alice already sent hers as part of
    // add_contact_by_username; bob announced his inside
    // receive_first_contact_attempts. Each needs to receive the other's
    // once to fully transition off the bootstrap mailbox.
    let received = receive_pending(&db_alice, &mut alice_conn, &alice, &alice_contact)
        .await
        .unwrap();
    assert!(received.messages.is_empty());
    let alice_contact = db_alice
        .load_contact(&alice_contact.fingerprint)
        .unwrap()
        .unwrap();

    let received = receive_pending(&db_bob, &mut bob_conn, &bob, bob_contact)
        .await
        .unwrap();
    assert!(received.messages.is_empty());
    let bob_contact = db_bob
        .load_contact(&bob_contact.fingerprint)
        .unwrap()
        .unwrap();

    // Now a real chat message round-trips.
    let sent = send_message(
        &db_alice,
        &mut alice_conn,
        &alice,
        &alice_contact,
        b"hi bob, it's alice",
    )
    .await
    .unwrap();
    assert_eq!(sent.content, b"hi bob, it's alice");

    let received = receive_pending(&db_bob, &mut bob_conn, &bob, &bob_contact)
        .await
        .unwrap();
    assert_eq!(received.messages.len(), 1);
    assert_eq!(received.messages[0].content, b"hi bob, it's alice");
}

/// If `bob_generates_a_code` is true, Bob generates a real code and Alice
/// is given a guaranteed-different guess; otherwise Bob never generates
/// one at all and Alice sends an arbitrary code into the void. Either way
/// the attempt must fail invisibly. Returns whether Bob's side discovered
/// anything.
async fn attempt_with_code(bob_generates_a_code: bool) -> bool {
    let url = spawn_server().await;

    let db_alice = Arc::new(temp_db());
    let mut alice = open_account(&db_alice).unwrap();
    let mut alice_conn = Connection::connect(&url).await.unwrap();
    alice_conn.authenticate(&alice).await.unwrap();
    let alice_profile = publish_own_bundle(&db_alice, &mut alice_conn, &mut alice, "alice")
        .await
        .unwrap();

    let db_bob = Arc::new(temp_db());
    let mut bob = open_account(&db_bob).unwrap();
    let mut bob_conn = Connection::connect(&url).await.unwrap();
    bob_conn.authenticate(&bob).await.unwrap();
    let bob_profile = publish_own_bundle(&db_bob, &mut bob_conn, &mut bob, "bob")
        .await
        .unwrap();

    let alice_code = if bob_generates_a_code {
        let real = generate_pairing_code(&db_bob).unwrap().code;
        // Flip the first digit to guarantee a different 6-digit string.
        let first: u32 = real[..1].parse().unwrap();
        format!("{}{}", (first + 1) % 10, &real[1..])
    } else {
        "123456".to_string()
    };

    add_contact_by_username(
        &db_alice,
        &mut alice_conn,
        &alice,
        &alice_profile,
        &bob_profile.username,
        bob_profile.discriminator,
        &alice_code,
    )
    .await
    .unwrap();

    let new_contacts = receive_first_contact_attempts(&db_bob, &mut bob_conn, &mut bob)
        .await
        .unwrap();
    let discovered = !new_contacts.is_empty();

    assert!(
        db_bob.list_contacts().unwrap().is_empty(),
        "no contact should ever be created on a failed attempt"
    );

    // Re-fetching the same (now-drained) inbox must come back empty too —
    // the attempt left no trace behind to reprocess or discover later.
    let again = receive_first_contact_attempts(&db_bob, &mut bob_conn, &mut bob)
        .await
        .unwrap();
    assert!(
        again.is_empty(),
        "the mailbox entry must be consumed either way, not left to reprocess"
    );

    discovered
}

#[tokio::test]
async fn a_wrong_code_leaves_no_trace_even_though_a_real_one_was_generated() {
    assert!(!attempt_with_code(true).await);
}

#[tokio::test]
async fn no_code_generated_at_all_leaves_no_trace() {
    // The strictest case: there is no live pairing code for anything to
    // possibly match — a leaked/guessed username alone must never reach
    // anyone.
    assert!(!attempt_with_code(false).await);
}

/// A rename must release the old handle (not just at the raw server-state
/// level `renaming_releases_the_old_username` in `server/tests/
/// integration.rs` already proves, but through the real app-layer API a
/// client actually calls) and the new handle must work end to end for
/// add-contact.
#[tokio::test]
async fn renaming_releases_the_old_username_through_the_app_api() {
    let url = spawn_server().await;

    let db_alice = Arc::new(temp_db());
    let mut alice = open_account(&db_alice).unwrap();
    let mut alice_conn = Connection::connect(&url).await.unwrap();
    alice_conn.authenticate(&alice).await.unwrap();
    publish_own_bundle(&db_alice, &mut alice_conn, &mut alice, "alice")
        .await
        .unwrap();
    let renamed = rename_own_profile(&db_alice, &mut alice_conn, &mut alice, "alice2")
        .await
        .unwrap();
    assert_eq!(renamed.username, "alice2");

    let db_bob = Arc::new(temp_db());
    let mut bob = open_account(&db_bob).unwrap();
    let mut bob_conn = Connection::connect(&url).await.unwrap();
    bob_conn.authenticate(&bob).await.unwrap();
    let bob_profile = publish_own_bundle(&db_bob, &mut bob_conn, &mut bob, "bob")
        .await
        .unwrap();
    let code = generate_pairing_code(&db_bob).unwrap();

    // The old handle must no longer resolve to anything at all.
    let old_handle_result = add_contact_by_username(
        &db_bob,
        &mut bob_conn,
        &bob,
        &bob_profile,
        "alice",
        renamed.discriminator,
        &code.code,
    )
    .await;
    assert!(
        matches!(old_handle_result, Err(dratchet_app::Error::NoSuchAccount)),
        "the pre-rename username must no longer resolve: {old_handle_result:?}"
    );

    // The new handle works normally.
    let contact = add_contact_by_username(
        &db_bob,
        &mut bob_conn,
        &bob,
        &bob_profile,
        "alice2",
        renamed.discriminator,
        &code.code,
    )
    .await
    .unwrap();
    assert_eq!(contact.username.as_deref(), Some("alice2"));
}
