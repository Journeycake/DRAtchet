//! Item 3 of the wipe-atomicity edge-case sweep (see
//! `docs/DELIVERY_FAILURE_FINDINGS.md`'s finding #34 and item-2
//! confirmation): does anything actually stop two overlapping
//! `receive_pending` calls for the *same* conversation from racing each
//! other, or is that only true by accident of how `poll_loop` happens to
//! call it today?
//!
//! **The type system does not rule this out.** `receive_pending` takes
//! `db: &Db` (a shared reference — `Db`'s own methods all take `&self`
//! and rely on `redb`'s internal transaction isolation, not exclusive
//! access) and `conn: &mut Connection` (exclusive, but only over *one*
//! `Connection` value — nothing stops a second, independently-
//! authenticated `Connection` for the same account from existing and
//! being used concurrently). The only reason this doesn't happen in the
//! shipped app is architectural, not a type-level guarantee:
//! `ui/src-tauri/src/lib.rs`'s `poll_loop` is the sole production call
//! site, it's spawned exactly once, and every call already runs inside a
//! `for` loop holding `state.conn`'s single shared `tokio::sync::Mutex`
//! across the whole `.await` — which incidentally serializes every
//! `receive_pending` call in the app, not just same-conversation ones.
//! That's a caller-side invariant, not something `receive_pending`'s own
//! signature enforces — a future caller (a manual "sync now" command on
//! its own connection, or a per-contact-parallel rewrite of the poll
//! loop) could violate it silently.
//!
//! This test proves what actually happens when that invariant is
//! violated, rather than leaving it as a hypothetical: two independent,
//! separately-authenticated `Connection`s for the same account
//! (`bob`/`bob2`) both call `receive_pending` for the *same* contact at
//! the *same* time via `tokio::join!`, racing against two real messages
//! sitting in the mailbox. No mocks — a real server, real ratchet state,
//! a real race via genuine concurrent `.await`s, not an artificial delay
//! or a mutex forced open.

use std::sync::Arc;

use dratchet_app::{
    add_contact_by_username, generate_pairing_code, list_messages, open_account,
    publish_own_bundle, receive_first_contact_attempts, receive_pending, send_message,
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

/// Confirms the race is real and characterizes exactly what it does:
/// whether messages get lost, duplicated, or merely reordered, and —the
/// question that actually matters for the app's own health— whether the
/// ratchet survives usable enough that a message sent *after* the race
/// still decrypts normally, or the conversation is left permanently
/// wedged.
#[tokio::test]
async fn two_connections_racing_receive_pending_for_the_same_conversation() {
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
    let bob_contact = receive_first_contact_attempts(&db_bob, &mut bob_conn, &mut bob)
        .await
        .unwrap()
        .into_iter()
        .next()
        .unwrap();

    // Complete the routing-id exchange first, same as
    // `receive_pending_resilience.rs` — isolates this test to the race
    // itself, not the separate shared-bootstrap-inbox limitation.
    receive_pending(&db_alice, &mut alice_conn, &alice, &alice_contact)
        .await
        .unwrap();
    let alice_contact = db_alice
        .load_contact(&alice_contact.fingerprint)
        .unwrap()
        .unwrap();
    receive_pending(&db_bob, &mut bob_conn, &bob, &bob_contact)
        .await
        .unwrap();
    let bob_contact = db_bob
        .load_contact(&bob_contact.fingerprint)
        .unwrap()
        .unwrap();

    // Two real messages queued in Bob's mailbox before either racing call
    // starts, so both connections' `MailboxFetch` have a real, identical
    // chance of observing the same entries.
    send_message(&db_alice, &mut alice_conn, &alice, &alice_contact, b"one")
        .await
        .unwrap();
    send_message(&db_alice, &mut alice_conn, &alice, &alice_contact, b"two")
        .await
        .unwrap();

    // A second, independent, separately-authenticated connection for the
    // *same* account — nothing about `receive_pending`'s own signature
    // stops this from existing alongside `bob_conn`.
    let mut bob_conn2 = Connection::connect(&url).await.unwrap();
    bob_conn2.authenticate(&bob).await.unwrap();

    let (result_a, result_b) = tokio::join!(
        receive_pending(&db_bob, &mut bob_conn, &bob, &bob_contact),
        receive_pending(&db_bob, &mut bob_conn2, &bob, &bob_contact),
    );

    // Neither call is expected to hard-error even under the race —
    // `apply_entry`'s failure modes are about malformed *content*, not
    // concurrent access; a hard `Err` here would itself be a new finding.
    let outcome_a = result_a.expect("first racing receive_pending call");
    let outcome_b = result_b.expect("second racing receive_pending call");

    let total_delivered = outcome_a.messages.len() + outcome_b.messages.len();
    let stored = list_messages(&db_bob, &bob, &bob_contact).unwrap();
    let stored_incoming: Vec<_> = stored.iter().filter(|m| !m.sender_is_local).collect();

    println!(
        "call A delivered {} message(s), call B delivered {} message(s); \
         {} incoming message(s) now in the store",
        outcome_a.messages.len(),
        outcome_b.messages.len(),
        stored_incoming.len(),
    );

    // The two messages must not simply vanish — every worthwhile outcome
    // here still requires content survival, whatever else the race does
    // to the bookkeeping around it.
    assert!(
        total_delivered >= 2 || stored_incoming.len() >= 2,
        "SEVERE: the race lost content — neither call's return value nor the store shows both \
         'one' and 'two' anywhere after two overlapping receive_pending calls"
    );

    if total_delivered > 2 || stored_incoming.len() > 2 {
        println!(
            "CONFIRMED FINDING: two overlapping receive_pending calls for the same conversation \
             duplicate content — {total_delivered} total delivered across both calls' return \
             values, {} persisted in the store, for only 2 real messages sent. This is the \
             concrete failure this test exists to characterize, not a test bug: see this file's \
             module doc for why the type system permits it and why it doesn't happen in the \
             shipped app today.",
            stored_incoming.len()
        );
    }

    // The health check that actually matters: is the conversation still
    // usable afterward, or did the race leave the ratchet in a state
    // where legitimate future messages stop decrypting? A last-write-wins
    // `db.save_ratchet` at the end of each call means whichever call
    // finishes last fully determines the persisted state — if that
    // state is internally self-consistent (even if it discarded the
    // other call's in-memory progress), a subsequent message should
    // still round-trip normally.
    send_message(
        &db_alice,
        &mut alice_conn,
        &alice,
        &alice_contact,
        b"after the race",
    )
    .await
    .unwrap();
    let post_race = receive_pending(&db_bob, &mut bob_conn, &bob, &bob_contact).await;

    match post_race {
        Ok(outcome)
            if outcome
                .messages
                .iter()
                .any(|m| m.content == b"after the race") =>
        {
            println!(
                "CONFIRMED: the conversation survived the race — a message sent afterward still \
                 decrypts normally, so whichever call's save_ratchet won left a self-consistent, \
                 still-usable ratchet state (data may have been duplicated above, but the \
                 conversation itself was not permanently wedged)."
            );
        }
        Ok(outcome) => panic!(
            "SEVERE: a message sent after the race did not decrypt as expected (got {} message(s), \
             none matching) — the race left the ratchet desynced from Alice's side, not just \
             duplicated: {:?}",
            outcome.messages.len(),
            outcome.messages.iter().map(|m| &m.content).collect::<Vec<_>>()
        ),
        Err(e) => panic!(
            "SEVERE: receive_pending itself now fails after the race ({e}) — the conversation is \
             permanently wedged, not just duplicated"
        ),
    }
}
