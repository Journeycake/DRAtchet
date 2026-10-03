//! Item 3 of the wipe-atomicity edge-case sweep (see
//! `docs/DELIVERY_FAILURE_FINDINGS.md`'s finding #34 and item-2
//! confirmation), later tracked as DRA-0012: does anything actually stop
//! two overlapping `receive_pending` calls for the *same* conversation
//! from racing each other?
//!
//! **Originally, no — confirmed here, not just reasoned about.**
//! `receive_pending` used to take `db: &Db` (a shared reference — `Db`'s
//! own methods all take `&self` and rely on `redb`'s internal
//! transaction isolation, not exclusive access) and `conn: &mut
//! Connection` (exclusive, but only over *one* `Connection` value —
//! nothing stopped a second, independently-authenticated `Connection`
//! for the same account from existing and being used concurrently). The
//! only reason this didn't happen in the shipped app was architectural,
//! not a type-level guarantee: `ui/src-tauri/src/lib.rs`'s `poll_loop`
//! is the sole production call site, it's spawned exactly once, and
//! every call already runs inside a `for` loop holding `state.conn`'s
//! single shared `tokio::sync::Mutex` across the whole `.await` — which
//! incidentally serialized every `receive_pending` call in the app, not
//! just same-conversation ones. That was a caller-side invariant, not
//! something `receive_pending`'s own signature enforced — a future
//! caller (a manual "sync now" command on its own connection, or a
//! per-contact-parallel rewrite of the poll loop) could have violated it
//! silently.
//!
//! **Fixed in two layers**: `receive_pending` now acquires
//! `Db::receive_lock(conv_id)` — a per-conversation `tokio::sync::Mutex`
//! — for the whole call, so a second overlapping call for the same
//! conversation blocks until the first finishes, regardless of caller.
//! Behind that, `Db::save_received_message_idempotent` also refuses to
//! store a second message for the same `(recv_dh_pub, recv_n)` ratchet
//! position, as a backstop against any caller that bypasses the
//! in-process lock entirely (a second OS process against the same
//! on-disk `Db` file, for instance).
//!
//! This test proves the fix holds under the exact scenario that used to
//! duplicate content: two independent, separately-authenticated
//! `Connection`s for the same account (`bob`/`bob2`) both call
//! `receive_pending` for the *same* contact at the *same* time via
//! `tokio::join!`, racing against two real messages sitting in the
//! mailbox. No mocks — a real server, real ratchet state, a real
//! concurrent `.await` race, not an artificial delay or a mutex forced
//! open.

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

/// Confirms the fix: two overlapping `receive_pending` calls for the
/// same conversation no longer lose, duplicate, or reorder content, and
/// the conversation remains fully usable afterward (a message sent after
/// the race still decrypts normally).
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

    // DRA-0012, fixed: `receive_lock` serializes the two calls for this
    // conversation (call B blocks until call A's `MailboxFetch` has
    // already consumed and deleted both entries, so call B's own fetch
    // sees an empty mailbox and delivers 0), and
    // `save_received_message_idempotent` would refuse a duplicate even
    // if it didn't. Exactly 2 messages, no more, no fewer, either way.
    assert_eq!(
        total_delivered, 2,
        "the two calls' return values should together account for exactly the 2 real messages \
         sent, no loss and no duplication, now that receive_lock serializes them"
    );
    assert_eq!(
        stored_incoming.len(),
        2,
        "the store should hold exactly 2 incoming messages — a regression here would mean \
         either receive_lock or save_received_message_idempotent stopped doing its job"
    );

    // Belt-and-suspenders: confirms the conversation is still usable
    // afterward — a subsequent message from Alice should decrypt
    // normally against whatever `receive_lock`-serialized state call A
    // and call B left behind.
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
                "CONFIRMED: the conversation is fully healthy after the once-racing calls — a \
                 message sent afterward decrypts normally, with no data loss or duplication \
                 anywhere in this run."
            );
        }
        Ok(outcome) => {
            panic!(
            "SEVERE REGRESSION: a message sent after the race did not decrypt as expected (got \
             {} message(s), none matching) — receive_lock/save_received_message_idempotent no \
             longer keep the ratchet in sync: {:?}",
            outcome.messages.len(),
            outcome.messages.iter().map(|m| &m.content).collect::<Vec<_>>()
        )
        }
        Err(e) => panic!(
            "SEVERE REGRESSION: receive_pending itself now fails after the race ({e}) — the \
             conversation is permanently wedged"
        ),
    }
}
