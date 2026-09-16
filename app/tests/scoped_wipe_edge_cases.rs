//! Edge-case probes for the boundary-scoped remote wipe feature
//! (`ARCHITECTURE.md` §11.9a's "Boundary-scoped wipe on the peer's side"
//! note), pushing past the 5-client acceptance scenario in
//! `five_client_scoped_wipe_scenario.rs` into timing conditions that
//! scenario doesn't exercise: what happens when the peer is offline for
//! an extended stretch and catches up in one shot, and whether the
//! feature actually survives a real process restart rather than just
//! staying alive in one long-lived in-memory `Db` handle.
//!
//! `receive_pending` (`app/src/lib.rs`) processes every mailbox entry in
//! one fetched batch against a single `contact: &Contact` snapshot
//! captured once, before the loop — its own doc comment says so
//! explicitly ("Wipe-policy decisions below use this same stale-within-
//! the-batch snapshot"). That's correct for verification state (which
//! genuinely can't change mid-batch), but a policy announcement *can*
//! land earlier in the very same batch as the wipe request it's meant to
//! gate — and when it does, the wipe-request arm still reads the
//! *pre-batch* snapshot, not the boundary the announcement two entries
//! earlier in the same loop just persisted to disk. These tests confirm
//! that directly, on real mailbox traffic, rather than reasoning about it
//! from the source.

use std::sync::Arc;

use dratchet_app::{
    announce_routing_id, announce_wipe_policy, list_messages, receive_pending,
    record_verification_result, request_conversation_wipe, send_message,
};
use dratchet_client::net::Connection;
use dratchet_core::account::Account;
use dratchet_core::prekey::{OneTimePrekeyPublic, PrekeyBundle, SignedPrekeyPublic};
use dratchet_core::ratchet::{RatchetState, DEFAULT_MAX_SKIP};
use dratchet_core::x3dh::{self, bootstrap_mailbox_id};
use dratchet_server::protocol::*;
use dratchet_store::{Contact, Db, VerificationState};
use rand_core::{OsRng, RngCore};
use tokio::net::TcpListener;
use x25519_dalek::PublicKey;

async fn spawn_server() -> String {
    let (router, _state) = dratchet_server::app();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    format!("ws://{addr}/v1/ws")
}

/// Unlike other test files' `temp_db()`, this returns the *path* too —
/// several of these tests need to `Db::open` the same file again after
/// dropping the original handle, to prove persistence across a genuine
/// process restart rather than just continuity of one in-memory `Db`.
fn temp_db_path() -> std::path::PathBuf {
    let dir = tempfile::tempdir().unwrap().keep();
    dir.join("test.redb")
}

fn random_routing_id() -> Vec<u8> {
    let mut buf = [0u8; 32];
    OsRng.fill_bytes(&mut buf);
    buf.to_vec()
}

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

struct Paired {
    db_alice: Arc<Db>,
    alice: Account,
    alice_contact: Contact,
    alice_conn: Connection,
    path_bob: std::path::PathBuf,
    db_bob: Arc<Db>,
    bob: Account,
    bob_contact: Contact,
    bob_conn: Connection,
}

async fn pair(username_prefix: &str, discriminator: u16) -> Paired {
    let url = spawn_server().await;

    let mut bob = Account::generate().unwrap();
    let bob_otp_publics = bob.generate_one_time_prekeys(1);
    let bob_local_bundle = bob.publish_bundle(false).unwrap();
    let username = format!("{username_prefix}{:04x}", OsRng.next_u32() as u16);
    let bob_bundle_wire = PrekeyBundleWire {
        username: username.clone(),
        discriminator,
        identity_key: bob_local_bundle.identity_public_key.clone(),
        identity_dh_public: bob_local_bundle.identity_dh_public.as_bytes().to_vec(),
        identity_dh_signature: bob_local_bundle.identity_dh_signature.clone(),
        signed_prekey_id: bob_local_bundle.signed_prekey.id,
        signed_prekey: bob_local_bundle.signed_prekey.public.as_bytes().to_vec(),
        signed_prekey_sig: bob_local_bundle.signed_prekey.signature.clone(),
        signed_prekey_expires_at: 0,
        one_time_prekeys: bob_otp_publics
            .into_iter()
            .map(|otp| OneTimePrekeyWire {
                id: otp.id,
                key: otp.public.as_bytes().to_vec(),
            })
            .collect(),
        registration_pow: Some(dratchet_server::abuse::solve_registration_pow(
            &username,
            discriminator,
            &bob_local_bundle.identity_public_key,
        )),
    };
    let mut publisher = Connection::connect(&url).await.unwrap();
    let (_, _challenge): (_, AuthChallenge) = publisher.recv().await.unwrap();
    publisher
        .send(
            FrameTag::PublishBundle,
            &PublishBundle {
                bundle: bob_bundle_wire,
            },
        )
        .await
        .unwrap();

    let alice = Account::generate().unwrap();
    let mut fetcher = Connection::connect(&url).await.unwrap();
    let (_, _challenge): (_, AuthChallenge) = fetcher.recv().await.unwrap();
    fetcher
        .send(
            FrameTag::FetchBundle,
            &FetchBundle {
                username: username.clone(),
                discriminator,
            },
        )
        .await
        .unwrap();
    let (_, result): (_, BundleResult) = fetcher.recv().await.unwrap();
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
    let alice_ratchet = RatchetState::init_as_initiator(
        conv_id,
        init.root_key,
        core_bundle.signed_prekey.public,
        DEFAULT_MAX_SKIP,
    )
    .unwrap();

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
    let bob_ratchet = RatchetState::init_as_responder(
        conv_id,
        bob_root_key,
        bob.signed_prekey_secret().clone(),
        DEFAULT_MAX_SKIP,
    )
    .unwrap();

    let alice_fp = alice.identity.fingerprint().as_bytes().to_vec();
    let bob_fp = bob.identity.fingerprint().as_bytes().to_vec();
    let alice_routing_id = random_routing_id();
    let bob_routing_id = random_routing_id();

    let db_alice = Arc::new(Db::create(temp_db_path(), "pw").unwrap());
    db_alice.save_account(&alice).unwrap();
    let mut alice_contact = Contact {
        fingerprint: bob_fp.clone(),
        username: Some(username.clone()),
        discriminator: Some(discriminator),
        verification_state: VerificationState::Pending,
        mailbox_id: bootstrap_mailbox_id(&bob_fp).to_vec(),
        created_at: 0,
        local_routing_id: alice_routing_id.clone(),
        peer_routing_id: None,
        wipe_ask_before_delete: false,
        peer_wipe_ask_before_delete: None,
        wipe_include_session: false,
        peer_wipe_include_session: None,
        wipe_request_pending: false,
        wipe_boundary_timestamp: None,
        wipe_boundary_sequence: None,
        peer_wipe_boundary_timestamp: None,
        peer_wipe_boundary_sequence: None,
    };
    db_alice.save_contact(&alice_contact).unwrap();
    db_alice.save_ratchet(conv_id, &alice_ratchet).unwrap();

    let path_bob = temp_db_path();
    let db_bob = Arc::new(Db::create(&path_bob, "pw").unwrap());
    db_bob.save_account(&bob).unwrap();
    let mut bob_contact = Contact {
        fingerprint: alice_fp.clone(),
        username: None,
        discriminator: None,
        verification_state: VerificationState::Pending,
        mailbox_id: bootstrap_mailbox_id(&alice_fp).to_vec(),
        created_at: 0,
        local_routing_id: bob_routing_id.clone(),
        peer_routing_id: None,
        wipe_ask_before_delete: false,
        peer_wipe_ask_before_delete: None,
        wipe_include_session: false,
        peer_wipe_include_session: None,
        wipe_request_pending: false,
        wipe_boundary_timestamp: None,
        wipe_boundary_sequence: None,
        peer_wipe_boundary_timestamp: None,
        peer_wipe_boundary_sequence: None,
    };
    db_bob.save_contact(&bob_contact).unwrap();
    db_bob.save_ratchet(conv_id, &bob_ratchet).unwrap();

    let mut alice_conn = Connection::connect(&url).await.unwrap();
    alice_conn.authenticate(&alice).await.unwrap();
    let mut bob_conn = Connection::connect(&url).await.unwrap();
    bob_conn.authenticate(&bob).await.unwrap();

    announce_routing_id(
        &db_alice,
        &mut alice_conn,
        &alice,
        &alice_contact,
        alice_routing_id,
    )
    .await
    .unwrap();
    receive_pending(&db_bob, &mut bob_conn, &bob, &bob_contact)
        .await
        .unwrap();
    bob_contact = db_bob.load_contact(&alice_fp).unwrap().unwrap();

    announce_routing_id(&db_bob, &mut bob_conn, &bob, &bob_contact, bob_routing_id)
        .await
        .unwrap();
    receive_pending(&db_alice, &mut alice_conn, &alice, &alice_contact)
        .await
        .unwrap();
    alice_contact = db_alice.load_contact(&bob_fp).unwrap().unwrap();

    alice_contact = record_verification_result(&db_alice, alice_contact, true).unwrap();
    bob_contact = record_verification_result(&db_bob, bob_contact, true).unwrap();

    Paired {
        db_alice,
        alice,
        alice_contact,
        alice_conn,
        path_bob,
        db_bob,
        bob,
        bob_contact,
        bob_conn,
    }
}

/// **Edge case 1 — the announcement and the wipe request land in the
/// same fetched batch** (bob is offline for the entire stretch between
/// alice announcing her policy change and alice sending the wipe
/// request, then comes back online and does one `receive_pending` call
/// that fetches everything at once).
///
/// **Documented/intended behavior** (`ARCHITECTURE.md` §11.9a): bob
/// should keep the messages he already had *before* processing alice's
/// announcement and lose only the ones from after it — the same outcome
/// as `five_client_scoped_wipe_scenario.rs`'s `late_change_*` cases,
/// which only differ from this one in *when* bob happens to poll.
/// Whether bob polls once per message or once for the whole backlog is
/// not supposed to be part of the contract.
#[tokio::test]
async fn same_batch_announce_and_wipe_request_when_peer_is_offline_the_whole_time() {
    let Paired {
        db_alice,
        alice,
        mut alice_contact,
        mut alice_conn,
        path_bob: _,
        db_bob,
        bob,
        bob_contact,
        mut bob_conn,
    } = pair("edgeoffline", 5001).await;

    // Two pre-boundary messages, each fetched by a separate, real,
    // online `receive_pending` call — genuinely already stored before
    // any of this test's edge condition begins.
    for text in [&b"pre-boundary 1"[..], &b"pre-boundary 2"[..]] {
        send_message(&db_alice, &mut alice_conn, &alice, &alice_contact, text)
            .await
            .unwrap();
        receive_pending(&db_bob, &mut bob_conn, &bob, &bob_contact)
            .await
            .unwrap();
    }
    assert_eq!(
        list_messages(&db_bob, &bob, &bob_contact).unwrap().len(),
        2,
        "setup sanity: bob genuinely has both pre-boundary messages already"
    );

    // From here on, bob does NOT call receive_pending again until the
    // very end — everything alice does now queues up in his mailbox.
    alice_contact = announce_wipe_policy(
        &db_alice,
        &mut alice_conn,
        &alice,
        &alice_contact,
        false,
        true,
    )
    .await
    .unwrap();
    for text in [&b"post-boundary 1"[..], &b"post-boundary 2"[..]] {
        send_message(&db_alice, &mut alice_conn, &alice, &alice_contact, text)
            .await
            .unwrap();
    }
    request_conversation_wipe(&db_alice, &mut alice_conn, &alice, &alice_contact)
        .await
        .unwrap();

    // Bob comes back online and fetches everything in one batch: the
    // policy announce, both post-boundary messages, and the wipe
    // request, all processed by one `receive_pending` call.
    let outcome = receive_pending(&db_bob, &mut bob_conn, &bob, &bob_contact)
        .await
        .unwrap();
    assert_eq!(
        outcome.messages.len(),
        2,
        "sanity: both post-boundary messages really were decrypted and saved during this batch"
    );
    assert!(
        outcome.wipe_activity,
        "sanity: the wipe request really was processed in this same batch"
    );

    let bob_contact_after = db_bob
        .load_contact(&bob_contact.fingerprint)
        .unwrap()
        .unwrap();
    let bob_remaining = list_messages(&db_bob, &bob, &bob_contact_after).unwrap();

    println!(
        "\n[edge: same-batch announce+wipe] expected: bob keeps 2 pre-boundary messages, loses 2 post-boundary"
    );
    println!(
        "[edge: same-batch announce+wipe] actual:   bob keeps {} message(s): {:?}",
        bob_remaining.len(),
        bob_remaining
            .iter()
            .map(|m| String::from_utf8_lossy(&m.content).to_string())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        bob_remaining.len(),
        2,
        "EXPECTED-PER-DOCS: bob should keep exactly the 2 pre-boundary messages regardless of \
         whether the announcement and the wipe request happened to arrive in the same poll — \
         if this fails, the boundary the announce just persisted mid-batch was not honored by \
         the wipe-request arm later in that same batch (receive_pending's documented \
         stale-within-the-batch `contact` snapshot)"
    );
}

/// **Edge case 2 — the same stale-snapshot mechanism, but on the older,
/// pre-existing `ask_before_delete` gate rather than the new boundary
/// feature.** Not something this session's boundary-scoping work
/// introduced — `receive_pending`'s single-snapshot-per-batch design
/// predates it — but it sits on the exact same wipe-request code path
/// this audit is exercising, so it belongs in this pass.
///
/// Bob has *already* told alice (in an earlier, separate, real exchange)
/// that he wants ask-before-delete. Alice now announces the matching
/// preference on her side *and* sends the wipe request in the same
/// offline stretch bob doesn't poll during.
///
/// **Documented/intended behavior**: once both sides have opted into
/// ask-before-delete, an incoming wipe request should set
/// `wipe_request_pending` and touch nothing — never auto-comply,
/// regardless of polling cadence.
#[tokio::test]
async fn same_batch_ask_before_delete_announce_and_wipe_request() {
    let Paired {
        db_alice,
        alice,
        mut alice_contact,
        mut alice_conn,
        path_bob: _,
        db_bob,
        bob,
        mut bob_contact,
        mut bob_conn,
    } = pair("edgeaskfirst", 5002).await;

    // Bob announces his own ask-before-delete preference first, in a
    // real, separate, online round trip — this alone is enough to set
    // bob's own local `wipe_ask_before_delete = true` immediately.
    bob_contact = announce_wipe_policy(&db_bob, &mut bob_conn, &bob, &bob_contact, true, false)
        .await
        .unwrap();
    receive_pending(&db_alice, &mut alice_conn, &alice, &alice_contact)
        .await
        .unwrap();
    alice_contact = db_alice
        .load_contact(&alice_contact.fingerprint)
        .unwrap()
        .unwrap();

    // From here on, bob does not poll again until the very end. Alice
    // announces her own matching preference *and* sends the wipe
    // request in the same offline stretch.
    announce_wipe_policy(
        &db_alice,
        &mut alice_conn,
        &alice,
        &alice_contact,
        true,
        false,
    )
    .await
    .unwrap();
    send_message(
        &db_alice,
        &mut alice_conn,
        &alice,
        &alice_contact,
        b"one message",
    )
    .await
    .unwrap();
    request_conversation_wipe(&db_alice, &mut alice_conn, &alice, &alice_contact)
        .await
        .unwrap();

    receive_pending(&db_bob, &mut bob_conn, &bob, &bob_contact)
        .await
        .unwrap();
    let bob_contact_after = db_bob
        .load_contact(&bob_contact.fingerprint)
        .unwrap()
        .unwrap();
    let bob_remaining = list_messages(&db_bob, &bob, &bob_contact_after).unwrap();

    println!(
        "\n[edge: same-batch ask-before-delete] expected: wipe_request_pending=true, message untouched (count=1)"
    );
    println!(
        "[edge: same-batch ask-before-delete] actual:   wipe_request_pending={}, message count={}",
        bob_contact_after.wipe_request_pending,
        bob_remaining.len()
    );
    assert!(
        bob_contact_after.wipe_request_pending,
        "EXPECTED-PER-DOCS: both sides had opted into ask-before-delete, so the wipe should \
         have been held for confirmation rather than auto-applied — if this fails, alice's \
         announce (processed earlier in this same batch) didn't reach the wipe-request arm's \
         decision later in that same batch"
    );
    assert_eq!(
        bob_remaining.len(),
        1,
        "EXPECTED-PER-DOCS: nothing should have been deleted without confirmation"
    );
}

/// **Positive control — the intended usage pattern actually works,
/// including across a real process restart, not just one long-lived
/// in-memory `Db` handle.** The policy announcement is processed in its
/// *own* `receive_pending` call, genuinely separate from the wipe
/// request — bob's `Db` is dropped and reopened from the same file
/// between them, so the boundary this test relies on has to have
/// actually round-tripped through disk, not just survived in memory.
#[tokio::test]
async fn boundary_persists_across_a_real_db_restart_when_processed_in_separate_polls() {
    let Paired {
        db_alice,
        alice,
        mut alice_contact,
        mut alice_conn,
        path_bob,
        db_bob,
        bob,
        bob_contact,
        mut bob_conn,
    } = pair("edgerestart", 5003).await;

    send_message(
        &db_alice,
        &mut alice_conn,
        &alice,
        &alice_contact,
        b"pre-boundary, before the restart",
    )
    .await
    .unwrap();
    receive_pending(&db_bob, &mut bob_conn, &bob, &bob_contact)
        .await
        .unwrap();

    alice_contact = announce_wipe_policy(
        &db_alice,
        &mut alice_conn,
        &alice,
        &alice_contact,
        false,
        false,
    )
    .await
    .unwrap();
    // Processed in its own, separate call — no wipe request anywhere
    // near this batch.
    receive_pending(&db_bob, &mut bob_conn, &bob, &bob_contact)
        .await
        .unwrap();
    let bob_contact_before_restart = db_bob
        .load_contact(&bob_contact.fingerprint)
        .unwrap()
        .unwrap();
    assert!(
        bob_contact_before_restart
            .peer_wipe_boundary_timestamp
            .is_some(),
        "setup sanity: bob's boundary was recorded before the simulated restart"
    );

    // Simulate a real app restart: drop bob's only `Db` handle and
    // `Db::open` the same on-disk file fresh.
    drop(db_bob);
    let db_bob = Arc::new(Db::open(&path_bob, "pw").unwrap());
    let bob_contact_reopened = db_bob
        .load_contact(&bob_contact.fingerprint)
        .unwrap()
        .unwrap();
    assert_eq!(
        bob_contact_reopened.peer_wipe_boundary_timestamp,
        bob_contact_before_restart.peer_wipe_boundary_timestamp,
        "the boundary genuinely round-tripped through disk, not just process memory"
    );

    send_message(
        &db_alice,
        &mut alice_conn,
        &alice,
        &alice_contact,
        b"post-boundary, after the restart",
    )
    .await
    .unwrap();
    receive_pending(&db_bob, &mut bob_conn, &bob, &bob_contact_reopened)
        .await
        .unwrap();

    request_conversation_wipe(&db_alice, &mut alice_conn, &alice, &alice_contact)
        .await
        .unwrap();
    receive_pending(&db_bob, &mut bob_conn, &bob, &bob_contact_reopened)
        .await
        .unwrap();

    let bob_contact_final = db_bob
        .load_contact(&bob_contact.fingerprint)
        .unwrap()
        .unwrap();
    let bob_remaining = list_messages(&db_bob, &bob, &bob_contact_final).unwrap();

    println!(
        "\n[edge: real restart, separate polls] expected: bob keeps the 1 pre-boundary message"
    );
    println!(
        "[edge: real restart, separate polls] actual:   bob keeps {} message(s)",
        bob_remaining.len()
    );
    assert_eq!(
        bob_remaining.len(),
        1,
        "ACTUAL: with the announcement processed in its own poll — even across a real db \
         restart in between — the scoped wipe works exactly as intended"
    );
    assert_eq!(
        bob_remaining[0].content,
        b"pre-boundary, before the restart"
    );
}
