//! Real, no-mocks "5 client" acceptance test for the boundary-scoped
//! remote wipe feature (`ARCHITECTURE.md` §11.9a's "Boundary-scoped wipe
//! on the peer's side" note, `store::wipe_policy::wipe_conversation_since`).
//!
//! One requesting client ("wendy") maintains four independent, real,
//! X3DH-paired conversations, each configured differently, then performs
//! a wipe against all four — exactly the shape of a user auditing "did
//! the scoped-wipe change actually behave the way each conversation's
//! policy says it should":
//!
//! - **`ask_first`** — both sides agree, and never change, "ask before
//!   deleting" (`effective_wipe_ask_before_delete() == true` on the peer's
//!   side). **Expected**: wendy's wipe request never auto-completes on the
//!   peer's side at all — `wipe_request_pending` is set and nothing is
//!   deleted, regardless of the new boundary machinery. This is the
//!   control proving boundary-scoping didn't quietly bypass the
//!   pre-existing ask-before-delete gate.
//! - **`always_full`** — both sides configure the fuller
//!   (`include_session = true`) policy from the very start, before any
//!   chat message is ever sent. **Expected**: every message and the
//!   ratchet are removed on both sides — a boundary technically exists,
//!   but it predates every message, so the outcome is indistinguishable
//!   from the pre-feature full wipe. Regression control for "a boundary
//!   that covers 100% of history behaves like no boundary at all."
//! - **`late_change_same_second`** — default (no boundary) for 3
//!   messages, then wendy announces a policy change, then 2 more
//!   messages, all within the same wall-clock second. **Expected**: the
//!   peer keeps exactly the 3 pre-change messages and loses the 2
//!   post-change ones — proving the `(timestamp, sequence)` tie-break
//!   itself (not just timestamp granularity) places the boundary
//!   correctly when everything happens in one second, which is the
//!   common case in any fast, scripted, or bursty exchange.
//! - **`late_change_real_gap`** — the same shape, but with real
//!   multi-second sleeps around the policy change, so pre- and post-
//!   change messages land in genuinely different wall-clock seconds.
//!   **Expected**: same outcome as above, this time driven by `timestamp`
//!   alone rather than the same-second `sequence` tie-break — the other
//!   half of the boundary comparison this suite needs to cover.
//!
//! Every conversation also checks wendy's own local copy: per
//! `ARCHITECTURE.md` §11.9a, `request_conversation_wipe`'s local wipe is
//! always full and unconditional, *regardless* of any policy on either
//! side — including `ask_first`, where the peer's copy is deliberately
//! left untouched. That asymmetry is easy to assume away, so it's
//! asserted explicitly here rather than left implicit.

use std::sync::Arc;
use std::time::Duration;

use dratchet_app::{
    announce_routing_id, announce_wipe_policy, list_messages, preview_conversation_wipe,
    receive_pending, record_verification_result, request_conversation_wipe, send_message,
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

fn temp_db() -> Db {
    let dir = tempfile::tempdir().unwrap().keep();
    Db::create(dir.join("test.redb"), "pw").unwrap()
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

/// One of wendy's four independent, real, X3DH-paired conversations.
/// Wendy is always the X3DH initiator (she fetches the peer's published
/// bundle), matching every other single-sided-wipe test in this
/// session — the peer is always the one whose bundle gets published and
/// fetched, never wendy's.
struct PeerConversation {
    label: &'static str,
    db_peer: Arc<Db>,
    peer: Account,
    peer_contact: Contact,
    peer_conn: Connection,
    wendy_contact: Contact,
}

async fn pair_new_peer(
    url: &str,
    db_wendy: &Arc<Db>,
    wendy: &Account,
    wendy_conn: &mut Connection,
    label: &'static str,
) -> PeerConversation {
    let username = format!("{label}{:04x}", OsRng.next_u32() as u16);
    let discriminator = (OsRng.next_u32() % 10_000) as u16;

    let mut peer = Account::generate().unwrap();
    let peer_otp_publics = peer.generate_one_time_prekeys(1);
    let peer_local_bundle = peer.publish_bundle(false).unwrap();
    let peer_bundle_wire = PrekeyBundleWire {
        username: username.clone(),
        discriminator,
        identity_key: peer_local_bundle.identity_public_key.clone(),
        identity_dh_public: peer_local_bundle.identity_dh_public.as_bytes().to_vec(),
        identity_dh_signature: peer_local_bundle.identity_dh_signature.clone(),
        signed_prekey_id: peer_local_bundle.signed_prekey.id,
        signed_prekey: peer_local_bundle.signed_prekey.public.as_bytes().to_vec(),
        signed_prekey_sig: peer_local_bundle.signed_prekey.signature.clone(),
        signed_prekey_expires_at: 0,
        one_time_prekeys: peer_otp_publics
            .into_iter()
            .map(|otp| OneTimePrekeyWire {
                id: otp.id,
                key: otp.public.as_bytes().to_vec(),
            })
            .collect(),
        registration_pow: Some(dratchet_server::abuse::solve_registration_pow(
            &username,
            discriminator,
            &peer_local_bundle.identity_public_key,
        )),
    };
    let mut publisher = Connection::connect(url).await.unwrap();
    let (_, _challenge): (_, AuthChallenge) = publisher.recv().await.unwrap();
    publisher
        .send(
            FrameTag::PublishBundle,
            &PublishBundle {
                bundle: peer_bundle_wire,
            },
        )
        .await
        .unwrap();

    let mut fetcher = Connection::connect(url).await.unwrap();
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
    let fetched = result.bundle.expect("peer's bundle should be found");
    let core_bundle = to_core_bundle(&fetched);

    let init = x3dh::initiate(
        wendy.identity_dh_secret(),
        wendy.identity_dh_public,
        &core_bundle,
    )
    .unwrap();
    let conv_id = dratchet_core::conversation_id(
        wendy.identity.fingerprint().as_bytes(),
        peer.identity.fingerprint().as_bytes(),
    );
    let wendy_ratchet = RatchetState::init_as_initiator(
        conv_id,
        init.root_key,
        core_bundle.signed_prekey.public,
        DEFAULT_MAX_SKIP,
    )
    .unwrap();

    let peer_otp_secret = init
        .message
        .used_one_time_prekey_id
        .and_then(|id| peer.take_one_time_prekey_secret(id));
    let peer_root_key = x3dh::respond(
        peer.identity_dh_secret(),
        peer.signed_prekey_secret(),
        peer_otp_secret.as_ref(),
        &init.message,
    );
    let peer_ratchet = RatchetState::init_as_responder(
        conv_id,
        peer_root_key,
        peer.signed_prekey_secret().clone(),
        DEFAULT_MAX_SKIP,
    )
    .unwrap();

    let wendy_fp = wendy.identity.fingerprint().as_bytes().to_vec();
    let peer_fp = peer.identity.fingerprint().as_bytes().to_vec();
    let wendy_routing_id = random_routing_id();
    let peer_routing_id = random_routing_id();

    let mut wendy_contact = Contact {
        fingerprint: peer_fp.clone(),
        username: Some(username.clone()),
        discriminator: Some(discriminator),
        verification_state: VerificationState::Pending,
        mailbox_id: bootstrap_mailbox_id(&peer_fp).to_vec(),
        created_at: 0,
        local_routing_id: wendy_routing_id.clone(),
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
    db_wendy.save_contact(&wendy_contact).unwrap();
    db_wendy.save_ratchet(conv_id, &wendy_ratchet).unwrap();

    let db_peer = Arc::new(temp_db());
    db_peer.save_account(&peer).unwrap();
    let mut peer_contact = Contact {
        fingerprint: wendy_fp.clone(),
        username: None,
        discriminator: None,
        verification_state: VerificationState::Pending,
        mailbox_id: bootstrap_mailbox_id(&wendy_fp).to_vec(),
        created_at: 0,
        local_routing_id: peer_routing_id.clone(),
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
    db_peer.save_contact(&peer_contact).unwrap();
    db_peer.save_ratchet(conv_id, &peer_ratchet).unwrap();

    let mut peer_conn = Connection::connect(url).await.unwrap();
    peer_conn.authenticate(&peer).await.unwrap();

    announce_routing_id(
        db_wendy,
        wendy_conn,
        wendy,
        &wendy_contact,
        wendy_routing_id,
    )
    .await
    .unwrap();
    receive_pending(&db_peer, &mut peer_conn, &peer, &peer_contact)
        .await
        .unwrap();
    peer_contact = db_peer.load_contact(&wendy_fp).unwrap().unwrap();

    announce_routing_id(
        &db_peer,
        &mut peer_conn,
        &peer,
        &peer_contact,
        peer_routing_id,
    )
    .await
    .unwrap();
    receive_pending(db_wendy, wendy_conn, wendy, &wendy_contact)
        .await
        .unwrap();
    wendy_contact = db_wendy.load_contact(&peer_fp).unwrap().unwrap();

    wendy_contact = record_verification_result(db_wendy, wendy_contact, true).unwrap();
    peer_contact = record_verification_result(&db_peer, peer_contact, true).unwrap();

    PeerConversation {
        label,
        db_peer,
        peer,
        peer_contact,
        peer_conn,
        wendy_contact,
    }
}

#[tokio::test]
async fn five_client_scoped_wipe_scenario_matches_each_conversations_configured_policy() {
    let url = spawn_server().await;
    let db_wendy = Arc::new(temp_db());
    let wendy = Account::generate().unwrap();
    db_wendy.save_account(&wendy).unwrap();
    let mut wendy_conn = Connection::connect(&url).await.unwrap();
    wendy_conn.authenticate(&wendy).await.unwrap();

    println!("\n=== 5-client scoped-wipe scenario: expected vs. actual ===\n");

    // ---------------------------------------------------------------
    // Conversation 1: "ask_first" — both sides agree, unchanged, to ask
    // before deleting. Never confirmed in this run: "left at do not
    // wipe" by both parties.
    // ---------------------------------------------------------------
    let mut ask_first = pair_new_peer(&url, &db_wendy, &wendy, &mut wendy_conn, "askfirst").await;
    announce_wipe_policy(
        &db_wendy,
        &mut wendy_conn,
        &wendy,
        &ask_first.wendy_contact,
        true,
        false,
    )
    .await
    .unwrap();
    receive_pending(
        &ask_first.db_peer,
        &mut ask_first.peer_conn,
        &ask_first.peer,
        &ask_first.peer_contact,
    )
    .await
    .unwrap();
    ask_first.peer_contact = ask_first
        .db_peer
        .load_contact(&ask_first.peer_contact.fingerprint)
        .unwrap()
        .unwrap();
    ask_first.peer_contact = announce_wipe_policy(
        &ask_first.db_peer,
        &mut ask_first.peer_conn,
        &ask_first.peer,
        &ask_first.peer_contact,
        true,
        false,
    )
    .await
    .unwrap();
    receive_pending(&db_wendy, &mut wendy_conn, &wendy, &ask_first.wendy_contact)
        .await
        .unwrap();
    ask_first.wendy_contact = db_wendy
        .load_contact(&ask_first.wendy_contact.fingerprint)
        .unwrap()
        .unwrap();
    assert!(
        ask_first.peer_contact.effective_wipe_ask_before_delete(),
        "setup sanity: both sides opted into ask-before-delete"
    );

    for text in [&b"ask-first message 1"[..], &b"ask-first message 2"[..]] {
        send_message(
            &db_wendy,
            &mut wendy_conn,
            &wendy,
            &ask_first.wendy_contact,
            text,
        )
        .await
        .unwrap();
        receive_pending(
            &ask_first.db_peer,
            &mut ask_first.peer_conn,
            &ask_first.peer,
            &ask_first.peer_contact,
        )
        .await
        .unwrap();
    }

    let ask_first_removed_locally =
        request_conversation_wipe(&db_wendy, &mut wendy_conn, &wendy, &ask_first.wendy_contact)
            .await
            .unwrap();
    receive_pending(
        &ask_first.db_peer,
        &mut ask_first.peer_conn,
        &ask_first.peer,
        &ask_first.peer_contact,
    )
    .await
    .unwrap();
    let ask_first_peer_after = ask_first
        .db_peer
        .load_contact(&ask_first.peer_contact.fingerprint)
        .unwrap()
        .unwrap();
    let ask_first_peer_messages =
        list_messages(&ask_first.db_peer, &ask_first.peer, &ask_first_peer_after)
            .unwrap()
            .len();
    let ask_first_wendy_messages = list_messages(&db_wendy, &wendy, &ask_first.wendy_contact)
        .unwrap()
        .len();

    println!(
        "[ask_first]   expected: wendy local=0, peer messages=2 (untouched), peer wipe_request_pending=true"
    );
    println!(
        "[ask_first]   actual:   wendy local={ask_first_wendy_messages}, peer messages={ask_first_peer_messages}, peer wipe_request_pending={}",
        ask_first_peer_after.wipe_request_pending
    );
    assert_eq!(
        ask_first_removed_locally, 2,
        "wendy's own 2 messages, unconditional local wipe"
    );
    assert_eq!(
        ask_first_wendy_messages, 0,
        "ACTUAL: wendy's own side is fully wiped regardless of ask-before-delete"
    );
    assert_eq!(
        ask_first_peer_messages, 2,
        "ACTUAL: the peer's ask-before-delete gate is untouched by the new boundary machinery — nothing auto-deleted"
    );
    assert!(
        ask_first_peer_after.wipe_request_pending,
        "ACTUAL: the peer is left with a pending confirmation instead"
    );

    // ---------------------------------------------------------------
    // Conversation 2: "always_full" — both sides configure the fuller
    // (include_session) policy before any chat message is ever sent.
    // ---------------------------------------------------------------
    let mut always_full =
        pair_new_peer(&url, &db_wendy, &wendy, &mut wendy_conn, "alwaysfull").await;
    announce_wipe_policy(
        &db_wendy,
        &mut wendy_conn,
        &wendy,
        &always_full.wendy_contact,
        false,
        true,
    )
    .await
    .unwrap();
    receive_pending(
        &always_full.db_peer,
        &mut always_full.peer_conn,
        &always_full.peer,
        &always_full.peer_contact,
    )
    .await
    .unwrap();
    always_full.peer_contact = always_full
        .db_peer
        .load_contact(&always_full.peer_contact.fingerprint)
        .unwrap()
        .unwrap();
    always_full.peer_contact = announce_wipe_policy(
        &always_full.db_peer,
        &mut always_full.peer_conn,
        &always_full.peer,
        &always_full.peer_contact,
        false,
        true,
    )
    .await
    .unwrap();
    receive_pending(
        &db_wendy,
        &mut wendy_conn,
        &wendy,
        &always_full.wendy_contact,
    )
    .await
    .unwrap();
    always_full.wendy_contact = db_wendy
        .load_contact(&always_full.wendy_contact.fingerprint)
        .unwrap()
        .unwrap();

    for text in [
        &b"always-full message 1"[..],
        &b"always-full message 2"[..],
        &b"always-full message 3"[..],
    ] {
        send_message(
            &db_wendy,
            &mut wendy_conn,
            &wendy,
            &always_full.wendy_contact,
            text,
        )
        .await
        .unwrap();
        receive_pending(
            &always_full.db_peer,
            &mut always_full.peer_conn,
            &always_full.peer,
            &always_full.peer_contact,
        )
        .await
        .unwrap();
    }

    let always_full_preview =
        preview_conversation_wipe(&db_wendy, &wendy, &always_full.wendy_contact).unwrap();
    request_conversation_wipe(
        &db_wendy,
        &mut wendy_conn,
        &wendy,
        &always_full.wendy_contact,
    )
    .await
    .unwrap();
    receive_pending(
        &always_full.db_peer,
        &mut always_full.peer_conn,
        &always_full.peer,
        &always_full.peer_contact,
    )
    .await
    .unwrap();
    let always_full_peer_after = always_full
        .db_peer
        .load_contact(&always_full.peer_contact.fingerprint)
        .unwrap()
        .unwrap();
    let always_full_peer_messages = list_messages(
        &always_full.db_peer,
        &always_full.peer,
        &always_full_peer_after,
    )
    .unwrap()
    .len();
    let always_full_peer_conv_id = dratchet_core::conversation_id(
        always_full.peer.identity.fingerprint().as_bytes(),
        &always_full_peer_after.fingerprint,
    );
    let always_full_peer_ratchet_gone = always_full
        .db_peer
        .load_ratchet(always_full_peer_conv_id)
        .unwrap()
        .is_none();

    println!(
        "[always_full] expected: preview.peer_likely_keeps=0, peer messages=0, peer ratchet=gone"
    );
    println!(
        "[always_full] actual:   preview.peer_likely_keeps={}, peer messages={always_full_peer_messages}, peer ratchet_gone={always_full_peer_ratchet_gone}",
        always_full_preview.peer_likely_keeps
    );
    assert_eq!(
        always_full_preview.peer_likely_keeps, 0,
        "ACTUAL: the boundary predates every message, so the preview correctly estimates nothing survives"
    );
    assert_eq!(
        always_full_peer_messages, 0,
        "ACTUAL: a boundary that covers 100% of history behaves identically to a full wipe"
    );
    assert!(
        always_full_peer_ratchet_gone,
        "ACTUAL: include_session was configured from the start, so the ratchet is gone too"
    );

    // ---------------------------------------------------------------
    // Conversation 3: "late_change_same_second" — default policy for 3
    // messages, a mid-conversation policy change, then 2 more messages,
    // all within the same wall-clock second (the common case).
    // ---------------------------------------------------------------
    let mut late_same = pair_new_peer(&url, &db_wendy, &wendy, &mut wendy_conn, "latesame").await;

    for text in [
        &b"late-same pre-change 1"[..],
        &b"late-same pre-change 2"[..],
        &b"late-same pre-change 3"[..],
    ] {
        send_message(
            &db_wendy,
            &mut wendy_conn,
            &wendy,
            &late_same.wendy_contact,
            text,
        )
        .await
        .unwrap();
        receive_pending(
            &late_same.db_peer,
            &mut late_same.peer_conn,
            &late_same.peer,
            &late_same.peer_contact,
        )
        .await
        .unwrap();
    }

    late_same.wendy_contact = announce_wipe_policy(
        &db_wendy,
        &mut wendy_conn,
        &wendy,
        &late_same.wendy_contact,
        false,
        true,
    )
    .await
    .unwrap();
    receive_pending(
        &late_same.db_peer,
        &mut late_same.peer_conn,
        &late_same.peer,
        &late_same.peer_contact,
    )
    .await
    .unwrap();
    late_same.peer_contact = late_same
        .db_peer
        .load_contact(&late_same.peer_contact.fingerprint)
        .unwrap()
        .unwrap();

    for text in [
        &b"late-same post-change 1"[..],
        &b"late-same post-change 2"[..],
    ] {
        send_message(
            &db_wendy,
            &mut wendy_conn,
            &wendy,
            &late_same.wendy_contact,
            text,
        )
        .await
        .unwrap();
        receive_pending(
            &late_same.db_peer,
            &mut late_same.peer_conn,
            &late_same.peer,
            &late_same.peer_contact,
        )
        .await
        .unwrap();
    }

    let late_same_preview =
        preview_conversation_wipe(&db_wendy, &wendy, &late_same.wendy_contact).unwrap();
    request_conversation_wipe(&db_wendy, &mut wendy_conn, &wendy, &late_same.wendy_contact)
        .await
        .unwrap();
    receive_pending(
        &late_same.db_peer,
        &mut late_same.peer_conn,
        &late_same.peer,
        &late_same.peer_contact,
    )
    .await
    .unwrap();
    let late_same_peer_after = late_same
        .db_peer
        .load_contact(&late_same.peer_contact.fingerprint)
        .unwrap()
        .unwrap();
    let late_same_peer_remaining =
        list_messages(&late_same.db_peer, &late_same.peer, &late_same_peer_after).unwrap();

    println!(
        "[late_change_same_second] expected: preview.peer_likely_keeps=3, peer keeps exactly the 3 pre-change messages"
    );
    println!(
        "[late_change_same_second] actual:   preview.peer_likely_keeps={}, peer keeps {} message(s)",
        late_same_preview.peer_likely_keeps,
        late_same_peer_remaining.len()
    );
    assert_eq!(
        late_same_preview.peer_likely_keeps, 3,
        "ACTUAL: preview correctly estimates the 3 pre-change messages survive"
    );
    assert_eq!(
        late_same_peer_remaining.len(),
        3,
        "ACTUAL: exactly 3 messages survive on the peer's side"
    );
    assert!(
        late_same_peer_remaining
            .iter()
            .all(|m| m.content.starts_with(b"late-same pre-change")),
        "ACTUAL: the survivors are specifically the pre-change ones, not just any 3"
    );

    // ---------------------------------------------------------------
    // Conversation 4: "late_change_real_gap" — same shape, but with real
    // multi-second sleeps so pre-/post-change messages land in genuinely
    // different wall-clock seconds (exercises the timestamp comparison
    // itself, not the same-second sequence tie-break).
    // ---------------------------------------------------------------
    let mut late_gap = pair_new_peer(&url, &db_wendy, &wendy, &mut wendy_conn, "lategap").await;

    send_message(
        &db_wendy,
        &mut wendy_conn,
        &wendy,
        &late_gap.wendy_contact,
        b"late-gap pre-change 1",
    )
    .await
    .unwrap();
    receive_pending(
        &late_gap.db_peer,
        &mut late_gap.peer_conn,
        &late_gap.peer,
        &late_gap.peer_contact,
    )
    .await
    .unwrap();

    tokio::time::sleep(Duration::from_millis(1200)).await;

    late_gap.wendy_contact = announce_wipe_policy(
        &db_wendy,
        &mut wendy_conn,
        &wendy,
        &late_gap.wendy_contact,
        false,
        true,
    )
    .await
    .unwrap();
    receive_pending(
        &late_gap.db_peer,
        &mut late_gap.peer_conn,
        &late_gap.peer,
        &late_gap.peer_contact,
    )
    .await
    .unwrap();
    late_gap.peer_contact = late_gap
        .db_peer
        .load_contact(&late_gap.peer_contact.fingerprint)
        .unwrap()
        .unwrap();

    tokio::time::sleep(Duration::from_millis(1200)).await;

    for text in [
        &b"late-gap post-change 1"[..],
        &b"late-gap post-change 2"[..],
        &b"late-gap post-change 3"[..],
        &b"late-gap post-change 4"[..],
    ] {
        send_message(
            &db_wendy,
            &mut wendy_conn,
            &wendy,
            &late_gap.wendy_contact,
            text,
        )
        .await
        .unwrap();
        receive_pending(
            &late_gap.db_peer,
            &mut late_gap.peer_conn,
            &late_gap.peer,
            &late_gap.peer_contact,
        )
        .await
        .unwrap();
    }

    let late_gap_preview =
        preview_conversation_wipe(&db_wendy, &wendy, &late_gap.wendy_contact).unwrap();
    request_conversation_wipe(&db_wendy, &mut wendy_conn, &wendy, &late_gap.wendy_contact)
        .await
        .unwrap();
    receive_pending(
        &late_gap.db_peer,
        &mut late_gap.peer_conn,
        &late_gap.peer,
        &late_gap.peer_contact,
    )
    .await
    .unwrap();
    let late_gap_peer_after = late_gap
        .db_peer
        .load_contact(&late_gap.peer_contact.fingerprint)
        .unwrap()
        .unwrap();
    let late_gap_peer_remaining =
        list_messages(&late_gap.db_peer, &late_gap.peer, &late_gap_peer_after).unwrap();
    let late_gap_peer_conv_id = dratchet_core::conversation_id(
        late_gap.peer.identity.fingerprint().as_bytes(),
        &late_gap_peer_after.fingerprint,
    );
    let late_gap_peer_ratchet_gone = late_gap
        .db_peer
        .load_ratchet(late_gap_peer_conv_id)
        .unwrap()
        .is_none();

    println!(
        "[late_change_real_gap]    expected: preview.peer_likely_keeps=1, peer keeps exactly the 1 pre-change message, ratchet gone"
    );
    println!(
        "[late_change_real_gap]    actual:   preview.peer_likely_keeps={}, peer keeps {} message(s), ratchet_gone={late_gap_peer_ratchet_gone}",
        late_gap_preview.peer_likely_keeps,
        late_gap_peer_remaining.len()
    );
    assert_eq!(
        late_gap_preview.peer_likely_keeps, 1,
        "ACTUAL: preview correctly estimates the 1 pre-change message survives"
    );
    assert_eq!(
        late_gap_peer_remaining.len(),
        1,
        "ACTUAL: exactly 1 message survives on the peer's side"
    );
    assert_eq!(
        late_gap_peer_remaining[0].content, b"late-gap pre-change 1",
        "ACTUAL: the one survivor is specifically the pre-change message"
    );
    assert!(
        late_gap_peer_ratchet_gone,
        "ACTUAL: include_session was requested, ratchet is gone too"
    );

    println!(
        "\n=== All 4 conversations matched their configured policy. No unexpected behavior. ===\n"
    );

    // Silence "field never read" warnings for struct fields only used as
    // setup/audit trail above, not in a final assertion.
    let _ = (
        &ask_first.label,
        &always_full.label,
        &late_same.label,
        &late_gap.label,
    );
    let _ = (
        &ask_first.peer,
        &always_full.peer,
        &late_same.peer,
        &late_gap.peer,
    );
}
