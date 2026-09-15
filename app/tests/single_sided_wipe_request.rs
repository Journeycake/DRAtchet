//! Real, no-mocks tests for `ARCHITECTURE.md` §11.9a's per-conversation
//! wipe when it's genuinely single-sided: only Alice ever calls
//! [`request_conversation_wipe`]; Bob never reciprocates or requests a
//! wipe of his own. Each test states the expected behavior first, then
//! asserts it against the real, spawned-server implementation — matching
//! this session's fault-injection testing pattern.
//!
//! Also probes the interaction with this session's new uncertain/
//! piggyback-ack machinery (`ARCHITECTURE.md` §4.6a): `PAYLOAD_CONVERSATION_WIPE_REQUEST`
//! carries no `piggyback_ack` at all (it isn't a `ChatContent`), so the
//! wipe path neither resolves nor is resolved by it — the interaction, if
//! any, is entirely through `wipe_conversation` deleting the `Message`
//! rows an `uncertain` flag would otherwise live on.

use std::sync::Arc;

use dratchet_app::{
    announce_routing_id, announce_wipe_policy, list_messages, mark_pending_sends_uncertain,
    preview_conversation_wipe, receive_pending, record_verification_result,
    request_conversation_wipe, send_message,
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

/// Full real X3DH + routing-id-exchange pairing, both sides `Verified` —
/// the same setup this session's other real tests use, returning
/// everything a test needs to drive both sides directly.
struct Paired {
    db_alice: Arc<Db>,
    alice: Account,
    alice_contact: Contact,
    alice_conn: Connection,
    db_bob: Arc<Db>,
    bob: Account,
    bob_contact: Contact,
    bob_conn: Connection,
}

async fn pair() -> Paired {
    let url = spawn_server().await;

    let mut bob = Account::generate().unwrap();
    let bob_otp_publics = bob.generate_one_time_prekeys(1);
    let bob_local_bundle = bob.publish_bundle(false).unwrap();
    let bob_bundle_wire = PrekeyBundleWire {
        username: "wipebob".into(),
        discriminator: 4001,
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
            "wipebob",
            4001,
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
                username: "wipebob".into(),
                discriminator: 4001,
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

    let db_alice = Arc::new(temp_db());
    db_alice.save_account(&alice).unwrap();
    let mut alice_contact = Contact {
        fingerprint: bob_fp.clone(),
        username: Some("wipebob".into()),
        discriminator: Some(4001),
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

    let db_bob = Arc::new(temp_db());
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
        db_bob,
        bob,
        bob_contact,
        bob_conn,
    }
}

/// **Expected** (default policy, neither side has announced anything —
/// `ARCHITECTURE.md` §11.9a, `store::wipe_policy`'s "unanimous ask, most-
/// restrictive-wins session" merge): Alice's unilateral wipe request
/// should (1) delete every message on *her* side immediately, locally,
/// the moment the server acks the mailbox write — not waiting for Bob;
/// (2) reach Bob and, since `effective_wipe_ask_before_delete()` is false
/// for him too (unanimous consent requires both sides opting in, and
/// neither did), auto-comply immediately rather than setting
/// `wipe_request_pending` and waiting for a manual confirm; (3) leave the
/// *ratchet/session* alone on both sides, since neither side asked for
/// `include_session` — so the conversation should keep working
/// afterward with zero re-pairing, on the very next ordinary message.
#[tokio::test]
async fn default_policy_single_sided_wipe_is_messages_only_and_leaves_the_session_usable() {
    let Paired {
        db_alice,
        alice,
        alice_contact,
        mut alice_conn,
        db_bob,
        bob,
        bob_contact,
        mut bob_conn,
    } = pair().await;

    send_message(
        &db_alice,
        &mut alice_conn,
        &alice,
        &alice_contact,
        b"before the wipe",
    )
    .await
    .unwrap();
    receive_pending(&db_bob, &mut bob_conn, &bob, &bob_contact)
        .await
        .unwrap();
    assert_eq!(
        list_messages(&db_bob, &bob, &bob_contact).unwrap().len(),
        1,
        "bob genuinely has the pre-wipe message before any of this starts"
    );

    let removed = request_conversation_wipe(&db_alice, &mut alice_conn, &alice, &alice_contact)
        .await
        .unwrap();
    assert_eq!(
        removed, 1,
        "alice's own single message, messages-only (no ratchet)"
    );
    assert!(
        list_messages(&db_alice, &alice, &alice_contact)
            .unwrap()
            .is_empty(),
        "ACTUAL: alice's local copy is wiped immediately, before bob ever sees the request"
    );
    assert!(
        db_alice
            .load_ratchet(dratchet_core::conversation_id(
                alice.identity.fingerprint().as_bytes(),
                &alice_contact.fingerprint
            ))
            .unwrap()
            .is_some(),
        "ACTUAL: alice's ratchet survives — include_session was never requested"
    );

    let outcome = receive_pending(&db_bob, &mut bob_conn, &bob, &bob_contact)
        .await
        .unwrap();
    assert!(
        outcome.wipe_activity,
        "ACTUAL: bob's receive_pending surfaces the wipe so a UI can refresh"
    );
    let bob_contact = db_bob
        .load_contact(&bob_contact.fingerprint)
        .unwrap()
        .unwrap();
    assert!(
        !bob_contact.wipe_request_pending,
        "ACTUAL: unanimous ask-before-delete was never met (neither side opted in), \
         so bob auto-complied instead of waiting for a manual confirm"
    );
    assert!(
        list_messages(&db_bob, &bob, &bob_contact)
            .unwrap()
            .is_empty(),
        "ACTUAL: bob's own copy — including the message he'd already received — is gone too"
    );

    let conv_id = dratchet_core::conversation_id(
        bob.identity.fingerprint().as_bytes(),
        &bob_contact.fingerprint,
    );
    assert!(
        db_bob.load_ratchet(conv_id).unwrap().is_some(),
        "ACTUAL: bob's ratchet survives too — matches alice's side"
    );

    // The real proof the session survived: an ordinary message afterward,
    // with no re-pairing, still works end to end.
    send_message(
        &db_bob,
        &mut bob_conn,
        &bob,
        &bob_contact,
        b"still works after the wipe",
    )
    .await
    .unwrap();
    let alice_contact = db_alice
        .load_contact(&alice_contact.fingerprint)
        .unwrap()
        .unwrap();
    let received = receive_pending(&db_alice, &mut alice_conn, &alice, &alice_contact)
        .await
        .unwrap();
    assert_eq!(received.messages.len(), 1);
    assert_eq!(received.messages[0].content, b"still works after the wipe");
}

/// **Expected**: `wipe_conversation` deletes every `Message` row for the
/// conversation unconditionally — it has no special case for `uncertain`
/// vs. `delivered` vs. plain sent, so an in-flight `uncertain` send must
/// disappear along with everything else, on *both* sides, rather than
/// surviving as an orphaned row nothing will ever resolve.
#[tokio::test]
async fn wipe_removes_uncertain_messages_too_not_just_delivered_ones() {
    let Paired {
        db_alice,
        alice,
        alice_contact,
        mut alice_conn,
        db_bob,
        bob,
        bob_contact,
        mut bob_conn,
    } = pair().await;

    send_message(
        &db_alice,
        &mut alice_conn,
        &alice,
        &alice_contact,
        b"will go uncertain",
    )
    .await
    .unwrap();
    let newly_uncertain = mark_pending_sends_uncertain(&db_alice, &alice).unwrap();
    assert_eq!(newly_uncertain, 1);
    assert!(
        list_messages(&db_alice, &alice, &alice_contact)
            .unwrap()
            .iter()
            .any(|m| m.uncertain),
        "confirmed uncertain before the wipe"
    );

    // Bob never fetched it (never called receive_pending), so this is a
    // genuinely still-in-doubt send when the wipe happens — exactly the
    // state finding #29's fix cares about getting right, now tested
    // against the *other* way that state can end: not resolved, but wiped.
    request_conversation_wipe(&db_alice, &mut alice_conn, &alice, &alice_contact)
        .await
        .unwrap();

    assert!(
        list_messages(&db_alice, &alice, &alice_contact)
            .unwrap()
            .is_empty(),
        "ACTUAL: the uncertain message is gone, not left behind as an orphan \
         nothing will ever resolve"
    );

    // Bob's mailbox still has the never-fetched chat entry *and* the wipe
    // request queued behind it. receive_pending processes both in one
    // pass, in order: the still-undecided chat message arrives and gets
    // saved first, then the wipe request destroys it (and everything
    // else) moments later in the same call.
    let outcome = receive_pending(&db_bob, &mut bob_conn, &bob, &bob_contact)
        .await
        .unwrap();
    assert_eq!(
        outcome.messages.len(),
        1,
        "ACTUAL: bob's receive_pending really did decrypt the chat message first"
    );
    assert!(
        outcome.wipe_activity,
        "ACTUAL: and then processed the wipe request too"
    );
    assert!(
        list_messages(&db_bob, &bob, &bob_contact)
            .unwrap()
            .is_empty(),
        "ACTUAL: bob's local copy — decrypted and saved only moments earlier in this \
         same pass — is gone too, not left behind as a message the wipe request \
         technically arrived \"too late\" to catch"
    );
}

/// **Originally a real finding, now a fixed-and-locked-in regression
/// test.** Per `store::wipe_policy`'s own doc, `effective_wipe_include_session`
/// is "most-restrictive-wins" — either side wanting the fuller wipe should
/// mean *both* get it. The first implementation only honored that when the
/// preference had been separately announced and landed first
/// (`announce_wipe_policy`) — `PAYLOAD_CONVERSATION_WIPE_REQUEST` itself
/// carried no policy data at all, so a requester who set `include_session`
/// only in their own local contact record (skipping, or racing ahead of,
/// the announce step) would desync the two sides: their own ratchet gone,
/// the peer's still intact, with no automatic recovery — the peer's next
/// ordinary message would come back as a hard `NoSession` on the
/// requester's side. Documented as
/// `docs/DELIVERY_FAILURE_FINDINGS.md` finding #30 and fixed at the
/// source: `request_conversation_wipe` now carries the requester's own
/// `include_session` directly in the request
/// (`core::payload::ConversationWipeRequestContent`), so the recipient
/// folds it into their own effective decision for *this* wipe without
/// needing a prior announcement at all. This test proves the fix: the
/// exact scenario that used to desync the two sides no longer does.
#[tokio::test]
async fn include_session_no_longer_desyncs_the_peer_even_when_never_announced() {
    let Paired {
        db_alice,
        alice,
        mut alice_contact,
        mut alice_conn,
        db_bob,
        bob,
        bob_contact,
        mut bob_conn,
    } = pair().await;

    // Alice wants the fuller (session-destroying) wipe — but sets it
    // *only* in her own local contact record, the same as if a UI bug (or
    // a deliberate skip of the "announce first" step) let her reach the
    // wipe action without ever calling `announce_wipe_policy`.
    alice_contact.wipe_include_session = true;
    db_alice.save_contact(&alice_contact).unwrap();
    assert!(
        alice_contact.effective_wipe_include_session(),
        "alice's own side already computes the fuller wipe — her local flag alone is enough"
    );

    let bob_contact_before = db_bob
        .load_contact(&bob_contact.fingerprint)
        .unwrap()
        .unwrap();
    assert!(
        !bob_contact_before.effective_wipe_include_session(),
        "bob still has no idea from any *prior* announcement — nothing has told him that way"
    );

    request_conversation_wipe(&db_alice, &mut alice_conn, &alice, &alice_contact)
        .await
        .unwrap();

    let alice_conv_id = dratchet_core::conversation_id(
        alice.identity.fingerprint().as_bytes(),
        &alice_contact.fingerprint,
    );
    assert!(
        db_alice.load_ratchet(alice_conv_id).unwrap().is_none(),
        "alice's own ratchet is gone — she asked for the fuller wipe"
    );

    receive_pending(&db_bob, &mut bob_conn, &bob, &bob_contact)
        .await
        .unwrap();
    let bob_conv_id = dratchet_core::conversation_id(
        bob.identity.fingerprint().as_bytes(),
        &bob_contact.fingerprint,
    );
    assert!(
        db_bob.load_ratchet(bob_conv_id).unwrap().is_none(),
        "ACTUAL, post-fix: bob's ratchet is gone too — the request itself carried alice's \
         include_session preference, so bob correctly applied the fuller wipe even though \
         she never separately announced it"
    );

    // The real, user-visible proof: bob, now correctly aware the session
    // is gone, would need to re-pair before sending again — but if he
    // *does* still have a live ratchet somehow, alice being equally gone
    // is the symmetric, no-longer-surprising outcome. Confirm neither side
    // is left holding a ratchet the other has already destroyed.
    assert_eq!(
        db_alice.load_ratchet(alice_conv_id).unwrap().is_none(),
        db_bob.load_ratchet(bob_conv_id).unwrap().is_none(),
        "both sides agree on whether the session is gone — no more desync"
    );
}

/// The positive control for the finding above: when alice announces her
/// `include_session` preference first (`announce_wipe_policy`, the
/// documented intended flow — `ARCHITECTURE.md` §11.9a says preferences
/// are announced "once after pairing, and again whenever the user changes
/// a preference in Settings," i.e. *before* any wipe, not bundled with
/// the request) and it lands on bob's side before the wipe request does,
/// `effective_wipe_include_session()` correctly reads `true` on *both*
/// sides and both ratchets are removed together — proving the desync
/// above is specifically about the request carrying no policy data and
/// the announce step being skippable, not the merge logic itself being
/// wrong.
#[tokio::test]
async fn include_session_wipe_syncs_correctly_when_announced_first() {
    let Paired {
        db_alice,
        alice,
        alice_contact,
        mut alice_conn,
        db_bob,
        bob,
        bob_contact,
        mut bob_conn,
    } = pair().await;

    let alice_contact = announce_wipe_policy(
        &db_alice,
        &mut alice_conn,
        &alice,
        &alice_contact,
        false,
        true,
    )
    .await
    .unwrap();
    // Bob must actually receive and process the announcement before the
    // wipe request — the same ordering requirement the finding above
    // shows breaks silently when skipped.
    receive_pending(&db_bob, &mut bob_conn, &bob, &bob_contact)
        .await
        .unwrap();
    let bob_contact = db_bob
        .load_contact(&bob_contact.fingerprint)
        .unwrap()
        .unwrap();
    assert!(
        bob_contact.effective_wipe_include_session(),
        "the announcement landed — bob's side now agrees on the fuller wipe too"
    );

    request_conversation_wipe(&db_alice, &mut alice_conn, &alice, &alice_contact)
        .await
        .unwrap();
    receive_pending(&db_bob, &mut bob_conn, &bob, &bob_contact)
        .await
        .unwrap();

    let alice_conv_id = dratchet_core::conversation_id(
        alice.identity.fingerprint().as_bytes(),
        &alice_contact.fingerprint,
    );
    let bob_conv_id = dratchet_core::conversation_id(
        bob.identity.fingerprint().as_bytes(),
        &bob_contact.fingerprint,
    );
    assert!(
        db_alice.load_ratchet(alice_conv_id).unwrap().is_none(),
        "alice's ratchet is gone, as expected"
    );
    assert!(
        db_bob.load_ratchet(bob_conv_id).unwrap().is_none(),
        "ACTUAL: with the announcement landed first, bob's ratchet is gone too — \
         both sides genuinely agree this time, unlike the un-announced case above"
    );
}

/// The exact scenario from the feature request this test was written for:
/// Bob and Alice exchange messages under the default "no remote wipe"
/// policy, Bob changes his wipe policy for this conversation and
/// announces it, they keep messaging, and Bob initiates a wipe. **Expected**:
/// Bob's own chat goes to zero (his own local wipe is still full and
/// unconditional — that's his own device). Alice keeps every message from
/// *before* she processed Bob's policy announcement and loses every
/// message from *after* it — not because of when the wipe itself fires,
/// but because of when the policy change was communicated and received.
/// Also proves `preview_conversation_wipe`, the local read-only estimate
/// Bob gets before he ever sends the request: `peer_likely_keeps` should
/// name exactly the pre-announce count.
#[tokio::test]
async fn boundary_scoped_wipe_protects_alices_pre_announce_history() {
    let Paired {
        db_alice,
        alice,
        mut alice_contact,
        mut alice_conn,
        db_bob,
        bob,
        mut bob_contact,
        mut bob_conn,
    } = pair().await;

    // Bob and Alice exchange messages under "no remote wipe" — default
    // policy, neither side has announced anything yet.
    for text in [&b"pre-announce 1"[..], &b"pre-announce 2"[..]] {
        send_message(&db_bob, &mut bob_conn, &bob, &bob_contact, text)
            .await
            .unwrap();
        receive_pending(&db_alice, &mut alice_conn, &alice, &alice_contact)
            .await
            .unwrap();
    }
    assert_eq!(
        list_messages(&db_alice, &alice, &alice_contact)
            .unwrap()
            .len(),
        2,
        "alice genuinely has both pre-announce messages before any of this starts"
    );

    // Bob changes his wipe policy for this conversation and the
    // notification is sent to Alice.
    bob_contact = announce_wipe_policy(&db_bob, &mut bob_conn, &bob, &bob_contact, false, false)
        .await
        .unwrap();
    assert!(
        bob_contact.wipe_boundary_timestamp.is_some(),
        "ACTUAL: bob's own boundary is stamped the moment his announce is acked"
    );

    // Alice actually receives and processes the announcement — this is
    // what sets *her* record of bob's boundary, gating her own future
    // compliance with a wipe request from him.
    receive_pending(&db_alice, &mut alice_conn, &alice, &alice_contact)
        .await
        .unwrap();
    alice_contact = db_alice
        .load_contact(&alice_contact.fingerprint)
        .unwrap()
        .unwrap();
    assert!(
        alice_contact.peer_wipe_boundary_timestamp.is_some(),
        "ACTUAL: alice recorded bob's boundary the moment she processed his announcement"
    );

    // Bob and Alice continue messaging.
    for text in [&b"post-announce 1"[..], &b"post-announce 2"[..]] {
        send_message(&db_bob, &mut bob_conn, &bob, &bob_contact, text)
            .await
            .unwrap();
        receive_pending(&db_alice, &mut alice_conn, &alice, &alice_contact)
            .await
            .unwrap();
    }
    assert_eq!(
        list_messages(&db_alice, &alice, &alice_contact)
            .unwrap()
            .len(),
        4,
        "alice now has all 4 messages, 2 from before and 2 from after the policy change"
    );

    // Bob previews the wipe before sending it — a local, read-only
    // estimate of how much of his own history alice likely still keeps.
    let preview = preview_conversation_wipe(&db_bob, &bob, &bob_contact).unwrap();
    assert_eq!(
        preview.will_remove_locally, 4,
        "bob's own local wipe still removes everything, unconditionally"
    );
    assert_eq!(
        preview.peer_likely_keeps, 2,
        "ACTUAL: the preview correctly estimates alice keeps the 2 pre-announce messages"
    );

    // Bob initiates the wipe.
    let removed = request_conversation_wipe(&db_bob, &mut bob_conn, &bob, &bob_contact)
        .await
        .unwrap();
    assert_eq!(
        removed, 4,
        "bob's own side is still a full, unconditional local wipe"
    );
    assert!(
        list_messages(&db_bob, &bob, &bob_contact)
            .unwrap()
            .is_empty(),
        "ACTUAL: bob's own chat is fully cleared, exactly as before this feature"
    );

    receive_pending(&db_alice, &mut alice_conn, &alice, &alice_contact)
        .await
        .unwrap();
    let alice_remaining = list_messages(&db_alice, &alice, &alice_contact).unwrap();
    assert_eq!(
        alice_remaining.len(),
        2,
        "ACTUAL: alice keeps exactly the 2 pre-announce messages, loses the 2 post-announce ones"
    );
    assert!(
        alice_remaining
            .iter()
            .all(|m| m.content == b"pre-announce 1" || m.content == b"pre-announce 2"),
        "ACTUAL: the surviving messages are specifically the pre-announce ones, \
         all other messages in alice's client prior to the policy change remain, \
         nothing extra survived by accident"
    );

    // The session itself is untouched by a messages-only wipe — proof the
    // conversation is still usable, on both sides, after this.
    send_message(
        &db_alice,
        &mut alice_conn,
        &alice,
        &alice_contact,
        b"still works after the boundary-scoped wipe",
    )
    .await
    .unwrap();
    let bob_contact = db_bob
        .load_contact(&bob_contact.fingerprint)
        .unwrap()
        .unwrap();
    let received = receive_pending(&db_bob, &mut bob_conn, &bob, &bob_contact)
        .await
        .unwrap();
    assert_eq!(received.messages.len(), 1);
    assert_eq!(
        received.messages[0].content,
        b"still works after the boundary-scoped wipe"
    );
}
