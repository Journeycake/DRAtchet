//! Real, no-mocks exploration of "how does a dropped message actually
//! behave today" — app-layer scenarios (the asymmetry between the two
//! sides of the pairing-code gate, and what a network failure mid-send
//! actually leaves behind), against a real spawned `dratchet_server::app()`.
//! Companion to `server/tests/delivery_failures.rs` (mailbox-layer) and
//! `core/src/ratchet.rs`'s tests (ratchet-layer). See the accompanying
//! report for the full numbered findings.

use std::sync::Arc;

use dratchet_app::{
    add_contact_by_username, open_account, publish_own_bundle, receive_first_contact_attempts,
    receive_pending,
};
use dratchet_client::net::Connection;
use dratchet_core::account::Account;
use dratchet_core::payload::PAYLOAD_CHAT;
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
        one_time_prekey: wire
            .one_time_prekey
            .as_ref()
            .map(|otp| OneTimePrekeyPublic {
                id: otp.id,
                public: PublicKey::from(<[u8; 32]>::try_from(otp.key.as_slice()).unwrap()),
            }),
    }
}

fn new_contact(fingerprint: Vec<u8>, routing_id: Vec<u8>) -> Contact {
    Contact {
        mailbox_id: bootstrap_mailbox_id(&fingerprint).to_vec(),
        fingerprint,
        username: None,
        discriminator: None,
        verification_state: VerificationState::Verified,
        created_at: 0,
        local_routing_id: routing_id,
        peer_routing_id: None,
        wipe_ask_before_delete: false,
        peer_wipe_ask_before_delete: None,
        wipe_include_session: false,
        peer_wipe_include_session: None,
        wipe_request_pending: false,
    }
}

/// Scenario 20 — the asymmetry documented in `app::add_contact_by_username`'s
/// own doc comment, pinned down as a real regression test rather than only
/// a doc claim: after a *wrong* pairing code, Alice's own contact list
/// still gains a `Verified` entry for Bob, because her side commits before
/// Bob's code check ever runs and there is no reply to wait for. Extends
/// `app/tests/first_contact.rs`'s `a_wrong_code_leaves_no_trace_even_though_a_real_one_was_generated`,
/// which only ever checked Bob's side.
#[tokio::test]
async fn scenario_20_alices_contact_is_verified_regardless_of_whether_bobs_code_matched() {
    let url = spawn_server().await;

    let db_alice = Arc::new(temp_db());
    let mut alice = open_account(&db_alice).unwrap();
    let mut alice_conn = Connection::connect(&url).await.unwrap();
    alice_conn.authenticate(&alice).await.unwrap();
    let alice_profile = publish_own_bundle(&db_alice, &mut alice_conn, &mut alice, "alice20")
        .await
        .unwrap();

    let db_bob = Arc::new(temp_db());
    let mut bob = open_account(&db_bob).unwrap();
    let mut bob_conn = Connection::connect(&url).await.unwrap();
    bob_conn.authenticate(&bob).await.unwrap();
    let bob_profile = publish_own_bundle(&db_bob, &mut bob_conn, &mut bob, "bob20")
        .await
        .unwrap();

    // Bob never even generates a code — the strictest "wrong" case.
    assert!(db_bob.load_pairing_code().unwrap().is_none());

    let alice_result = add_contact_by_username(
        &db_alice,
        &mut alice_conn,
        &alice,
        &alice_profile,
        &bob_profile.username,
        bob_profile.discriminator,
        "000000",
    )
    .await;
    assert!(
        alice_result.is_ok(),
        "add_contact_by_username itself must not error just because the code was wrong — \
         it has no way to know that"
    );

    let alice_contacts = db_alice.list_contacts().unwrap();
    assert_eq!(alice_contacts.len(), 1, "Alice gained exactly one contact");
    assert_eq!(
        alice_contacts[0].verification_state,
        VerificationState::Verified,
        "Alice's side is Verified regardless of whether Bob's code check ever passes — \
         this is the real finding: nothing on her screen distinguishes this from a \
         correct-code success"
    );

    // Confirm Bob's side really did reject it — the asymmetry is real, not
    // just an artifact of this test not driving Bob's side at all.
    let bob_new = receive_first_contact_attempts(&db_bob, &mut bob_conn, &mut bob)
        .await
        .unwrap();
    assert!(bob_new.is_empty());
    assert!(db_bob.list_contacts().unwrap().is_empty());
}

/// Scenario 22 — what a "network drops between encrypt and ack" retry
/// actually leaves behind. `send_message` (`app/src/lib.rs`) only calls
/// `db.save_ratchet` *after* a successful `Ack`; if the connection dies
/// first, the caller sees an `Err` and the advanced in-memory ratchet is
/// just dropped — the on-disk state is untouched. That's the *safe* half
/// of the story (proven here: a retry from the untouched disk state is
/// possible at all). The real finding is what a retry with a *different*
/// plaintext produces: because message-key derivation is deterministic
/// from chain position, two attempts loaded from the same unsaved disk
/// state land on the identical (dh_pub, n) — an actual key/nonce reuse at
/// the crypto layer, not merely a UI-level duplicate.
#[tokio::test]
async fn scenario_22_retrying_from_unsaved_ratchet_state_reuses_the_same_chain_position() {
    let alice = Account::generate().unwrap();
    let mut bob = Account::generate().unwrap();
    bob.generate_one_time_prekeys(1);

    let conv_id = dratchet_core::conversation_id(
        alice.identity.fingerprint().as_bytes(),
        bob.identity.fingerprint().as_bytes(),
    );
    let bob_bundle = bob.publish_bundle(true).unwrap();
    let init = x3dh::initiate(
        alice.identity_dh_secret(),
        alice.identity_dh_public,
        &bob_bundle,
    )
    .unwrap();
    let alice_ratchet = RatchetState::init_as_initiator(
        conv_id,
        init.root_key,
        bob_bundle.signed_prekey.public,
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
    let mut bob_ratchet = RatchetState::init_as_responder(
        conv_id,
        bob_root_key,
        bob.signed_prekey_secret().clone(),
        DEFAULT_MAX_SKIP,
    )
    .unwrap();

    let db = temp_db();
    db.save_ratchet(conv_id, &alice_ratchet).unwrap();

    // "Attempt 1": a real client call would load this, encrypt, send, and
    // only save back on a successful Ack. Simulated here by loading,
    // encrypting, and — because the (simulated) network failed before an
    // Ack arrived — deliberately *not* saving it back.
    let mut attempt_1 = db.load_ratchet(conv_id).unwrap().unwrap();
    let envelope_1 = attempt_1
        .encrypt_payload(PAYLOAD_CHAT, b"are you free tonight?")
        .unwrap();

    // "Attempt 2": the user retries. Because attempt 1 was never
    // persisted, this loads the *same* starting state — and, realistically,
    // the retry might not even carry identical content (the user edited
    // the draft, or a second queued message went out around the same
    // time) — a different plaintext, to make the point sharply.
    let mut attempt_2 = db.load_ratchet(conv_id).unwrap().unwrap();
    let envelope_2 = attempt_2
        .encrypt_payload(PAYLOAD_CHAT, b"never mind, it can wait")
        .unwrap();

    assert_eq!(
        envelope_1.dh_pub, envelope_2.dh_pub,
        "both attempts share the same DH ratchet key"
    );
    assert_eq!(
        envelope_1.n, envelope_2.n,
        "both attempts land on the identical chain position — the same message \
         key was derived and used to encrypt two different plaintexts"
    );

    // The recipient is nonetheless protected from ever seeing both: the
    // first successful decrypt consumes/deletes that message key, so
    // whichever envelope arrives second — if attempt 1 actually *did*
    // reach the mailbox despite the lost Ack, and the retry sends attempt 2
    // as well — is rejected outright, not silently accepted as a second,
    // different message.
    let first = bob_ratchet.decrypt_payload(&envelope_1);
    assert!(first.is_ok(), "whichever arrives first decrypts fine");
    let second = bob_ratchet.decrypt_payload(&envelope_2);
    assert!(
        second.is_err(),
        "the second envelope at the same chain position is rejected, not decrypted \
         as a silently different message — app-level correctness is preserved even \
         though the sender technically reused a message key/nonce pair"
    );
}

/// Scenario 14 — `receive_pending` (`app/src/lib.rs`) deletes each mailbox
/// entry from the server as it's processed, *inside* its loop, but only
/// calls `db.save_ratchet` once, *after* the whole loop finishes. If the
/// process dies partway through a batch — after entries have been
/// decrypted, saved as `Message`s, and deleted server-side, but before the
/// final `save_ratchet` — what's actually left behind?
///
/// This reproduces that exact sequence by hand (real fetch, real decrypt,
/// real `save_message_now`, real delete+ack for two of three entries —
/// deliberately never calling `save_ratchet`, standing in for the crash),
/// then proves the real, production `receive_pending` recovers cleanly on
/// the next call: the answer turns out to be more benign than the code
/// structure first suggests — see the assertions below for exactly why.
#[tokio::test]
async fn scenario_14_a_crash_before_save_ratchet_does_not_lose_already_processed_messages() {
    let url = spawn_server().await;

    let bob = Account::generate().unwrap();
    let mut alice = Account::generate().unwrap();
    alice.generate_one_time_prekeys(1);
    let alice_fp = alice.identity.fingerprint().as_bytes().to_vec();
    let bob_fp = bob.identity.fingerprint().as_bytes().to_vec();
    let conv_id = dratchet_core::conversation_id(&bob_fp, &alice_fp);

    // Real X3DH so both sides derive a real, matching root key — Bob as
    // initiator (so he can send immediately without waiting on a reply).
    let mut publisher = Connection::connect(&url).await.unwrap();
    publisher.authenticate(&alice).await.unwrap();
    let alice_local_bundle = alice.publish_bundle(true).unwrap();
    let alice_bundle_wire = PrekeyBundleWire {
        username: "alice14".into(),
        discriminator: 1,
        identity_key: alice_local_bundle.identity_public_key.clone(),
        identity_dh_public: alice_local_bundle.identity_dh_public.as_bytes().to_vec(),
        identity_dh_signature: alice_local_bundle.identity_dh_signature.clone(),
        signed_prekey_id: alice_local_bundle.signed_prekey.id,
        signed_prekey: alice_local_bundle.signed_prekey.public.as_bytes().to_vec(),
        signed_prekey_sig: alice_local_bundle.signed_prekey.signature.clone(),
        signed_prekey_expires_at: 0,
        one_time_prekeys: alice_local_bundle
            .one_time_prekey
            .iter()
            .map(|otp| OneTimePrekeyWire {
                id: otp.id,
                key: otp.public.as_bytes().to_vec(),
            })
            .collect(),
        registration_pow: Some(dratchet_server::abuse::solve_registration_pow(
            "alice14",
            1,
            &alice_local_bundle.identity_public_key,
        )),
    };
    publisher
        .send(
            FrameTag::PublishBundle,
            &PublishBundle {
                bundle: alice_bundle_wire,
            },
        )
        .await
        .unwrap();
    let (_, ack): (_, Ack) = publisher.recv().await.unwrap();
    assert!(ack.ok);

    let mut fetcher = Connection::connect(&url).await.unwrap();
    fetcher.authenticate(&bob).await.unwrap();
    fetcher
        .send(
            FrameTag::FetchBundle,
            &FetchBundle {
                username: "alice14".into(),
                discriminator: 1,
            },
        )
        .await
        .unwrap();
    let (_, result): (_, BundleResult) = fetcher.recv().await.unwrap();
    let fetched = result.bundle.unwrap();
    let core_bundle = to_core_bundle(&fetched);

    let init = x3dh::initiate(
        bob.identity_dh_secret(),
        bob.identity_dh_public,
        &core_bundle,
    )
    .unwrap();
    let mut bob_ratchet = RatchetState::init_as_initiator(
        conv_id,
        init.root_key,
        core_bundle.signed_prekey.public,
        DEFAULT_MAX_SKIP,
    )
    .unwrap();
    let alice_otp_secret = init
        .message
        .used_one_time_prekey_id
        .and_then(|id| alice.take_one_time_prekey_secret(id));
    let alice_root_key = x3dh::respond(
        alice.identity_dh_secret(),
        alice.signed_prekey_secret(),
        alice_otp_secret.as_ref(),
        &init.message,
    );
    let alice_ratchet = RatchetState::init_as_responder(
        conv_id,
        alice_root_key,
        alice.signed_prekey_secret().clone(),
        DEFAULT_MAX_SKIP,
    )
    .unwrap();

    let db_alice = temp_db();
    db_alice.save_account(&alice).unwrap();
    let alice_contact = new_contact(bob_fp.clone(), random_routing_id());
    db_alice.save_contact(&alice_contact).unwrap();
    db_alice.save_ratchet(conv_id, &alice_ratchet).unwrap();

    let mailbox_id = bootstrap_mailbox_id(&alice_fp).to_vec();
    let mut bob_conn = Connection::connect(&url).await.unwrap();
    bob_conn.authenticate(&bob).await.unwrap();

    // Bob sends 3 real messages, ratchet-encrypted and written to Alice's
    // real mailbox, one at a time (each `encrypt_payload` call advances
    // Bob's local `bob_ratchet` — no `Db` involved on his side, kept
    // in-memory for this test since only Alice's persistence is at issue).
    let plaintexts = ["message one", "message two", "message three"];
    for text in &plaintexts {
        let envelope = bob_ratchet
            .encrypt_payload(PAYLOAD_CHAT, text.as_bytes())
            .unwrap();
        bob_conn
            .send(
                FrameTag::MailboxWrite,
                &MailboxWrite {
                    mailbox_id: mailbox_id.clone(),
                    envelope: envelope.encode(),
                    ttl: 86_400,
                },
            )
            .await
            .unwrap();
        let (_, ack): (_, Ack) = bob_conn.recv().await.unwrap();
        assert!(ack.ok);
    }

    // --- Alice "processes" the batch by hand, exactly matching
    // `receive_pending`'s real sequence (decrypt, save_message_now, then
    // MailboxDelete+Ack) for entries 1 and 2 — then the process "dies":
    // `save_ratchet` is never called, matching a crash right here. ---
    let mut alice_conn = Connection::connect(&url).await.unwrap();
    alice_conn.authenticate(&alice).await.unwrap();
    alice_conn
        .send(
            FrameTag::MailboxFetch,
            &MailboxFetch {
                mailbox_id: mailbox_id.clone(),
            },
        )
        .await
        .unwrap();
    let (_, entries): (_, MailboxEntries) = alice_conn.recv().await.unwrap();
    assert_eq!(entries.entries.len(), 3);

    let mut in_memory_ratchet = db_alice.load_ratchet(conv_id).unwrap().unwrap();
    for entry in &entries.entries[..2] {
        let envelope = dratchet_core::envelope::Envelope::decode(&entry.envelope).unwrap();
        let (payload_type, content) = in_memory_ratchet.decrypt_payload(&envelope).unwrap();
        assert_eq!(payload_type, PAYLOAD_CHAT);
        db_alice
            .save_message_now(conv_id, content, false, None)
            .unwrap();
        alice_conn
            .send(
                FrameTag::MailboxDelete,
                &MailboxDelete {
                    mailbox_id: mailbox_id.clone(),
                    entry_id: entry.entry_id.clone(),
                },
            )
            .await
            .unwrap();
        let (_, ack): (_, Ack) = alice_conn.recv().await.unwrap();
        assert!(ack.ok);
    }
    // `db_alice.save_ratchet(...)` deliberately never called — this is the crash.

    // The two processed entries are really gone from the server now.
    alice_conn
        .send(
            FrameTag::MailboxFetch,
            &MailboxFetch {
                mailbox_id: mailbox_id.clone(),
            },
        )
        .await
        .unwrap();
    let (_, remaining): (_, MailboxEntries) = alice_conn.recv().await.unwrap();
    assert_eq!(
        remaining.entries.len(),
        1,
        "only the third, never-reached entry is still in the mailbox"
    );

    // Finding 1: the two messages already decrypted before the crash are
    // NOT lost — `save_message_now` is called per-entry, inside the loop,
    // not deferred like `save_ratchet` is. This is the correction to the
    // more alarming hypothesis the code structure first suggests.
    assert_eq!(
        db_alice.list_messages(conv_id).unwrap().len(),
        2,
        "messages already decrypted before the crash survive it — only the ratchet's \
         own position bookkeeping is what's stale, not message content"
    );

    // Finding 2: the on-disk ratchet really is stale — still at its
    // pre-batch position, with no idea entries 1 and 2 ever happened. The
    // next assertions (Finding 3) prove this precisely, by way of the
    // real `receive_pending` having to skip past their positions to reach
    // what comes next.

    // Bob sends a 4th, real message.
    let envelope_4 = bob_ratchet
        .encrypt_payload(PAYLOAD_CHAT, b"message four")
        .unwrap();
    bob_conn
        .send(
            FrameTag::MailboxWrite,
            &MailboxWrite {
                mailbox_id: mailbox_id.clone(),
                envelope: envelope_4.encode(),
                ttl: 86_400,
            },
        )
        .await
        .unwrap();
    let (_, ack): (_, Ack) = bob_conn.recv().await.unwrap();
    assert!(ack.ok);

    // Finding 3, and the actual bottom line: the real, production
    // `receive_pending` — loading the stale ratchet exactly as a freshly-
    // restarted app would — fetches *both* remaining mailbox entries
    // (message three, never deleted since the crash happened before
    // reaching it, and the new message four), and correctly recovers
    // both: it skips-and-derives the phantom key for the already-gone
    // position 1 range to reach message three, decrypts it, then
    // continues straight on to message four. Nothing is actually lost —
    // the deferred `save_ratchet` costs a little wasted skipped-key
    // derivation on the next call, not data.
    let received = receive_pending(&db_alice, &mut alice_conn, &alice, &alice_contact)
        .await
        .unwrap();
    assert_eq!(
        received.messages.len(),
        2,
        "both message three and message four recover"
    );
    assert_eq!(
        String::from_utf8(received.messages[0].content.clone()).unwrap(),
        "message three"
    );
    assert_eq!(
        String::from_utf8(received.messages[1].content.clone()).unwrap(),
        "message four"
    );
    assert_eq!(
        db_alice.list_messages(conv_id).unwrap().len(),
        4,
        "all 4 messages end up saved — a crash between the last per-entry delete and \
         the batch's final save_ratchet costs nothing real, as long as whatever wasn't \
         reached yet is still sitting in the mailbox (at-least-once, scenario 2) for the \
         next call to pick back up"
    );
}
