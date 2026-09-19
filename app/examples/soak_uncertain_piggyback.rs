//! Long-running soak test for the uncertain/piggyback-ack feature
//! (`ARCHITECTURE.md` §4.6a) and its finding #29 fix
//! (`content_delivered_contiguous`). Two real clients (alice, bob) run
//! concurrent send/receive loops against a real, externally-managed
//! `dratchetd` for the whole run — an external supervisor script is
//! expected to periodically kill+restart that server, injecting the same
//! class of connection interruption this session's live UI testing used
//! to find finding #29. This binary never touches the server process
//! itself; it only reacts to the resulting connection errors, exactly
//! like the real Tauri poll loop does.
//!
//! Every send/receive/reconnect/uncertain-mark is logged as a structured
//! line to stdout. Every `STATUS_INTERVAL`, both sides' full local message
//! stores are cross-referenced: any message reading `delivered: true` on
//! the sender's side must have matching content genuinely present in the
//! recipient's own store — a direct, continuous check for a regression of
//! finding #29 (a permanently-skipped message falsely marked delivered).
//! Runs until killed (SIGTERM/SIGKILL from outside) or `--duration-secs`
//! elapses, printing a final report either way is left to the last status
//! line already written — there is no special shutdown hook, so an
//! external supervisor should just read the log's last `STATUS` line
//! rather than wait for a graceful exit.
//!
//! ```sh
//! cargo run -p dratchet-app --example soak_uncertain_piggyback -- [duration_secs]
//! ```

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use dratchet_app::{
    mark_pending_sends_uncertain, receive_pending, record_verification_result, send_message,
};
use dratchet_client::net::Connection;
use dratchet_core::account::Account;
use dratchet_core::prekey::{OneTimePrekeyPublic, PrekeyBundle, SignedPrekeyPublic};
use dratchet_core::ratchet::{RatchetState, DEFAULT_MAX_SKIP};
use dratchet_core::x3dh::{self, bootstrap_mailbox_id};
use dratchet_server::protocol::*;
use dratchet_store::{Contact, Db, VerificationState};
use rand_core::{OsRng, RngCore};
use x25519_dalek::PublicKey;

const SERVER_URL: &str = "ws://127.0.0.1:8787/v1/ws";
const SEND_INTERVAL: Duration = Duration::from_secs(4);
const POLL_INTERVAL: Duration = Duration::from_secs(2);
const STATUS_INTERVAL: Duration = Duration::from_secs(60);
const RECONNECT_BACKOFF: Duration = Duration::from_secs(2);

fn now_str() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    format!("t={secs}")
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

async fn connect_retrying(role: &str) -> Connection {
    loop {
        match Connection::connect(SERVER_URL).await {
            Ok(c) => return c,
            Err(e) => {
                eprintln!(
                    "[{}] {role} initial connect failed, retrying: {e}",
                    now_str()
                );
                tokio::time::sleep(RECONNECT_BACKOFF).await;
            }
        }
    }
}

/// One side's send/receive loop. Mirrors the real Tauri poll loop's
/// reconnect-then-mark-uncertain sequence (`ui/src-tauri/src/lib.rs`'s
/// `poll_loop`), hand-rolled here since this binary has no Tauri app
/// around it.
async fn client_loop(
    role: &'static str,
    db: Arc<Db>,
    account: Account,
    mut contact: Contact,
    mut conn: Connection,
) {
    let mut seq: u64 = 0;
    let mut send_ticker = tokio::time::interval(SEND_INTERVAL);
    let mut poll_ticker = tokio::time::interval(POLL_INTERVAL);
    let mut reconnecting = false;

    loop {
        tokio::select! {
            _ = send_ticker.tick() => {
                if reconnecting {
                    continue;
                }
                let content = format!("{role}-seq-{seq}");
                seq += 1;
                match send_message(&db, &mut conn, &account, &contact, content.as_bytes()).await {
                    Ok(_) => eprintln!("[{}] {role} sent {content}", now_str()),
                    Err(e) => {
                        eprintln!("[{}] {role} send failed ({content}): {e}", now_str());
                        reconnecting = true;
                    }
                }
            }
            _ = poll_ticker.tick() => {
                if reconnecting {
                    conn = connect_retrying(role).await;
                    match conn.authenticate(&account).await {
                        Ok(()) => {
                            match mark_pending_sends_uncertain(&db, &account) {
                                Ok(n) if n > 0 => eprintln!(
                                    "[{}] {role} reconnected, marked {n} outstanding send(s) uncertain",
                                    now_str()
                                ),
                                Ok(_) => eprintln!("[{}] {role} reconnected, nothing outstanding", now_str()),
                                Err(e) => eprintln!("[{}] {role} mark_pending_sends_uncertain failed: {e}", now_str()),
                            }
                            reconnecting = false;
                        }
                        Err(e) => eprintln!("[{}] {role} re-authenticate failed: {e}", now_str()),
                    }
                    continue;
                }
                match receive_pending(&db, &mut conn, &account, &contact).await {
                    Ok(outcome) => {
                        for m in &outcome.messages {
                            eprintln!(
                                "[{}] {role} received {:?}",
                                now_str(),
                                String::from_utf8_lossy(&m.content)
                            );
                        }
                        if !outcome.delivered.is_empty() {
                            eprintln!(
                                "[{}] {role} {} of its own sends confirmed delivered this pass",
                                now_str(),
                                outcome.delivered.len()
                            );
                        }
                        if let Ok(Some(updated)) = db.load_contact(&contact.fingerprint) {
                            contact = updated;
                        }
                    }
                    Err(e) => {
                        eprintln!("[{}] {role} receive failed, will reconnect: {e}", now_str());
                        reconnecting = true;
                    }
                }
            }
        }
    }
}

/// Cross-reference both sides' local stores: every message the sender
/// shows as `delivered: true` must have matching content genuinely
/// present in the recipient's own store. Prints a report; panics (loudly,
/// unmissable in the log) if it ever finds a violation — that would be a
/// regression of finding #29.
async fn status_report(db_alice: &Db, db_bob: &Db, conv_id: [u8; 16]) {
    let alice_messages = db_alice.list_messages(conv_id).unwrap();
    let bob_messages = db_bob.list_messages(conv_id).unwrap();

    let bob_received: HashSet<Vec<u8>> = bob_messages
        .iter()
        .filter(|m| !m.sender_is_local)
        .map(|m| m.content.clone())
        .collect();
    let alice_received: HashSet<Vec<u8>> = alice_messages
        .iter()
        .filter(|m| !m.sender_is_local)
        .map(|m| m.content.clone())
        .collect();

    let mut alice_sent = 0;
    let mut alice_delivered = 0;
    let mut alice_uncertain = 0;
    let mut violations = 0;
    for m in alice_messages.iter().filter(|m| m.sender_is_local) {
        alice_sent += 1;
        if m.uncertain {
            alice_uncertain += 1;
        }
        if m.delivered {
            alice_delivered += 1;
            if !bob_received.contains(&m.content) {
                violations += 1;
                eprintln!(
                    "[{}] !!! FINDING #29 REGRESSION: alice's message {:?} reads delivered=true \
                     but bob's store has no matching content !!!",
                    now_str(),
                    String::from_utf8_lossy(&m.content)
                );
            }
        }
    }

    let mut bob_sent = 0;
    let mut bob_delivered = 0;
    let mut bob_uncertain = 0;
    for m in bob_messages.iter().filter(|m| m.sender_is_local) {
        bob_sent += 1;
        if m.uncertain {
            bob_uncertain += 1;
        }
        if m.delivered {
            bob_delivered += 1;
            if !alice_received.contains(&m.content) {
                violations += 1;
                eprintln!(
                    "[{}] !!! FINDING #29 REGRESSION: bob's message {:?} reads delivered=true \
                     but alice's store has no matching content !!!",
                    now_str(),
                    String::from_utf8_lossy(&m.content)
                );
            }
        }
    }

    eprintln!(
        "[{}] STATUS alice: sent={alice_sent} delivered={alice_delivered} uncertain={alice_uncertain} | \
         bob: sent={bob_sent} delivered={bob_delivered} uncertain={bob_uncertain} | violations={violations}",
        now_str()
    );
}

#[tokio::main]
async fn main() {
    let duration_secs: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(3600 * 6); // default: run until externally killed, 6h ceiling

    eprintln!(
        "[{}] soak test starting, will run up to {duration_secs}s (kill this process to stop earlier)",
        now_str()
    );

    // Randomized, not a fixed name: dratchetd's directory is long-lived (this
    // process may be relaunched against an already-populated one, or share it
    // with other manual runs), so a fixed name risks colliding with a stale
    // registration and fetching the wrong identity's bundle — the same
    // real bug `seed_dev_pair.rs` documents hitting first.
    let username = format!("soakbob{:04x}", OsRng.next_u32() as u16);
    let discriminator = (OsRng.next_u32() % 10_000) as u16;

    // --- Real X3DH pairing, same setup this session's other real tests use. ---
    let mut bob = Account::generate().unwrap();
    let bob_otp_publics = bob.generate_one_time_prekeys(1);
    let bob_local_bundle = bob.publish_bundle(false).unwrap();
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
    let mut publisher = connect_retrying("bob-publisher").await;
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
    let mut fetcher = connect_retrying("alice-fetcher").await;
    let (_, _challenge): (_, AuthChallenge) = fetcher.recv().await.unwrap();
    let fetched = 'fetch: {
        for attempt in 0..20 {
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
            if let Some(bundle) = result.bundle {
                break 'fetch bundle;
            }
            eprintln!("(bob's bundle not published yet, retrying — attempt {attempt})");
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        panic!("bob's bundle was never found after publishing");
    };
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
    )
    .unwrap();
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

    let db_dir = tempfile::tempdir().unwrap().keep();
    let db_alice = Arc::new(Db::create(db_dir.join("soak-alice.redb"), "soak").unwrap());
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

    let db_bob = Arc::new(Db::create(db_dir.join("soak-bob.redb"), "soak").unwrap());
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

    let mut alice_conn = connect_retrying("alice-setup").await;
    alice_conn.authenticate(&alice).await.unwrap();
    let mut bob_conn = connect_retrying("bob-setup").await;
    bob_conn.authenticate(&bob).await.unwrap();

    dratchet_app::announce_routing_id(
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

    dratchet_app::announce_routing_id(&db_bob, &mut bob_conn, &bob, &bob_contact, bob_routing_id)
        .await
        .unwrap();
    receive_pending(&db_alice, &mut alice_conn, &alice, &alice_contact)
        .await
        .unwrap();
    alice_contact = db_alice.load_contact(&bob_fp).unwrap().unwrap();

    alice_contact = record_verification_result(&db_alice, alice_contact, true).unwrap();
    bob_contact = record_verification_result(&db_bob, bob_contact, true).unwrap();

    eprintln!(
        "[{}] pairing complete, both sides Verified — starting soak loops",
        now_str()
    );

    let db_alice_status = Arc::clone(&db_alice);
    let db_bob_status = Arc::clone(&db_bob);

    let status_handle = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(STATUS_INTERVAL);
        loop {
            ticker.tick().await;
            status_report(&db_alice_status, &db_bob_status, conv_id).await;
        }
    });

    let alice_handle = tokio::spawn(client_loop(
        "alice",
        db_alice,
        alice,
        alice_contact,
        alice_conn,
    ));
    let bob_handle = tokio::spawn(client_loop("bob", db_bob, bob, bob_contact, bob_conn));

    tokio::time::sleep(Duration::from_secs(duration_secs)).await;

    eprintln!("[{}] soak test duration elapsed, stopping", now_str());
    status_handle.abort();
    alice_handle.abort();
    bob_handle.abort();
}
