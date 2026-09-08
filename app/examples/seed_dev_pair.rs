//! Dev-only utility: creates two real, mutually-paired `Db` files an
//! operator can point two separate `ui/` (Tauri) instances at to manually
//! test live send/receive networking against each other. Requires a real
//! `dratchetd` already running on `ws://127.0.0.1:8787/v1/ws` (`cargo run
//! --bin dratchetd` from the repo root).
//!
//! Reuses the exact real X3DH-via-directory setup
//! `app/tests/pairing_and_chat.rs` already proves works end-to-end, then
//! completes the routing-id exchange for real through `dratchet_app`'s
//! own `announce_routing_id`/`receive_pending` — dogfooding the same
//! functions the UI calls, not hand-rolled protocol code. Both contacts
//! are left `Pending` (not `Verified`) on purpose, so the app's
//! verification-gate UI stays exercisable against real data too.
//!
//! Run once per fresh pair of DB files:
//! ```sh
//! cargo run -p dratchet-app --example seed_dev_pair
//! ```
//!
//! Pass `--verified` to additionally mark both sides `Verified` right
//! after the routing-id exchange (skipping the app's verification-gate
//! UI) — useful for testing live send/receive directly without also
//! exercising the (separately-tested) verification flow. Default (no
//! flag) behavior is unchanged: both sides stay `Pending`.
//!
//! Then point two `ui/` instances at the two output files, e.g.:
//! ```sh
//! DRATCHET_DEV_DB=/tmp/dratchet-dev-a.redb cargo run   # from ui/src-tauri
//! DRATCHET_DEV_DB=/tmp/dratchet-dev-b.redb cargo run   # a second instance
//! ```

use std::sync::Arc;

use dratchet_app::{announce_routing_id, receive_pending, record_verification_result};
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
const DEV_PASSPHRASE: &str = "dev";

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

#[tokio::main]
async fn main() {
    let verified = std::env::args().any(|a| a == "--verified");
    let path_a = std::env::temp_dir().join("dratchet-dev-a.redb");
    let path_b = std::env::temp_dir().join("dratchet-dev-b.redb");

    if path_a.exists() || path_b.exists() {
        eprintln!(
            "{} or {} already exists — delete both first if you want a fresh pair.",
            path_a.display(),
            path_b.display()
        );
        std::process::exit(1);
    }

    println!(
        "Connecting to {SERVER_URL} (start `cargo run --bin dratchetd` first if this hangs)..."
    );

    // --- Real X3DH via the directory, exactly as
    // app/tests/pairing_and_chat.rs proves works. ---
    //
    // Username is randomized per run: `dratchetd` keeps its directory
    // in-memory for as long as the process lives, so a fixed "bob#5001"
    // would collide with whatever identity claimed it on a previous run
    // against the same long-lived server — and since `PublishBundle` has
    // no server->client acknowledgment, a rejected (UsernameTaken)
    // publish fails *silently*: the fetch below would then return the
    // *other* run's stale bundle instead of this run's, and the ratchet
    // this run constructs from its own fresh private keys would never
    // match it (a real bug this exact way, caught while first running
    // this tool).
    let username = format!("bobdev{:04x}", OsRng.next_u32() as u16);
    let discriminator = (OsRng.next_u32() % 10_000) as u16;

    let mut bob = Account::generate().expect("generate bob");
    let bob_otp_publics = bob.generate_one_time_prekeys(1);
    let bob_local_bundle = bob.publish_bundle(false).expect("bob publish_bundle");
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
    let mut publisher = Connection::connect(SERVER_URL)
        .await
        .expect("connect (is dratchetd running?)");
    let (_, _challenge): (_, AuthChallenge) = publisher.recv().await.expect("recv auth challenge");
    publisher
        .send(
            FrameTag::PublishBundle,
            &PublishBundle {
                bundle: bob_bundle_wire,
            },
        )
        .await
        .expect("publish bob's bundle");

    let alice = Account::generate().expect("generate alice");
    let mut fetcher = Connection::connect(SERVER_URL).await.expect("connect");
    let (_, _challenge): (_, AuthChallenge) = fetcher.recv().await.expect("recv auth challenge");

    // PublishBundle has no server->client acknowledgment (by design — see
    // ws.rs), so there's no way to know from the wire alone that the
    // publish above has actually landed in the directory yet before
    // fetching it back. A real client would only ever fetch a contact's
    // *existing* bundle, never one it just published itself in the same
    // breath, so this race is specific to this seeding tool — worked
    // around here with a short bounded retry rather than by touching the
    // protocol.
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
                .expect("fetch bob's bundle");
            let (_, result): (_, BundleResult) = fetcher.recv().await.expect("recv bundle result");
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
    .expect("x3dh initiate");
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
    .expect("alice ratchet init");

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
    .expect("bob ratchet init");

    // --- Each side saves its account, Pending contact, and ratchet to a
    // real db file. ---
    let alice_fp = alice.identity.fingerprint().as_bytes().to_vec();
    let bob_fp = bob.identity.fingerprint().as_bytes().to_vec();
    let alice_routing_id = random_routing_id();
    let bob_routing_id = random_routing_id();

    let db_alice = Arc::new(Db::create(&path_a, DEV_PASSPHRASE).expect("create db a"));
    db_alice.save_account(&alice).expect("save alice account");
    let mut alice_contact = Contact {
        fingerprint: bob_fp.clone(),
        username: Some(username.clone()),
        discriminator: Some(discriminator),
        verification_state: VerificationState::Pending,
        mailbox_id: bootstrap_mailbox_id(&bob_fp).to_vec(),
        created_at: 0,
        disappearing_timer_secs: None,
        local_routing_id: alice_routing_id.clone(),
        peer_routing_id: None,
    };
    db_alice
        .save_contact(&alice_contact)
        .expect("save alice's contact");
    db_alice
        .save_ratchet(conv_id, &alice_ratchet)
        .expect("save alice's ratchet");

    let db_bob = Arc::new(Db::create(&path_b, DEV_PASSPHRASE).expect("create db b"));
    db_bob.save_account(&bob).expect("save bob account");
    let mut bob_contact = Contact {
        fingerprint: alice_fp.clone(),
        username: None,
        discriminator: None,
        verification_state: VerificationState::Pending,
        mailbox_id: bootstrap_mailbox_id(&alice_fp).to_vec(),
        created_at: 0,
        disappearing_timer_secs: None,
        local_routing_id: bob_routing_id.clone(),
        peer_routing_id: None,
    };
    db_bob
        .save_contact(&bob_contact)
        .expect("save bob's contact");
    db_bob
        .save_ratchet(conv_id, &bob_ratchet)
        .expect("save bob's ratchet");

    // --- Routing-id exchange for real, through dratchet_app's own
    // functions — sequential, since the X3DH responder (bob) has no
    // sending chain until it decrypts something (see announce_routing_id's
    // doc). ---
    let mut alice_conn = Connection::connect(SERVER_URL).await.expect("connect");
    alice_conn
        .authenticate(&alice)
        .await
        .expect("authenticate alice");
    let mut bob_conn = Connection::connect(SERVER_URL).await.expect("connect");
    bob_conn.authenticate(&bob).await.expect("authenticate bob");

    announce_routing_id(
        &db_alice,
        &mut alice_conn,
        &alice,
        &alice_contact,
        alice_routing_id,
    )
    .await
    .expect("alice announce routing id");

    receive_pending(&db_bob, &mut bob_conn, &bob, &bob_contact)
        .await
        .expect("bob receive alice's announce");
    bob_contact = db_bob
        .load_contact(&alice_fp)
        .expect("load bob's contact")
        .expect("bob's contact should exist");

    announce_routing_id(&db_bob, &mut bob_conn, &bob, &bob_contact, bob_routing_id)
        .await
        .expect("bob announce routing id");

    receive_pending(&db_alice, &mut alice_conn, &alice, &alice_contact)
        .await
        .expect("alice receive bob's announce");
    alice_contact = db_alice
        .load_contact(&bob_fp)
        .expect("load alice's contact")
        .expect("alice's contact should exist");

    assert_eq!(
        alice_contact.mailbox_id, bob_contact.mailbox_id,
        "both sides should have converged on the identical mailbox"
    );

    if verified {
        record_verification_result(&db_alice, alice_contact, true)
            .expect("mark alice's contact verified");
        record_verification_result(&db_bob, bob_contact, true)
            .expect("mark bob's contact verified");
    }

    let state_label = if verified { "Verified" } else { "Pending" };
    println!("\nSeeded two real, paired ({state_label}) contacts:");
    println!(
        "  alice's db: {} (contact: {username}#{discriminator:04})",
        path_a.display()
    );
    println!(
        "  bob's db:   {} (contact: alice, no directory registration)",
        path_b.display()
    );
    println!("\nPoint two ui/ instances at these, e.g. from ui/src-tauri:");
    println!("  DRATCHET_DEV_DB={} cargo run", path_a.display());
    println!("  DRATCHET_DEV_DB={} cargo run", path_b.display());
}
