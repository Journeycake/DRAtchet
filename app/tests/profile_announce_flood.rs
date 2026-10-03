//! A verified contact could flood your notifications with handle changes.
//!
//! Each `ProfileAnnounce` from a contact whose handle differed from the
//! stored one was recorded and raised a "contact changed their handle"
//! notice (a toast in the desktop app), with no limit
//! (`docs/ARCHITECTURE.md` §10 listed it as an open item). A contact could
//! send hundreds, each one a notice.

use std::sync::Arc;

use dratchet_app::{
    add_contact_by_username, announce_profile, generate_pairing_code, open_account,
    publish_own_bundle, receive_first_contact_attempts, receive_pending,
    PROFILE_NOTICE_INTERVAL_SECS,
};
use dratchet_client::net::Connection;
use dratchet_core::account::Account;
use dratchet_store::{Contact, Db, OwnProfile};
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

#[allow(dead_code)]
fn conversation_id_for(account: &Account, contact: &Contact) -> [u8; 16] {
    dratchet_core::conversation_id(
        account.identity.fingerprint().as_bytes(),
        &contact.fingerprint,
    )
}

fn temp_db() -> Db {
    let dir = tempfile::tempdir().unwrap().keep();
    Db::create(dir.join("test.redb"), "pw").unwrap()
}

struct Pair {
    db_alice: Arc<Db>,
    alice: Account,
    alice_conn: Connection,
    alice_contact: Contact,
    db_bob: Arc<Db>,
    bob: Account,
    bob_conn: Connection,
    bob_contact: Contact,
}

async fn paired(url: &str, tag: &str) -> Pair {
    let db_alice = Arc::new(temp_db());
    let mut alice = open_account(&db_alice).unwrap();
    let mut alice_conn = Connection::connect(url).await.unwrap();
    alice_conn.authenticate(&alice).await.unwrap();
    let alice_profile = publish_own_bundle(
        &db_alice,
        &mut alice_conn,
        &mut alice,
        &format!("alice{tag}"),
    )
    .await
    .unwrap();
    let db_bob = Arc::new(temp_db());
    let mut bob = open_account(&db_bob).unwrap();
    let mut bob_conn = Connection::connect(url).await.unwrap();
    bob_conn.authenticate(&bob).await.unwrap();
    let bob_profile = publish_own_bundle(&db_bob, &mut bob_conn, &mut bob, &format!("bob{tag}"))
        .await
        .unwrap();
    let code = generate_pairing_code(&db_bob).unwrap().code;
    let alice_contact = add_contact_by_username(
        &db_alice,
        &mut alice_conn,
        &alice,
        &alice_profile,
        &bob_profile.username,
        bob_profile.discriminator,
        &code,
    )
    .await
    .unwrap();
    let bob_contact = receive_first_contact_attempts(&db_bob, &mut bob_conn, &mut bob)
        .await
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    Pair {
        db_alice,
        alice,
        alice_conn,
        alice_contact,
        db_bob,
        bob,
        bob_conn,
        bob_contact,
    }
}

/// Bob's view of Alice, fresh from his database.
fn bob_view(p: &Pair) -> Contact {
    p.db_bob
        .load_contact(&p.bob_contact.fingerprint)
        .unwrap()
        .unwrap()
}

/// Bob reads his mail the way the desktop loop does, a few passes, and
/// returns every handle-change notice he'd have been shown.
async fn bob_notices(p: &mut Pair) -> Vec<String> {
    let mut notices = Vec::new();
    for _ in 0..3 {
        let current = bob_view(p);
        let got = receive_pending(&p.db_bob, &mut p.bob_conn, &p.bob, &current)
            .await
            .unwrap();
        notices.extend(got.profile_changes.into_iter().map(|n| n.new_handle));
    }
    notices
}

/// Both sides finish switching to the Conversation Mailbox, as their
/// desktop loops do within a couple of polls of pairing.
async fn settle(p: &mut Pair) {
    for _ in 0..2 {
        let alice_view = p
            .db_alice
            .load_contact(&p.alice_contact.fingerprint)
            .unwrap()
            .unwrap();
        receive_pending(&p.db_alice, &mut p.alice_conn, &p.alice, &alice_view)
            .await
            .unwrap();
        bob_notices(p).await;
    }
}

async fn alice_renames(p: &mut Pair, names: impl IntoIterator<Item = String>) {
    for (i, username) in names.into_iter().enumerate() {
        let alice_view = p
            .db_alice
            .load_contact(&p.alice_contact.fingerprint)
            .unwrap()
            .unwrap();
        announce_profile(
            &p.db_alice,
            &mut p.alice_conn,
            &p.alice,
            &alice_view,
            &OwnProfile {
                username,
                discriminator: 1000 + i as u16,
                signed_prekey_id: 0,
            },
        )
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn a_contact_cannot_flood_handle_change_notices() {
    let url = spawn_server().await;
    let mut p = paired(&url, "70a").await;
    settle(&mut p).await;

    let names: Vec<String> = (0..20).map(|i| format!("flood{i}")).collect();
    alice_renames(&mut p, names).await;
    let notices = bob_notices(&mut p).await;
    assert!(
        notices.len() <= 1,
        "VULNERABILITY: a contact sent 20 handle changes and Bob was shown {} notices",
        notices.len()
    );
    assert_eq!(
        bob_view(&p).username.as_deref(),
        Some("flood19"),
        "the contact list still shows the newest handle"
    );
}

/// Guard: a change that arrives inside the quiet period isn't hidden for
/// good. Once the period is over, Bob is told the handle changed from the
/// one he was last shown to the current one.
#[tokio::test]
async fn a_change_inside_the_quiet_period_is_announced_once_it_ends() {
    let url = spawn_server().await;
    let mut p = paired(&url, "70b").await;
    settle(&mut p).await;

    alice_renames(&mut p, ["first70".to_string()]).await;
    assert_eq!(bob_notices(&mut p).await, vec!["first70#1000".to_string()]);

    alice_renames(&mut p, ["second70".to_string()]).await;
    assert!(
        bob_notices(&mut p).await.is_empty(),
        "a second change straight after the first is held back"
    );
    assert_eq!(bob_view(&p).username.as_deref(), Some("second70"));

    // The quiet period passes.
    let fp = p.bob_contact.fingerprint.clone();
    let (at, shown) = p.db_bob.load_profile_notice_state(&fp).unwrap().unwrap();
    p.db_bob
        .save_profile_notice_state(&fp, at - PROFILE_NOTICE_INTERVAL_SECS - 1, &shown)
        .unwrap();
    assert_eq!(
        bob_notices(&mut p).await,
        vec!["second70#1000".to_string()],
        "the held-back change is announced, from the handle Bob was last shown"
    );
    assert!(bob_notices(&mut p).await.is_empty(), "and only once");
}
