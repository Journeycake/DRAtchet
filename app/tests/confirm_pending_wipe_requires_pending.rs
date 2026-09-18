//! Penetration-test finding, DRA-0020 (round 3, priority 2: message
//! poisoning/compromise — specifically, unauthorized destructive data
//! loss), found auditing `confirm_pending_wipe`
//! (`app/src/lib.rs`) — the sole entry point for §11.9a's "ask before
//! deleting" wipe path, exposed directly as a Tauri command
//! (`ui/src-tauri/src/lib.rs`) callable from the webview's JavaScript.
//!
//! It performed the wipe *unconditionally*: nothing checked that
//! `Contact::wipe_request_pending` was actually set before deleting real
//! message history and clearing the flag. The Svelte UI happens to gate
//! the "Allow" button's *visibility* on this same flag
//! (`{#if selected.wipe_request_pending}` in `+page.svelte`), but that's
//! a rendering decision, not a guard the async handler itself re-checks
//! before calling `invoke("confirm_pending_wipe", ...)` — and nothing
//! stops any other caller of the same Tauri command (a stale click
//! landing after the flag already cleared via another path, a future
//! code path that forgets the precondition, or literally any other
//! script able to reach the webview's `invoke` bridge) from destroying a
//! conversation's history that was never actually up for deletion.
//!
//! No server or network needed — `confirm_pending_wipe` is pure local
//! logic — so this is a fast, local-only test, in the same spirit as
//! `store`'s own unit tests for the primitives it calls.

use dratchet_app::confirm_pending_wipe;
use dratchet_core::account::Account;
use dratchet_core::conversation_id;
use dratchet_store::{Contact, Db, VerificationState};

fn temp_db() -> Db {
    let dir = tempfile::tempdir().unwrap().keep();
    Db::create(dir.join("test.redb"), "pw").unwrap()
}

fn sample_contact(fingerprint: Vec<u8>, wipe_request_pending: bool) -> Contact {
    Contact {
        fingerprint,
        username: Some("bob".to_string()),
        discriminator: Some(1490),
        verification_state: VerificationState::Verified,
        mailbox_id: vec![0xABu8; 16],
        created_at: 0,
        local_routing_id: vec![0xCDu8; 32],
        peer_routing_id: None,
        wipe_ask_before_delete: true,
        peer_wipe_ask_before_delete: None,
        wipe_include_session: false,
        peer_wipe_include_session: None,
        wipe_request_pending,
        wipe_boundary_timestamp: None,
        wipe_boundary_sequence: None,
        peer_wipe_boundary_timestamp: None,
        peer_wipe_boundary_sequence: None,
    }
}

#[test]
fn confirm_pending_wipe_refuses_to_run_when_nothing_is_actually_pending() {
    let db = temp_db();
    let account = Account::generate().unwrap();
    db.save_account(&account).unwrap();

    let peer_fingerprint = vec![9u8; 32];
    let contact = sample_contact(peer_fingerprint.clone(), false);
    db.save_contact(&contact).unwrap();

    let conv_id = conversation_id(account.identity.fingerprint().as_bytes(), &peer_fingerprint);
    db.save_message_now(
        conv_id,
        b"a real message, never up for deletion".to_vec(),
        false,
        None,
        None,
    )
    .unwrap();
    db.save_message_now(conv_id, b"another real message".to_vec(), true, None, None)
        .unwrap();
    assert_eq!(db.list_messages(conv_id).unwrap().len(), 2);

    let result = confirm_pending_wipe(&db, &account, &contact);
    assert!(
        result.is_err(),
        "VULNERABILITY: confirm_pending_wipe wiped a conversation with no wipe request ever \
         actually pending"
    );

    let survivors = db.list_messages(conv_id).unwrap();
    assert_eq!(
        survivors.len(),
        2,
        "FIX VERIFIED: both real messages must survive an unwarranted confirm_pending_wipe call"
    );
}

#[test]
fn confirm_pending_wipe_still_works_normally_when_genuinely_pending() {
    let db = temp_db();
    let account = Account::generate().unwrap();
    db.save_account(&account).unwrap();

    let peer_fingerprint = vec![9u8; 32];
    let contact = sample_contact(peer_fingerprint.clone(), true);
    db.save_contact(&contact).unwrap();

    let conv_id = conversation_id(account.identity.fingerprint().as_bytes(), &peer_fingerprint);
    db.save_message_now(
        conv_id,
        b"about to be wiped, as intended".to_vec(),
        false,
        None,
        None,
    )
    .unwrap();

    let removed = confirm_pending_wipe(&db, &account, &contact)
        .expect("a genuinely pending wipe request must still succeed");
    assert_eq!(removed, 1);
    assert!(db.list_messages(conv_id).unwrap().is_empty());

    let reloaded = db.load_contact(&peer_fingerprint).unwrap().unwrap();
    assert!(
        !reloaded.wipe_request_pending,
        "the flag must still be cleared after a real, successful confirm"
    );
}
