//! Tauri command layer — thin wrappers over `dratchet_app`/`dratchet_store`,
//! per this session's plan: no business logic lives here, so the same
//! `dratchet-app` crate these commands call stays reusable for a native
//! mobile client later without rewriting it.
//!
//! **Dev-only fixture data**: this first pass wires up `list_contacts`/
//! `list_messages` against a local `Db` seeded with sample contacts on
//! first run (one `Pending`, one `Verified`, matching the "DRAtchet UI
//! Mockups" artifact's `alice#4821`/`marcus#0451` scenario) — real
//! `store`/`gate` code, real persistence, just no live server connection
//! yet. `send_message`/`receive_pending` aren't wired to a command yet;
//! that's the next pass, once app startup owns a live
//! `dratchet_client::net::Connection`.

use std::path::PathBuf;

use dratchet_app::open_account;
use dratchet_core::account::Account;
use dratchet_core::conversation_id;
use dratchet_core::x3dh::bootstrap_mailbox_id;
use dratchet_store::{Contact, Db, VerificationState};
use serde::Serialize;
use tauri::State;

struct AppState {
    db: Db,
    account: Account,
}

/// A `Contact`, reshaped for the frontend: byte fields hex-encoded, a
/// ready-made `handle`/`initials` pair instead of making Svelte redo that
/// formatting.
#[derive(Serialize)]
struct ContactDto {
    fingerprint: String,
    handle: String,
    initials: String,
    verified: bool,
    pending: bool,
}

#[derive(Serialize)]
struct MessageDto {
    id: String,
    sender_is_local: bool,
    content: String,
    timestamp: u64,
}

fn to_contact_dto(contact: &Contact) -> ContactDto {
    let handle = match (&contact.username, contact.discriminator) {
        (Some(username), Some(discriminator)) => format!("{username}#{discriminator:04}"),
        _ => hex::encode(&contact.fingerprint[..4]),
    };
    let initials: String = handle.chars().take(2).collect::<String>().to_uppercase();
    ContactDto {
        fingerprint: hex::encode(&contact.fingerprint),
        handle,
        initials,
        verified: contact.verification_state == VerificationState::Verified,
        pending: contact.verification_state == VerificationState::Pending,
    }
}

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
    pub fn decode(s: &str) -> Result<Vec<u8>, String> {
        (0..s.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(s.get(i..i + 2).ok_or("odd-length hex string")?, 16)
                    .map_err(|e| e.to_string())
            })
            .collect()
    }
}

#[tauri::command]
fn list_contacts(state: State<AppState>) -> Result<Vec<ContactDto>, String> {
    dratchet_app::list_contacts(&state.db)
        .map(|contacts| contacts.iter().map(to_contact_dto).collect())
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn list_messages(state: State<AppState>, fingerprint: String) -> Result<Vec<MessageDto>, String> {
    let fp = hex::decode(&fingerprint)?;
    let contact = state
        .db
        .load_contact(&fp)
        .map_err(|e| e.to_string())?
        .ok_or("no such contact")?;
    let messages = dratchet_app::list_messages(&state.db, &state.account, &contact)
        .map_err(|e| e.to_string())?;
    Ok(messages
        .iter()
        .map(|m| MessageDto {
            id: hex::encode(&m.id),
            sender_is_local: m.sender_is_local,
            content: String::from_utf8_lossy(&m.content).into_owned(),
            timestamp: m.timestamp,
        })
        .collect())
}

/// Dev-only: a fresh `Db` has no contacts, so first run seeds two fixture
/// contacts matching the mockups — a `Pending` one (blocked from chat,
/// exercising `store::gate` for real) and a `Verified` one with a short
/// message history. Real `Contact`/`Message` records, real
/// `Db::save_contact`/`save_message_now` calls; just not driven by a live
/// pairing flow yet.
fn seed_fixture_data(db: &Db, account: &Account) {
    if !dratchet_app::list_contacts(db)
        .unwrap_or_default()
        .is_empty()
    {
        return;
    }

    let my_fp = account.identity.fingerprint().as_bytes().to_vec();

    let marcus_fp = vec![0x11u8; 32];
    let marcus = Contact {
        fingerprint: marcus_fp.clone(),
        username: Some("marcus".into()),
        discriminator: Some(451),
        verification_state: VerificationState::Pending,
        mailbox_id: bootstrap_mailbox_id(&marcus_fp).to_vec(),
        created_at: now_unix(),
        disappearing_timer_secs: None,
        local_routing_id: vec![0xAAu8; 32],
        peer_routing_id: None,
    };
    let _ = db.save_contact(&marcus);

    let sable_fp = vec![0x22u8; 32];
    let sable = Contact {
        fingerprint: sable_fp.clone(),
        username: Some("sable".into()),
        discriminator: Some(9012),
        verification_state: VerificationState::Verified,
        mailbox_id: dratchet_store::compute_mailbox_id(&[0xBBu8; 32], &[0xCCu8; 32]).to_vec(),
        created_at: now_unix(),
        disappearing_timer_secs: None,
        local_routing_id: vec![0xBBu8; 32],
        peer_routing_id: Some(vec![0xCCu8; 32]),
    };
    let _ = db.save_contact(&sable);

    let conv_id = conversation_id(&my_fp, &sable_fp);
    let _ = db.save_message_now(conv_id, &sable, b"hey, you free later?".to_vec(), false);
    let _ = db.save_message_now(conv_id, &sable, b"yeah, after 6".to_vec(), true);
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is after the Unix epoch")
        .as_secs()
}

fn dev_db_path() -> PathBuf {
    std::env::temp_dir().join("dratchet-dev.redb")
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let db_path = dev_db_path();
    let db = if db_path.exists() {
        Db::open(&db_path, "dev").expect("open dev db")
    } else {
        Db::create(&db_path, "dev").expect("create dev db")
    };
    let account = open_account(&db).expect("open account");
    seed_fixture_data(&db, &account);

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(AppState { db, account })
        .invoke_handler(tauri::generate_handler![list_contacts, list_messages])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
