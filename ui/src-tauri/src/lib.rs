//! Tauri command layer — thin wrappers over `dratchet_app`/`dratchet_store`,
//! per this session's plan: no business logic lives here, so the same
//! `dratchet-app` crate these commands call stays reusable for a native
//! mobile client later without rewriting it.
//!
//! **Live networking**: `.setup()` opens one real
//! `dratchet_client::net::Connection` to `SERVER_URL`, authenticated with
//! the local account, shared (behind a `tokio::sync::Mutex`, since a
//! single WS connection can't safely be written from two places at once)
//! between the `send_message` command and a background poll loop that
//! calls `dratchet_app::receive_pending` for every contact every
//! `POLL_INTERVAL` — the same 2-second cadence `client/src/main.rs`'s
//! reference CLI already uses. A real server-address *setting* is future
//! work; `SERVER_URL` is a hardcoded dev default for now.
//!
//! **Dev DB selection**: `DRATCHET_DEV_DB` names which `Db` file to open
//! (defaults to a fixed dev path) — see `app/examples/seed_dev_pair.rs`
//! for how to produce two real, mutually-paired ones to point two
//! instances of this app at.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use dratchet_app::open_account;
use dratchet_client::net::Connection;
use dratchet_core::account::Account;
use dratchet_store::{Contact, Db, VerificationState};
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::Mutex;

const SERVER_URL: &str = "ws://127.0.0.1:8787/v1/ws";
const POLL_INTERVAL: Duration = Duration::from_secs(2);
const INBOX_UPDATED_EVENT: &str = "dratchet://inbox-updated";

struct AppState {
    db: Db,
    account: Account,
    conn: Arc<Mutex<Connection>>,
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

fn to_message_dto(message: &dratchet_store::Message) -> MessageDto {
    MessageDto {
        id: hex::encode(&message.id),
        sender_is_local: message.sender_is_local,
        content: String::from_utf8_lossy(&message.content).into_owned(),
        timestamp: message.timestamp,
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
    Ok(messages.iter().map(to_message_dto).collect())
}

#[tauri::command]
async fn send_message(
    state: State<'_, AppState>,
    fingerprint: String,
    content: String,
) -> Result<MessageDto, String> {
    let fp = hex::decode(&fingerprint)?;
    let contact = state
        .db
        .load_contact(&fp)
        .map_err(|e| e.to_string())?
        .ok_or("no such contact")?;
    let mut conn = state.conn.lock().await;
    let message = dratchet_app::send_message(
        &state.db,
        &mut conn,
        &state.account,
        &contact,
        content.as_bytes(),
    )
    .await
    .map_err(|e| e.to_string())?;
    Ok(to_message_dto(&message))
}

/// Background receive loop, spawned once in `.setup()`: every
/// `POLL_INTERVAL`, calls `dratchet_app::receive_pending` for every saved
/// contact (`Pending` ones included — that's the only way a
/// `RoutingIdAnnounce` ever gets processed) and, on any actual change
/// (a message received, or a contact's mailbox transitioning off its
/// bootstrap address), emits one coarse `INBOX_UPDATED_EVENT` — no
/// fine-grained payload; the frontend just refetches.
async fn poll_loop(app_handle: AppHandle) {
    let mut ticker = tokio::time::interval(POLL_INTERVAL);
    loop {
        ticker.tick().await;
        let state = app_handle.state::<AppState>();

        let contacts = match dratchet_app::list_contacts(&state.db) {
            Ok(contacts) => contacts,
            Err(e) => {
                eprintln!("poll: list_contacts failed: {e}");
                continue;
            }
        };

        let mut changed = false;
        for contact in contacts {
            let mailbox_before = contact.mailbox_id.clone();
            let received = {
                let mut conn = state.conn.lock().await;
                dratchet_app::receive_pending(&state.db, &mut conn, &state.account, &contact).await
            };
            match received {
                Ok(messages) if !messages.is_empty() => changed = true,
                Ok(_) => {}
                Err(e) => eprintln!("poll: receive_pending failed for a contact: {e}"),
            }
            if let Ok(Some(updated)) = state.db.load_contact(&contact.fingerprint) {
                if updated.mailbox_id != mailbox_before {
                    changed = true;
                }
            }
        }

        if changed {
            let _ = app_handle.emit(INBOX_UPDATED_EVENT, ());
        }
    }
}

fn dev_db_path() -> PathBuf {
    std::env::var("DRATCHET_DEV_DB")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir().join("dratchet-dev-a.redb"))
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

    // Connect + authenticate once, synchronously, before the app is
    // considered ready — fails loudly if dratchetd isn't reachable,
    // matching the existing db/account `.expect(...)` posture. A real
    // server-address setting/retry UI is future work.
    let conn = tauri::async_runtime::block_on(async {
        let mut conn = Connection::connect(SERVER_URL)
            .await
            .unwrap_or_else(|e| panic!("connect to {SERVER_URL} (is dratchetd running?): {e}"));
        conn.authenticate(&account)
            .await
            .expect("authenticate with dratchetd");
        conn
    });
    let conn = Arc::new(Mutex::new(conn));

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(AppState { db, account, conn })
        .invoke_handler(tauri::generate_handler![
            list_contacts,
            list_messages,
            send_message
        ])
        .setup(|app| {
            let app_handle = app.handle().clone();
            tauri::async_runtime::spawn(poll_loop(app_handle));
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
