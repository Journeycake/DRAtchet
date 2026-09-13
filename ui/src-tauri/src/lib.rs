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
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use dratchet_app::{open_account, replenish_prekeys_if_low, ProfileReconciliation};
use dratchet_client::net::Connection;
use dratchet_core::account::Account;
use dratchet_store::{Contact, Db, VerificationState};
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::Mutex;

const SERVER_URL: &str = "ws://127.0.0.1:8787/v1/ws";
const POLL_INTERVAL: Duration = Duration::from_secs(2);
const INBOX_UPDATED_EVENT: &str = "dratchet://inbox-updated";
const CONNECTION_STATUS_EVENT: &str = "dratchet://connection-status";
// `replenish_prekeys_if_low` (`ARCHITECTURE.md` §3.4) is cheap but there's no
// reason to query/republish every 2-second tick — once a minute is plenty
// given the batch-of-10/threshold-of-3 sizing, so it only runs on every Nth
// poll tick.
const PREKEY_REPLENISH_CHECK_EVERY_N_TICKS: u32 = 30;
// `poll_loop`'s reconnect backoff after a transport failure
// (`docs/DELIVERY_FAILURE_FINDINGS.md` scenario 23): the first attempt is
// prompt (next tick), and only repeated *reconnect* failures — not the
// original disconnect — push the wait out further, capped so a genuinely
// down server is retried every minute rather than abandoned.
const RECONNECT_INITIAL_BACKOFF: Duration = POLL_INTERVAL;
const RECONNECT_MAX_BACKOFF: Duration = Duration::from_secs(60);

struct AppState {
    db: Db,
    db_path: PathBuf,
    // Behind a `Mutex` (not just `db`/`db_path`) because
    // `register_own_profile`/`rename_own_profile`/the poll loop's
    // first-contact scan all need `&mut Account` — self-registration and
    // discovering a first-contact attempt both consume one-time-prekey
    // secrets that have to survive in memory (and get persisted back to
    // `db`) between calls. `tokio::sync::Mutex`, not `std::sync::Mutex`,
    // since these calls hold it across real network `.await`s — same
    // reason `conn` already uses one.
    account: Arc<Mutex<Account>>,
    conn: Arc<Mutex<Connection>>,
    // Set once at startup if `reconcile_own_profile` finds this device's
    // stored discriminator was reassigned out from under it (only
    // realistically possible after the directory server lost its
    // in-memory state — see `docs/ARCHITECTURE.md` §6.1). A plain
    // `std::sync::Mutex`, not `tokio::sync::Mutex`: both fields below are
    // only ever locked for a quick take/push, never held across an
    // `.await`.
    own_discriminator_change_notice: StdMutex<Option<OwnDiscriminatorChangeNoticeDto>>,
    // Appended to by the poll loop whenever `receive_pending` reports a
    // peer's `username#NNNN` genuinely changed; drained by the frontend
    // alongside every `INBOX_UPDATED_EVENT`.
    peer_profile_change_notices: StdMutex<Vec<PeerProfileChangeNoticeDto>>,
    // Live connection health, updated by `poll_loop` as it detects a
    // transport failure and later reconnects (`docs/DELIVERY_FAILURE_FINDINGS.md`
    // scenario 23) — read once via `get_connection_status` and kept live
    // after that via `CONNECTION_STATUS_EVENT`, so the UI has an honest
    // signal instead of silence while a reconnect is in progress.
    connection_status: StdMutex<ConnectionStatusDto>,
}

/// `poll_loop`'s live connection health, as the frontend sees it — see
/// `AppState::connection_status`.
#[derive(Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ConnectionStatusDto {
    Connected,
    Reconnecting,
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
    /// `docs/ARCHITECTURE.md` §11.9a — this side's own per-conversation
    /// wipe preferences and whether the peer currently has a wipe request
    /// awaiting local confirmation. Peer-side preferences stay internal
    /// (the frontend only needs the effective outcome, not the raw
    /// values) — see `Contact::effective_wipe_ask_before_delete`/
    /// `effective_wipe_include_session`.
    wipe_ask_before_delete: bool,
    wipe_include_session: bool,
    wipe_request_pending: bool,
}

#[derive(Serialize)]
struct MessageDto {
    id: String,
    sender_is_local: bool,
    content: String,
    timestamp: u64,
    /// Only meaningful when `sender_is_local` — whether a `DeliveryAck`
    /// has come back for this message yet (`ARCHITECTURE.md` §4.6). Always
    /// `false` for a received message.
    delivered: bool,
}

/// This device's own directory-facing profile (`dratchet_store::OwnProfile`),
/// reshaped as `username#NNNN` the same way `ContactDto::handle` is.
#[derive(Serialize)]
struct OwnProfileDto {
    handle: String,
    username: String,
    discriminator: u16,
}

fn to_own_profile_dto(profile: &dratchet_store::OwnProfile) -> OwnProfileDto {
    OwnProfileDto {
        handle: format!("{}#{:04}", profile.username, profile.discriminator),
        username: profile.username.clone(),
        discriminator: profile.discriminator,
    }
}

/// A freshly generated pairing code, reshaped for the frontend: an
/// absolute expiry timestamp (Unix seconds) instead of a TTL, so the UI's
/// countdown doesn't need to know `PAIRING_CODE_TTL_SECS` itself.
#[derive(Serialize)]
struct PairingCodeDto {
    code: String,
    expires_at: u64,
}

/// This device's own `username#NNNN` changed without the user asking —
/// `reconcile_own_profile` found the stored discriminator taken and had
/// to pick a new one. Surfaced once, on startup.
#[derive(Serialize, Clone)]
struct OwnDiscriminatorChangeNoticeDto {
    old_handle: String,
    new_handle: String,
}

/// A contact's `username#NNNN` changed — their device went through the
/// same reconciliation (or they renamed on purpose) and announced it.
#[derive(Serialize, Clone)]
struct PeerProfileChangeNoticeDto {
    fingerprint: String,
    old_handle: String,
    new_handle: String,
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
        wipe_ask_before_delete: contact.wipe_ask_before_delete,
        wipe_include_session: contact.wipe_include_session,
        wipe_request_pending: contact.wipe_request_pending,
    }
}

fn to_message_dto(message: &dratchet_store::Message) -> MessageDto {
    MessageDto {
        id: hex::encode(&message.id),
        sender_is_local: message.sender_is_local,
        content: String::from_utf8_lossy(&message.content).into_owned(),
        timestamp: message.timestamp,
        delivered: message.delivered,
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
async fn list_messages(
    state: State<'_, AppState>,
    fingerprint: String,
) -> Result<Vec<MessageDto>, String> {
    let fp = hex::decode(&fingerprint)?;
    let contact = state
        .db
        .load_contact(&fp)
        .map_err(|e| e.to_string())?
        .ok_or("no such contact")?;
    let account = state.account.lock().await;
    let messages =
        dratchet_app::list_messages(&state.db, &account, &contact).map_err(|e| e.to_string())?;
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
    let account = state.account.lock().await;
    let message =
        dratchet_app::send_message(&state.db, &mut conn, &account, &contact, content.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
    Ok(to_message_dto(&message))
}

/// `docs/ARCHITECTURE.md` §11.9a's per-conversation wipe policy: saves
/// this side's own preferences and announces them to the peer.
#[tauri::command]
async fn set_wipe_policy(
    state: State<'_, AppState>,
    fingerprint: String,
    ask_before_delete: bool,
    include_session: bool,
) -> Result<(), String> {
    let fp = hex::decode(&fingerprint)?;
    let contact = state
        .db
        .load_contact(&fp)
        .map_err(|e| e.to_string())?
        .ok_or("no such contact")?;
    let mut conn = state.conn.lock().await;
    let account = state.account.lock().await;
    dratchet_app::announce_wipe_policy(
        &state.db,
        &mut conn,
        &account,
        &contact,
        ask_before_delete,
        include_session,
    )
    .await
    .map_err(|e| e.to_string())?;
    Ok(())
}

/// `docs/ARCHITECTURE.md` §11.9a's per-conversation wipe, the requesting
/// side — the same shape as "delete for everyone." Returns how many local
/// records were removed, for a confirmation toast.
#[tauri::command]
async fn request_conversation_wipe(
    state: State<'_, AppState>,
    fingerprint: String,
) -> Result<usize, String> {
    let fp = hex::decode(&fingerprint)?;
    let contact = state
        .db
        .load_contact(&fp)
        .map_err(|e| e.to_string())?
        .ok_or("no such contact")?;
    let mut conn = state.conn.lock().await;
    let account = state.account.lock().await;
    dratchet_app::request_conversation_wipe(&state.db, &mut conn, &account, &contact)
        .await
        .map_err(|e| e.to_string())
}

/// The "Allow" side of an incoming wipe request (`ContactDto::wipe_request_pending`).
#[tauri::command]
async fn confirm_pending_wipe(
    state: State<'_, AppState>,
    fingerprint: String,
) -> Result<usize, String> {
    let fp = hex::decode(&fingerprint)?;
    let contact = state
        .db
        .load_contact(&fp)
        .map_err(|e| e.to_string())?
        .ok_or("no such contact")?;
    let account = state.account.lock().await;
    dratchet_app::confirm_pending_wipe(&state.db, &account, &contact).map_err(|e| e.to_string())
}

/// The "Decline" side of an incoming wipe request.
#[tauri::command]
fn decline_pending_wipe(state: State<AppState>, fingerprint: String) -> Result<(), String> {
    let fp = hex::decode(&fingerprint)?;
    let contact = state
        .db
        .load_contact(&fp)
        .map_err(|e| e.to_string())?
        .ok_or("no such contact")?;
    dratchet_app::decline_pending_wipe(&state.db, &contact).map_err(|e| e.to_string())?;
    Ok(())
}

/// This device's current live connection health — called once on
/// startup so the UI has an accurate value before the first
/// `CONNECTION_STATUS_EVENT` (which only fires on a *change*).
#[tauri::command]
fn get_connection_status(state: State<AppState>) -> ConnectionStatusDto {
    *state
        .connection_status
        .lock()
        .expect("connection_status mutex poisoned")
}

/// This device's own registered profile, if self-registration
/// (`register_own_profile`) has ever run — `None` gates the Settings
/// "Choose a username" form vs. the normal profile display.
#[tauri::command]
fn get_own_profile(state: State<AppState>) -> Result<Option<OwnProfileDto>, String> {
    state
        .db
        .load_own_profile()
        .map(|opt| opt.as_ref().map(to_own_profile_dto))
        .map_err(|e| e.to_string())
}

/// First-run self-registration, `docs/ARCHITECTURE.md` §6.1 — publishes
/// this device's own prekey bundle under `username`, picking (and
/// retrying on collision) a random discriminator.
#[tauri::command]
async fn register_own_profile(
    state: State<'_, AppState>,
    username: String,
) -> Result<OwnProfileDto, String> {
    let mut conn = state.conn.lock().await;
    let mut account = state.account.lock().await;
    let profile = dratchet_app::publish_own_bundle(&state.db, &mut conn, &mut account, &username)
        .await
        .map_err(|e| e.to_string())?;
    Ok(to_own_profile_dto(&profile))
}

/// §6.1's rename — re-publishes under `new_username`.
#[tauri::command]
async fn rename_own_profile(
    state: State<'_, AppState>,
    new_username: String,
) -> Result<OwnProfileDto, String> {
    let mut conn = state.conn.lock().await;
    let mut account = state.account.lock().await;
    let profile =
        dratchet_app::rename_own_profile(&state.db, &mut conn, &mut account, &new_username)
            .await
            .map_err(|e| e.to_string())?;
    Ok(to_own_profile_dto(&profile))
}

/// §6.4's pairing-code-gated add-contact — generates and displays this
/// device's live code, to be read out over an already-trusted channel.
#[tauri::command]
fn generate_pairing_code(state: State<AppState>) -> Result<PairingCodeDto, String> {
    let code = dratchet_app::generate_pairing_code(&state.db).map_err(|e| e.to_string())?;
    Ok(PairingCodeDto {
        code: code.code,
        expires_at: code.generated_at + dratchet_store::PAIRING_CODE_TTL_SECS,
    })
}

/// §6.4's pairing-code-gated add-contact — the initiator side. Requires
/// this device to already have its own registered profile (the peer's
/// client labels the new contact from it).
#[tauri::command]
async fn add_contact(
    state: State<'_, AppState>,
    username: String,
    discriminator: u16,
    pairing_code: String,
) -> Result<ContactDto, String> {
    let own_profile = state
        .db
        .load_own_profile()
        .map_err(|e| e.to_string())?
        .ok_or("choose a username for yourself first")?;
    let mut conn = state.conn.lock().await;
    let account = state.account.lock().await;
    let contact = dratchet_app::add_contact_by_username(
        &state.db,
        &mut conn,
        &account,
        &own_profile,
        &username,
        discriminator,
        &pairing_code,
    )
    .await
    .map_err(|e| e.to_string())?;
    Ok(to_contact_dto(&contact))
}

/// One-shot: returns and clears the startup discriminator-change notice,
/// if `reconcile_own_profile` found one. `None` on every call after the
/// first (or if nothing changed) — the frontend calls this once on mount.
#[tauri::command]
fn take_own_discriminator_change_notice(
    state: State<AppState>,
) -> Option<OwnDiscriminatorChangeNoticeDto> {
    state
        .own_discriminator_change_notice
        .lock()
        .expect("own_discriminator_change_notice mutex poisoned")
        .take()
}

/// Drains every peer profile-change notice the poll loop has accumulated
/// since the last call — called alongside every `INBOX_UPDATED_EVENT`.
#[tauri::command]
fn take_peer_profile_change_notices(state: State<AppState>) -> Vec<PeerProfileChangeNoticeDto> {
    std::mem::take(
        &mut *state
            .peer_profile_change_notices
            .lock()
            .expect("peer_profile_change_notices mutex poisoned"),
    )
}

/// `docs/ARCHITECTURE.md` §11.9's **quick wipe** — the Settings "Danger
/// Zone" action that crypto-shreds message history and cached ratchet/
/// session state while leaving the account and contact list untouched.
/// Returns how many records were erased, for the frontend's confirmation
/// toast. See `dratchet_app::quick_wipe`/`dratchet_store::Db::quick_wipe`
/// for what "crypto-shred" actually means here — a real key destruction,
/// not just a `DELETE`.
#[tauri::command]
fn quick_wipe(state: State<AppState>) -> Result<usize, String> {
    dratchet_app::quick_wipe(&state.db).map_err(|e| e.to_string())
}

/// `docs/ARCHITECTURE.md` §11.9's **full wipe** — additionally destroys
/// the account's identity and the contact list, then restarts the whole
/// app process. Restarting (rather than trying to hot-swap `AppState.db`
/// in place) is what makes `dratchet_app::full_wipe`'s caller contract
/// trivial to satisfy: `run()`'s existing "no db file at this path yet →
/// generate a fresh identity" startup path handles the post-wipe launch
/// with zero special-casing, since `full_wipe` already removed the file.
#[tauri::command]
fn full_wipe(state: State<AppState>, app: AppHandle) -> Result<(), String> {
    dratchet_app::full_wipe(&state.db, &state.db_path).map_err(|e| e.to_string())?;
    app.restart();
}

/// Connect, authenticate, and reconcile this device's own registration —
/// the full sequence `run()` performs once at startup, factored out so
/// `poll_loop`'s reconnect-on-failure path (`docs/DELIVERY_FAILURE_FINDINGS.md`
/// scenario 23) can produce a connection exactly as complete as the
/// original one, including reclaiming a squatted handle if the directory
/// forgot this device owned it — the same server-restart scenario a
/// dropped WebSocket often coincides with, so skipping reconciliation on
/// reconnect would silently reopen the exact gap `reconcile_own_profile`
/// exists to close. Returns the discriminator-change notice, if
/// reconciliation produced one, so the caller can decide where to put it.
///
/// Takes `url` rather than reading `SERVER_URL` itself so tests can point
/// it at a real ephemeral test server instead of the hardcoded default.
async fn connect_authenticate_and_reconcile(
    url: &str,
    db: &Db,
    account: &mut Account,
) -> Result<(Connection, Option<OwnDiscriminatorChangeNoticeDto>), String> {
    let mut conn = Connection::connect(url).await?;
    conn.authenticate(account).await?;

    let mut notice = None;
    match dratchet_app::reconcile_own_profile(db, &mut conn, account).await {
        Ok(ProfileReconciliation::DiscriminatorChanged { old, new }) => {
            let old_handle = format!("{}#{:04}", old.username, old.discriminator);
            let new_handle = format!("{}#{:04}", new.username, new.discriminator);
            eprintln!(
                "reclaiming {old_handle} failed (taken by someone else since the \
                 directory last saw this device) — now {new_handle}"
            );
            if let Ok(contacts) = dratchet_app::list_contacts(db) {
                for contact in contacts {
                    if contact.verification_state != VerificationState::Verified {
                        continue;
                    }
                    if let Err(e) =
                        dratchet_app::announce_profile(db, &mut conn, account, &contact, &new).await
                    {
                        eprintln!("failed to announce new handle to a contact: {e}");
                    }
                }
            }
            notice = Some(OwnDiscriminatorChangeNoticeDto {
                old_handle,
                new_handle,
            });
        }
        Ok(ProfileReconciliation::Unchanged(_) | ProfileReconciliation::Unregistered) => {}
        Err(e) => eprintln!("reconcile_own_profile failed: {e}"),
    }

    Ok((conn, notice))
}

/// Update `state.connection_status` and, only if it actually changed,
/// emit `CONNECTION_STATUS_EVENT` — repeatedly re-setting `Reconnecting`
/// on every backoff-gated retry attempt would be a harmless but noisy
/// no-op for the frontend, so this stays quiet unless there's something
/// new to say.
fn set_connection_status(
    app_handle: &AppHandle,
    state: &AppState,
    new_status: ConnectionStatusDto,
) {
    let mut status = state
        .connection_status
        .lock()
        .expect("connection_status mutex poisoned");
    if *status != new_status {
        *status = new_status;
        drop(status);
        let _ = app_handle.emit(CONNECTION_STATUS_EVENT, new_status);
    }
}

/// Whether `e` indicates the underlying transport actually failed (the
/// WebSocket send/recv itself), as opposed to an application-level error
/// (`NotAcknowledged`, a decode failure, etc.) that says nothing about
/// whether the connection is still usable. Only the former should trigger
/// `poll_loop`'s reconnect path — retrying a healthy connection because a
/// peer's malformed entry produced some other `Error` variant would be
/// pointless and would blow away a connection that didn't need replacing.
fn is_connection_error(e: &dratchet_app::Error) -> bool {
    matches!(e, dratchet_app::Error::Connection(_))
}

/// Background receive loop, spawned once in `.setup()`: every
/// `POLL_INTERVAL`, scans for new §6.4 pairing-code-gated first-contact
/// attempts (`dratchet_app::receive_first_contact_attempts`) and calls
/// `dratchet_app::receive_pending` for every saved contact (`Pending`
/// ones included — that's the only way a `RoutingIdAnnounce` ever gets
/// processed) and, on any actual change (a new contact discovered, a
/// message received, a contact's mailbox transitioning off its bootstrap
/// address, or `Received::wipe_activity` — a wipe-policy announcement
/// recorded or a wipe request auto-complied/set pending, §11.9a), emits
/// one coarse `INBOX_UPDATED_EVENT` — no fine-grained payload; the
/// frontend just refetches. Every `PREKEY_REPLENISH_CHECK_EVERY_N_TICKS`th
/// tick it also checks `dratchet_app::replenish_prekeys_if_low` (§3.4) —
/// silent either way, since a republished prekey batch isn't something the
/// frontend needs to know about. On a transport-layer error from any of
/// the above, reconnects (`connect_authenticate_and_reconcile`) on a
/// backoff-gated retry rather than silently and permanently going dark —
/// see `docs/DELIVERY_FAILURE_FINDINGS.md` scenario 23 for the failure
/// mode this closes.
async fn poll_loop(app_handle: AppHandle) {
    let mut ticker = tokio::time::interval(POLL_INTERVAL);
    let mut tick_count: u32 = 0;
    // Set the moment a tick's work hits a transport-layer error
    // (`is_connection_error`); cleared the moment a reconnect succeeds.
    // While set, ordinary tick work is skipped in favor of a
    // backoff-gated reconnect attempt — every command shares `state.conn`
    // behind the same `Mutex`, so healing it here heals it for the whole
    // app, not just this loop (`docs/DELIVERY_FAILURE_FINDINGS.md`
    // scenario 23).
    let mut reconnect_backoff = RECONNECT_INITIAL_BACKOFF;
    let mut next_reconnect_attempt: Option<std::time::Instant> = None;

    loop {
        ticker.tick().await;
        tick_count = tick_count.wrapping_add(1);
        let state = app_handle.state::<AppState>();

        if let Some(due) = next_reconnect_attempt {
            if std::time::Instant::now() < due {
                continue;
            }
            let mut account = state.account.lock().await;
            match connect_authenticate_and_reconcile(SERVER_URL, &state.db, &mut account).await {
                Ok((new_conn, notice)) => {
                    eprintln!("poll: reconnected to {SERVER_URL}");
                    *state.conn.lock().await = new_conn;
                    if let Some(notice) = notice {
                        *state
                            .own_discriminator_change_notice
                            .lock()
                            .expect("own_discriminator_change_notice mutex poisoned") =
                            Some(notice);
                    }
                    next_reconnect_attempt = None;
                    reconnect_backoff = RECONNECT_INITIAL_BACKOFF;
                    set_connection_status(&app_handle, &state, ConnectionStatusDto::Connected);
                }
                Err(e) => {
                    eprintln!("poll: reconnect failed, retrying in {reconnect_backoff:?}: {e}");
                    next_reconnect_attempt = Some(std::time::Instant::now() + reconnect_backoff);
                    reconnect_backoff = (reconnect_backoff * 2).min(RECONNECT_MAX_BACKOFF);
                    continue;
                }
            }
        }

        let mut changed = false;
        let mut connection_died = false;
        {
            let mut conn = state.conn.lock().await;
            let mut account = state.account.lock().await;
            match dratchet_app::receive_first_contact_attempts(&state.db, &mut conn, &mut account)
                .await
            {
                Ok(new_contacts) if !new_contacts.is_empty() => changed = true,
                Ok(_) => {}
                Err(e) => {
                    connection_died = is_connection_error(&e);
                    eprintln!("poll: receive_first_contact_attempts failed: {e}");
                }
            }

            if !connection_died && tick_count.is_multiple_of(PREKEY_REPLENISH_CHECK_EVERY_N_TICKS) {
                if let Err(e) = replenish_prekeys_if_low(&state.db, &mut conn, &mut account).await {
                    connection_died = is_connection_error(&e);
                    eprintln!("poll: replenish_prekeys_if_low failed: {e}");
                }
            }
        }

        if !connection_died {
            let contacts = match dratchet_app::list_contacts(&state.db) {
                Ok(contacts) => contacts,
                Err(e) => {
                    eprintln!("poll: list_contacts failed: {e}");
                    continue;
                }
            };

            for contact in contacts {
                if connection_died {
                    break;
                }
                let mailbox_before = contact.mailbox_id.clone();
                let received = {
                    let mut conn = state.conn.lock().await;
                    let account = state.account.lock().await;
                    dratchet_app::receive_pending(&state.db, &mut conn, &account, &contact).await
                };
                match received {
                    Ok(outcome) => {
                        if !outcome.messages.is_empty()
                            || !outcome.delivered.is_empty()
                            || outcome.wipe_activity
                            || !outcome.profile_changes.is_empty()
                        {
                            changed = true;
                        }
                        if !outcome.profile_changes.is_empty() {
                            let mut notices = state
                                .peer_profile_change_notices
                                .lock()
                                .expect("peer_profile_change_notices mutex poisoned");
                            notices.extend(outcome.profile_changes.into_iter().map(|n| {
                                PeerProfileChangeNoticeDto {
                                    fingerprint: hex::encode(&n.fingerprint),
                                    old_handle: n.old_handle,
                                    new_handle: n.new_handle,
                                }
                            }));
                        }
                    }
                    Err(e) => {
                        connection_died = is_connection_error(&e);
                        eprintln!("poll: receive_pending failed for a contact: {e}");
                    }
                }
                if let Ok(Some(updated)) = state.db.load_contact(&contact.fingerprint) {
                    if updated.mailbox_id != mailbox_before {
                        changed = true;
                    }
                }
            }
        }

        if connection_died {
            eprintln!("poll: connection lost, will attempt to reconnect next tick");
            next_reconnect_attempt = Some(std::time::Instant::now());
            set_connection_status(&app_handle, &state, ConnectionStatusDto::Reconnecting);
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
    let mut account = open_account(&db).expect("open account");

    // Connect + authenticate once, synchronously, before the app is
    // considered ready — fails loudly if dratchetd isn't reachable,
    // matching the existing db/account `.expect(...)` posture. A real
    // server-address setting/retry UI is future work. Also reconciles
    // this device's own registration and, if the directory forgot it
    // owned its discriminator, broadcasts the new one to every
    // already-Verified contact right away — see
    // `connect_authenticate_and_reconcile`'s doc, also reused by
    // `poll_loop`'s reconnect-after-failure path so a re-established
    // connection is never any less complete than this first one.
    let (conn, own_discriminator_change_notice) = tauri::async_runtime::block_on(
        connect_authenticate_and_reconcile(SERVER_URL, &db, &mut account),
    )
    .unwrap_or_else(|e| panic!("connect to {SERVER_URL} (is dratchetd running?): {e}"));
    let conn = Arc::new(Mutex::new(conn));
    let account = Arc::new(Mutex::new(account));

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(AppState {
            db,
            db_path,
            account,
            conn,
            own_discriminator_change_notice: StdMutex::new(own_discriminator_change_notice),
            peer_profile_change_notices: StdMutex::new(Vec::new()),
            // `run()` only reaches here after a successful connect+authenticate
            // above (a failure panics), so `Connected` is the honest starting
            // value — never `Reconnecting` before `poll_loop` has even run once.
            connection_status: StdMutex::new(ConnectionStatusDto::Connected),
        })
        .invoke_handler(tauri::generate_handler![
            list_contacts,
            list_messages,
            send_message,
            set_wipe_policy,
            request_conversation_wipe,
            confirm_pending_wipe,
            decline_pending_wipe,
            get_own_profile,
            register_own_profile,
            rename_own_profile,
            generate_pairing_code,
            add_contact,
            take_own_discriminator_change_notice,
            take_peer_profile_change_notices,
            quick_wipe,
            full_wipe,
            get_connection_status
        ])
        .setup(|app| {
            let app_handle = app.handle().clone();
            tauri::async_runtime::spawn(poll_loop(app_handle));
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

/// Real, no-mocks coverage for the two testable units behind `poll_loop`'s
/// reconnect logic (`docs/DELIVERY_FAILURE_FINDINGS.md` scenario 23):
/// `is_connection_error`'s classification, and
/// `connect_authenticate_and_reconcile` actually producing a live,
/// usable connection against a real spawned `dratchet_server::app()` (the
/// same helper both `run()`'s startup and `poll_loop`'s reconnect path
/// call). `poll_loop`'s own backoff *timing* state machine isn't covered
/// here — it needs a real `tauri::AppHandle`, which isn't practical to
/// construct in a plain unit test — but the two pieces that actually
/// determine correctness (does a dead connection get correctly
/// recognized, does a fresh one actually work) are.
#[cfg(test)]
mod tests {
    use super::*;
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

    fn temp_db() -> Db {
        let dir = tempfile::tempdir().unwrap().keep();
        Db::create(dir.join("test.redb"), "pw").unwrap()
    }

    #[test]
    fn is_connection_error_matches_only_the_transport_variant() {
        assert!(is_connection_error(&dratchet_app::Error::Connection(
            "socket closed".into()
        )));
        assert!(!is_connection_error(&dratchet_app::Error::NotAcknowledged));
        assert!(!is_connection_error(&dratchet_app::Error::NoSession));
        assert!(!is_connection_error(&dratchet_app::Error::UsernameTaken));
    }

    /// The actual risk surface: does the helper `run()` and `poll_loop`
    /// both depend on really produce a working connection? Connects
    /// against a real server, confirms the returned `Connection` can
    /// genuinely be used afterward (a real `FetchOwnPrekeyCount`
    /// round-trip), and confirms reconciliation is a no-op for an
    /// account that's never published anything — matching what a normal,
    /// healthy reconnect looks like.
    #[tokio::test]
    async fn connect_authenticate_and_reconcile_produces_a_live_usable_connection() {
        let url = spawn_server().await;
        let db = temp_db();
        let mut account = open_account(&db).unwrap();

        let (mut conn, notice) = connect_authenticate_and_reconcile(&url, &db, &mut account)
            .await
            .expect("connect + authenticate + reconcile against a real, reachable server");
        assert!(
            notice.is_none(),
            "an account that's never published anything reconciles as a no-op, \
             so there's no discriminator-change notice to surface"
        );

        // The connection really is live, not just "didn't error" — a
        // further real round-trip on it succeeds, exactly what
        // `poll_loop`'s very next tick immediately does after reconnecting.
        let count = dratchet_app::replenish_prekeys_if_low(&db, &mut conn, &mut account).await;
        assert!(
            count.is_ok(),
            "the connection this helper hands back must still be usable for a real \
             follow-up call"
        );
    }

    /// The failure path `poll_loop`'s backoff depends on: connecting to
    /// nothing reachable must return a real `Err`, not hang or panic.
    #[tokio::test]
    async fn connect_authenticate_and_reconcile_fails_cleanly_against_an_unreachable_server() {
        let db = temp_db();
        let mut account = open_account(&db).unwrap();
        let result =
            connect_authenticate_and_reconcile("ws://127.0.0.1:1/v1/ws", &db, &mut account).await;
        assert!(
            result.is_err(),
            "an unreachable address must fail fast with an Err, which is what \
             poll_loop's backoff branch is built to receive and act on"
        );
    }

    /// Proof that a fresh connection from this helper really does replace
    /// a dead one end to end: authenticate once, drop that connection
    /// (simulating the transport dying), call the helper again, and
    /// confirm the *new* connection still works for a real round-trip —
    /// the exact sequence `poll_loop` performs when `connection_died` is
    /// set and its backoff timer fires.
    #[tokio::test]
    async fn a_second_call_produces_a_working_replacement_connection() {
        let url = spawn_server().await;
        let db = temp_db();
        let mut account = open_account(&db).unwrap();

        let (first_conn, _) = connect_authenticate_and_reconcile(&url, &db, &mut account)
            .await
            .unwrap();
        drop(first_conn); // simulates the transport dying

        let (mut second_conn, _) = connect_authenticate_and_reconcile(&url, &db, &mut account)
            .await
            .expect("reconnecting after the first connection is gone must still succeed");
        let ok = dratchet_app::replenish_prekeys_if_low(&db, &mut second_conn, &mut account)
            .await
            .is_ok();
        assert!(ok, "the replacement connection is genuinely usable");
    }
}
