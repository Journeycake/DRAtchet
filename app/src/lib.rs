//! Portable app core — the business logic a UI actually calls: account
//! setup, contacts/messages, and gated send/receive over the directory-
//! based pairing flow (`docs/ARCHITECTURE.md` §6.5's mandatory-
//! verification gate, `store::gate`; §11.1's routing-id mailbox
//! transition, `store::routing`).
//!
//! UI-agnostic on purpose: a Tauri command layer wraps these functions
//! directly today, and the same functions are what a `uniffi-rs` binding
//! layer would wrap for a native mobile client later — see this session's
//! plan file for why that split matters. Nothing here touches a UI
//! toolkit, a database schema, or a network detail beyond what
//! `dratchet_client::net::Connection`/`dratchet_store::Db` already expose.
//!
//! **Deliberately not built here — a real, currently-unimplemented
//! protocol gap found while scoping this crate, not a shortcut**:
//! starting a brand-new conversation purely from a `username#NNNN`
//! lookup. `docs/MESSAGE_SCHEMA.md` §3 documents an "X3DH session-
//! establishment message" wire format carrying
//! `initiator_identity_fingerprint` (so a responder can identify who's
//! messaging them) bundled with the first ratchet envelope — but
//! `core::x3dh::X3dhInitMessage` (what's actually implemented) carries
//! neither of those, and no wire type for it exists in
//! `dratchet_server::protocol`. Without that, a responder who's never
//! heard of the initiator has no way to discover the attempt or
//! reconstruct their side of the ratchet from the wire alone. Every
//! function below therefore operates on a contact whose `RatchetState`
//! already exists (persisted via `Db::save_ratchet`) — exactly the
//! shape `store/tests/routing_id_exchange.rs` already proves end-to-end.
//! Fixing the gap above is real follow-on work, flagged here rather than
//! worked around.

pub mod error;

pub use error::{Error, Result};

use dratchet_client::net::Connection;
use dratchet_core::account::Account;
use dratchet_core::conversation_id;
use dratchet_core::envelope::Envelope;
use dratchet_core::payload::{
    ConversationWipePolicyAnnounce, RoutingIdAnnounce, PAYLOAD_CHAT,
    PAYLOAD_CONVERSATION_WIPE_POLICY_ANNOUNCE, PAYLOAD_CONVERSATION_WIPE_REQUEST,
    PAYLOAD_ROUTING_ID_ANNOUNCE,
};
use dratchet_core::x3dh::bootstrap_mailbox_id;
use dratchet_server::protocol::{
    Ack, FrameTag, MailboxDelete, MailboxEntries, MailboxFetch, MailboxWrite,
};
use dratchet_store::{decrypt_gated, encrypt_gated, Contact, Db, Message};

/// Load the local account, or generate and persist a fresh one if this is
/// a brand-new `Db` — the one-time "first launch" path a UI's startup
/// calls once.
pub fn open_account(db: &Db) -> Result<Account> {
    if let Some(account) = db.load_account()? {
        return Ok(account);
    }
    let account = Account::generate()?;
    db.save_account(&account)?;
    Ok(account)
}

/// Every saved contact — a UI's conversation list.
pub fn list_contacts(db: &Db) -> Result<Vec<Contact>> {
    Ok(db.list_contacts()?)
}

/// Every non-expired message with `contact`, oldest first.
pub fn list_messages(db: &Db, account: &Account, contact: &Contact) -> Result<Vec<Message>> {
    let conv_id = conversation_id_for(account, contact);
    Ok(db.list_messages(conv_id)?)
}

fn conversation_id_for(account: &Account, contact: &Contact) -> [u8; 16] {
    conversation_id(
        account.identity.fingerprint().as_bytes(),
        &contact.fingerprint,
    )
}

/// Encrypt and send `content` to `contact`, refusing (via
/// `store::gate::encrypt_gated`) if `contact` isn't `Verified` yet —
/// `docs/ARCHITECTURE.md` §6.5's mandatory gate, enforced here, not left
/// to the UI to remember. On success, persists both the advanced ratchet
/// state and the sent message.
pub async fn send_message(
    db: &Db,
    conn: &mut Connection,
    account: &Account,
    contact: &Contact,
    content: &[u8],
) -> Result<Message> {
    let conv_id = conversation_id_for(account, contact);
    let mut ratchet = db.load_ratchet(conv_id)?.ok_or(Error::NoSession)?;

    let envelope = encrypt_gated(&mut ratchet, contact, PAYLOAD_CHAT, content)?;

    conn.send(
        FrameTag::MailboxWrite,
        &MailboxWrite {
            mailbox_id: contact.mailbox_id.clone(),
            envelope: envelope.encode(),
            ttl: 14 * 24 * 60 * 60, // 14 days, `ARCHITECTURE.md` §4.5's default
        },
    )
    .await?;
    let (_, ack): (_, Ack) = conn.recv().await?;
    if !ack.ok {
        return Err(Error::NotAcknowledged);
    }

    db.save_ratchet(conv_id, &ratchet)?;
    Ok(db.save_message_now(conv_id, contact, content.to_vec(), true)?)
}

/// Fetch and process everything currently sitting in the mailbox `contact`
/// writes to us over: `RoutingIdAnnounce` protocol messages transition the
/// mailbox off the bootstrap address (`store::routing`, never gated); chat
/// content is released only if `contact` is `Verified` (`store::gate`,
/// silently skipped otherwise — the message was still consumed off the
/// wire, just not surfaced, exactly as a Pending contact's chat is
/// supposed to behave). Every processed entry is deleted from the
/// mailbox, per `docs/MESSAGE_SCHEMA.md` §7's "after successful decrypt"
/// convention — the ratchet step already committed for it either way.
/// Returns the newly received, released chat messages.
///
/// **Fetch address, and why it's not simply `contact.mailbox_id`:**
/// `contact.mailbox_id` is where *we write to them* (starts as
/// `bootstrap_mailbox_id(contact.fingerprint)`, their identity's inbox —
/// see `announce_routing_id`'s doc for why that has to stay stable from
/// our side too). What *they* write to *us* lands somewhere keyed by
/// *our* fingerprint instead: `bootstrap_mailbox_id(account's fp)` before
/// transition, or the shared symmetric routing-id-derived address once
/// `contact.peer_routing_id` is known (at which point it's the same value
/// as `contact.mailbox_id`, since that address is symmetric).
///
/// **Known limitation, not solved here**: before transition, every
/// not-yet-transitioned contact's incoming mail lands in this same one
/// `bootstrap_mailbox_id(account's fp)` inbox — this function handles the
/// single-contact case correctly (as proven by the test below, matching
/// `store/tests/routing_id_exchange.rs`'s scenario), but a real multi-
/// pending-contact inbox needs a demultiplexing strategy (e.g. attempting
/// decrypt against every Pending contact's ratchet) this crate doesn't
/// implement yet — flagged here rather than silently assumed away.
///
/// Returns a [`Received`] rather than just the released chat messages:
/// a caller (the Tauri poll loop) needs to know whether *anything* about
/// this conversation changed — a peer-requested wipe that auto-complied,
/// or one that only set `Contact::wipe_request_pending` — even when no
/// chat message arrived, so it knows to refetch.
pub async fn receive_pending(
    db: &Db,
    conn: &mut Connection,
    account: &Account,
    contact: &Contact,
) -> Result<Received> {
    let conv_id = conversation_id_for(account, contact);
    let mut ratchet = db.load_ratchet(conv_id)?.ok_or(Error::NoSession)?;
    // Captured once so every delete in this pass targets the address the
    // entries were actually fetched from, even if a `RoutingIdAnnounce`
    // processed partway through this same batch moves `contact.mailbox_id`
    // forward (that mutation affects only our *send* address, computed
    // fresh below regardless).
    let fetch_mailbox_id = if contact.peer_routing_id.is_some() {
        contact.mailbox_id.clone()
    } else {
        bootstrap_mailbox_id(account.identity.fingerprint().as_bytes()).to_vec()
    };

    conn.send(
        FrameTag::MailboxFetch,
        &MailboxFetch {
            mailbox_id: fetch_mailbox_id.clone(),
        },
    )
    .await?;
    let (_, entries): (_, MailboxEntries) = conn.recv().await?;

    let mut received = Vec::new();
    let mut wipe_activity = false;
    // Set when a `ConversationWipeRequest` this pass auto-complied with
    // included the session — the on-disk ratchet key is gone at that
    // point, and the trailing `db.save_ratchet` below (using the
    // still-live in-memory `ratchet`, needed to keep decrypting the rest
    // of this batch) must not resurrect it.
    let mut session_wiped = false;
    // `contact`'s verification state (used by `decrypt_gated`) doesn't
    // change mid-loop — only its `mailbox_id`, tracked separately above —
    // so gating against the caller's original `contact` for every entry
    // in this batch is correct. Wipe-policy decisions below use this same
    // stale-within-the-batch snapshot for the same reason.
    for entry in &entries.entries {
        let envelope = Envelope::decode(&entry.envelope)?;
        match decrypt_gated(&mut ratchet, contact, &envelope) {
            Ok((PAYLOAD_ROUTING_ID_ANNOUNCE, content)) => {
                let announce = RoutingIdAnnounce::decode(&content)?;
                db.record_peer_routing_id(&contact.fingerprint, announce.routing_id)?;
            }
            Ok((PAYLOAD_CHAT, content)) => {
                received.push(db.save_message_now(conv_id, contact, content, false)?);
            }
            Ok((PAYLOAD_CONVERSATION_WIPE_POLICY_ANNOUNCE, content)) => {
                let announce = ConversationWipePolicyAnnounce::decode(&content)?;
                db.record_peer_wipe_policy(
                    &contact.fingerprint,
                    announce.ask_before_delete,
                    announce.include_session,
                )?;
                wipe_activity = true;
            }
            Ok((PAYLOAD_CONVERSATION_WIPE_REQUEST, _content)) => {
                if contact.effective_wipe_ask_before_delete() {
                    let mut pending = contact.clone();
                    pending.wipe_request_pending = true;
                    db.save_contact(&pending)?;
                } else {
                    let include_session = contact.effective_wipe_include_session();
                    db.wipe_conversation(conv_id, include_session)?;
                    if include_session {
                        session_wiped = true;
                    }
                }
                wipe_activity = true;
            }
            Ok(_) => {} // other protocol payload types: consumed, nothing to surface yet
            Err(dratchet_store::Error::NotVerified) => {} // chat content, withheld while Pending
            Err(e) => return Err(e.into()),
        }

        conn.send(
            FrameTag::MailboxDelete,
            &MailboxDelete {
                mailbox_id: fetch_mailbox_id.clone(),
                entry_id: entry.entry_id.clone(),
            },
        )
        .await?;
        let (_, ack): (_, Ack) = conn.recv().await?;
        if !ack.ok {
            return Err(Error::NotAcknowledged);
        }
    }

    if !session_wiped {
        db.save_ratchet(conv_id, &ratchet)?;
    }
    Ok(Received {
        messages: received,
        wipe_activity,
    })
}

/// What [`receive_pending`] actually did on one call.
pub struct Received {
    /// Newly received, released chat messages — what a caller used to get
    /// directly before this type existed.
    pub messages: Vec<Message>,
    /// Something about this conversation changed that isn't reflected in
    /// `messages` — a wipe-policy announcement was recorded, or a wipe
    /// request either auto-complied or set `Contact::wipe_request_pending`.
    /// A caller that refetches UI state only when something changed (the
    /// Tauri poll loop) needs this, since none of those side effects show
    /// up as a returned message.
    pub wipe_activity: bool,
}

/// Send this side's fresh routing-id announce — the first step of Phase
/// 1.6.2's exchange (`store::routing`'s module doc). Ungated: it's
/// protocol machinery, not chat content.
///
/// **Always addressed at `bootstrap_mailbox_id(contact.fingerprint)`,
/// deliberately never `contact.mailbox_id`.** By the time this side calls
/// this (e.g. right after `receive_pending` has just processed the
/// peer's own announce), `record_peer_routing_id` may have *already*
/// transitioned `contact.mailbox_id` to the routing-id-derived address —
/// but the peer doesn't know that yet (they haven't received this
/// announce), so they're necessarily still polling their own identity's
/// bootstrap mailbox. Sending anywhere else would leave this announce
/// undiscoverable — the exact bug `store/tests/routing_id_exchange.rs`'s
/// hand-sequenced version avoids by hardcoding the bootstrap address at
/// its reply call site, reproduced here as a general rule instead of a
/// one-off.
pub async fn announce_routing_id(
    db: &Db,
    conn: &mut Connection,
    account: &Account,
    contact: &Contact,
    routing_id: Vec<u8>,
) -> Result<()> {
    let conv_id = conversation_id_for(account, contact);
    let mut ratchet = db.load_ratchet(conv_id)?.ok_or(Error::NoSession)?;

    let envelope = ratchet.encrypt_payload(
        PAYLOAD_ROUTING_ID_ANNOUNCE,
        &RoutingIdAnnounce { routing_id }.encode(),
    )?;

    conn.send(
        FrameTag::MailboxWrite,
        &MailboxWrite {
            mailbox_id: bootstrap_mailbox_id(&contact.fingerprint).to_vec(),
            envelope: envelope.encode(),
            ttl: 14 * 24 * 60 * 60,
        },
    )
    .await?;
    let (_, ack): (_, Ack) = conn.recv().await?;
    if !ack.ok {
        return Err(Error::NotAcknowledged);
    }

    db.save_ratchet(conv_id, &ratchet)?;
    Ok(())
}

/// `docs/ARCHITECTURE.md` §11.9a's per-conversation wipe policy: saves
/// this side's own preferences and announces them to the peer over
/// `contact.mailbox_id` — unlike `announce_routing_id`, this only ever
/// runs after a session is already established (called once after
/// pairing, and again whenever the user changes a preference in
/// Settings), so no bootstrap-mailbox special-casing is needed. Ungated:
/// protocol machinery, not chat content.
pub async fn announce_wipe_policy(
    db: &Db,
    conn: &mut Connection,
    account: &Account,
    contact: &Contact,
    ask_before_delete: bool,
    include_session: bool,
) -> Result<Contact> {
    let conv_id = conversation_id_for(account, contact);
    let mut ratchet = db.load_ratchet(conv_id)?.ok_or(Error::NoSession)?;

    let mut updated = contact.clone();
    updated.wipe_ask_before_delete = ask_before_delete;
    updated.wipe_include_session = include_session;
    db.save_contact(&updated)?;

    let envelope = ratchet.encrypt_payload(
        PAYLOAD_CONVERSATION_WIPE_POLICY_ANNOUNCE,
        &ConversationWipePolicyAnnounce {
            ask_before_delete,
            include_session,
        }
        .encode(),
    )?;
    conn.send(
        FrameTag::MailboxWrite,
        &MailboxWrite {
            mailbox_id: updated.mailbox_id.clone(),
            envelope: envelope.encode(),
            ttl: 14 * 24 * 60 * 60,
        },
    )
    .await?;
    let (_, ack): (_, Ack) = conn.recv().await?;
    if !ack.ok {
        return Err(Error::NotAcknowledged);
    }

    db.save_ratchet(conv_id, &ratchet)?;
    Ok(updated)
}

/// `docs/ARCHITECTURE.md` §11.9a's per-conversation wipe, the requesting
/// side: sends a `ConversationWipeRequest` to `contact` — the same shape
/// as Signal/WhatsApp's "delete for everyone," scoped to this one
/// conversation, never a general remote-wipe primitive (see the module
/// doc comparison with `quick_wipe`/`full_wipe`). The request is sent
/// *before* any local deletion, since it needs the still-live ratchet;
/// the local wipe only proceeds once the server has acked the write (the
/// same "acked = proceed" threshold `send_message` already uses — it
/// doesn't mean the peer has received it yet, just that delivery has been
/// queued, which is the normal store-and-forward behavior every mailbox
/// message already has). Returns how many local records were removed.
pub async fn request_conversation_wipe(
    db: &Db,
    conn: &mut Connection,
    account: &Account,
    contact: &Contact,
) -> Result<usize> {
    let conv_id = conversation_id_for(account, contact);
    let mut ratchet = db.load_ratchet(conv_id)?.ok_or(Error::NoSession)?;

    let envelope = ratchet.encrypt_payload(PAYLOAD_CONVERSATION_WIPE_REQUEST, &[])?;
    conn.send(
        FrameTag::MailboxWrite,
        &MailboxWrite {
            mailbox_id: contact.mailbox_id.clone(),
            envelope: envelope.encode(),
            ttl: 14 * 24 * 60 * 60,
        },
    )
    .await?;
    let (_, ack): (_, Ack) = conn.recv().await?;
    if !ack.ok {
        return Err(Error::NotAcknowledged);
    }

    db.save_ratchet(conv_id, &ratchet)?;
    let include_session = contact.effective_wipe_include_session();
    Ok(db.wipe_conversation(conv_id, include_session)?)
}

/// The receiving side of §11.9a's "ask before deleting" path: the peer's
/// wipe request already set `Contact::wipe_request_pending` (via
/// `receive_pending`); this actually performs the wipe now and clears the
/// flag. No network access needed. Returns how many records were removed.
pub fn confirm_pending_wipe(db: &Db, account: &Account, contact: &Contact) -> Result<usize> {
    let conv_id = conversation_id_for(account, contact);
    let include_session = contact.effective_wipe_include_session();
    let removed = db.wipe_conversation(conv_id, include_session)?;

    let mut updated = contact.clone();
    updated.wipe_request_pending = false;
    db.save_contact(&updated)?;
    Ok(removed)
}

/// The declining counterpart to [`confirm_pending_wipe`]: clears
/// `Contact::wipe_request_pending` without deleting anything. There is no
/// wire message telling the requester this happened — see the module
/// doc's "no delivery receipt" note.
pub fn decline_pending_wipe(db: &Db, contact: &Contact) -> Result<Contact> {
    let mut updated = contact.clone();
    updated.wipe_request_pending = false;
    db.save_contact(&updated)?;
    Ok(updated)
}

/// Confirm or reject a fingerprint match — §6.3/§6.4's verification
/// outcome. `matches` is whatever the UI's actual check decided (QR
/// comparison, pairing code, manual fingerprint read-aloud); this
/// function only ever records the result, never performs the comparison
/// itself.
pub fn record_verification_result(db: &Db, mut contact: Contact, matches: bool) -> Result<Contact> {
    if matches {
        contact.mark_verified();
    } else {
        contact.mark_mismatch();
    }
    db.save_contact(&contact)?;
    Ok(contact)
}

/// `docs/ARCHITECTURE.md` §11.9's **quick wipe** — a thin wrapper over
/// `Db::quick_wipe` (the real crypto-shred logic lives there), exposed at
/// this layer so a Tauri command — or a future `uniffi-rs` mobile binding
/// — never has to reach into `dratchet_store` directly, matching every
/// other function in this crate. Returns how many message/ratchet
/// records were erased, for the caller to show as confirmation.
///
/// The account and contact list are untouched, so the caller can just
/// re-list contacts/messages afterward (both come back empty of history,
/// contacts still present) rather than needing any special "post-wipe"
/// UI state.
pub fn quick_wipe(db: &Db) -> Result<usize> {
    Ok(db.quick_wipe()?)
}

/// `docs/ARCHITECTURE.md` §11.9's **full wipe**: destroys everything in
/// `db` — identity, contacts, message/session content, alike — via
/// `Db::full_wipe`, then removes the now-empty file at `path` outright.
///
/// The file removal is not what makes this a real crypto-shred (`db`'s
/// own `full_wipe` already destroyed every key that could ever read the
/// file again, before this function does anything filesystem-related at
/// all) — it's just hygiene, so a stale-but-empty file doesn't linger.
/// Still surfaced as a real error rather than swallowed, so a permissions
/// problem removing it is at least visible to the caller.
///
/// **Caller contract**: `db` must not be used for anything else once
/// this returns (or once this returns an error partway through — treat
/// either outcome the same way). This function intentionally does not,
/// and structurally cannot (`db: &Db` never gives it ownership), hand
/// back a fresh replacement `Db` with a freshly generated identity —
/// the UI layer is expected to restart the whole application process
/// afterward. That keeps "no db file at this path yet" meaning exactly
/// one thing to a startup path: a fresh identity gets generated, whether
/// this is a genuinely first launch or the launch right after a full
/// wipe — no separate case to special-case.
pub fn full_wipe(db: &Db, path: &std::path::Path) -> Result<()> {
    db.full_wipe()?;
    std::fs::remove_file(path)?;
    Ok(())
}
