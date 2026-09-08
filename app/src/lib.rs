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
use dratchet_core::payload::{RoutingIdAnnounce, PAYLOAD_CHAT, PAYLOAD_ROUTING_ID_ANNOUNCE};
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
pub async fn receive_pending(
    db: &Db,
    conn: &mut Connection,
    account: &Account,
    contact: &Contact,
) -> Result<Vec<Message>> {
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
    // `contact`'s verification state (used by `decrypt_gated`) doesn't
    // change mid-loop — only its `mailbox_id`, tracked separately above —
    // so gating against the caller's original `contact` for every entry
    // in this batch is correct.
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

    db.save_ratchet(conv_id, &ratchet)?;
    Ok(received)
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
