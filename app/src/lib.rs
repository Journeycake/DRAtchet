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
//! **Starting a brand-new conversation purely from a `username#NNNN`
//! lookup** used to be a real, flagged gap here: the responder had no way
//! to discover an unsolicited first-contact attempt at all. Closed by
//! [`add_contact_by_username`] (initiator) and
//! [`receive_first_contact_attempts`] (responder), built around
//! `core::first_contact::FirstContactWire` — and deliberately *not* just
//! "fetch a bundle and land in Pending": a leaked or guessed username must
//! never be enough by itself to make an attempt appear on someone's
//! device, so the wire message is gated on a pairing code the recipient
//! generates and shares out of band *before* anything can reach them
//! (`docs/ARCHITECTURE.md` §6.4). Every other function below still
//! operates on a contact whose `RatchetState` already exists.

pub mod error;

pub use error::{Error, Result};

use dratchet_client::net::Connection;
use dratchet_core::account::Account;
use dratchet_core::conversation_id;
use dratchet_core::envelope::Envelope;
use dratchet_core::first_contact::FirstContactWire;
use dratchet_core::identity::fingerprint_of_public_key;
use dratchet_core::payload::{
    ChatContent, ConversationWipePolicyAnnounce, ConversationWipeRequestContent, DeliveryAck,
    FirstContactContent, PiggybackAck, ProfileAnnounce, RoutingIdAnnounce, PAYLOAD_CHAT,
    PAYLOAD_CONVERSATION_WIPE_POLICY_ANNOUNCE, PAYLOAD_CONVERSATION_WIPE_REQUEST,
    PAYLOAD_DELIVERY_ACK, PAYLOAD_FIRST_CONTACT, PAYLOAD_PROFILE_ANNOUNCE,
    PAYLOAD_ROUTING_ID_ANNOUNCE,
};
use dratchet_core::prekey::{OneTimePrekeyPublic, PrekeyBundle, SignedPrekeyPublic};
use dratchet_core::ratchet::{RatchetState, DEFAULT_MAX_SKIP};
use dratchet_core::x3dh::{self, bootstrap_mailbox_id};
use dratchet_server::protocol::{
    Ack, BundleResult, ErrorFrame, FetchBundle, FetchOwnPrekeyCount, FetchedBundleWire, FrameTag,
    MailboxDelete, MailboxEntries, MailboxFetch, MailboxWrite, OneTimePrekeyWire, OwnPrekeyCount,
    PrekeyBundleWire, PublishBundle,
};
use dratchet_store::{
    decrypt_gated, encrypt_gated, Contact, Db, Message, OwnProfile, PairingCode, VerificationState,
};
use rand_core::{OsRng, RngCore};
use x25519_dalek::PublicKey;

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

/// Marks every currently undelivered, locally-sent message across every
/// conversation as `uncertain` (`dratchet_store::Message::uncertain`'s
/// doc) — called once right after this device detects and recovers from
/// a connection interruption (the Tauri poll loop's reconnect-succeeded
/// path), since any send attempted during that gap has genuine reason to
/// be in doubt: it may never have reached the relay at all, as opposed to
/// simply "sent, ack not back yet." Ordinary continued chat in each
/// affected conversation resolves this without any further action here —
/// `send_message`'s piggybacked `PiggybackAck` on the next outgoing
/// message, or the peer's own next message's piggyback the other
/// direction, either confirms delivery (clearing `uncertain`) or the
/// conversation simply continues with the sender aware some prior sends
/// are unconfirmed. Returns how many messages were newly marked, summed
/// across every conversation.
pub fn mark_pending_sends_uncertain(db: &Db, account: &Account) -> Result<usize> {
    let mut total = 0;
    for contact in db.list_contacts()? {
        let conv_id = conversation_id_for(account, &contact);
        total += db.mark_undelivered_uncertain(conv_id)?;
    }
    Ok(total)
}

fn conversation_id_for(account: &Account, contact: &Contact) -> [u8; 16] {
    conversation_id(
        account.identity.fingerprint().as_bytes(),
        &contact.fingerprint,
    )
}

fn now_unix() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after the Unix epoch")
        .as_secs()
}

fn random_routing_id() -> Vec<u8> {
    let mut buf = [0u8; 32];
    OsRng.fill_bytes(&mut buf);
    buf.to_vec()
}

/// Convert a directory-fetched `FetchedBundleWire` into the real
/// `core::prekey::PrekeyBundle` X3DH needs — the same shape every test in
/// this workspace already hand-rolls (`app/tests/pairing_and_chat.rs`
/// among others), promoted here since [`add_contact_by_username`] is the
/// first *production* code path that needs it.
fn to_core_bundle(wire: &FetchedBundleWire) -> Result<PrekeyBundle> {
    let identity_dh_public: [u8; 32] =
        wire.identity_dh_public.as_slice().try_into().map_err(|_| {
            Error::Connection("fetched bundle: identity_dh_public must be 32 bytes".into())
        })?;
    let signed_prekey_public: [u8; 32] =
        wire.signed_prekey.as_slice().try_into().map_err(|_| {
            Error::Connection("fetched bundle: signed_prekey must be 32 bytes".into())
        })?;
    Ok(PrekeyBundle {
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
            .map(|otp| -> Result<OneTimePrekeyPublic> {
                let public: [u8; 32] = otp.key.as_slice().try_into().map_err(|_| {
                    Error::Connection("fetched bundle: one_time_prekey.key must be 32 bytes".into())
                })?;
                Ok(OneTimePrekeyPublic {
                    id: otp.id,
                    public: PublicKey::from(public),
                })
            })
            .transpose()?,
    })
}

/// Send a `PublishBundle` and interpret the real response — unlike every
/// other command this crate sends, a successful `PublishBundle` used to
/// get no response at all (`server/src/ws.rs` now sends an explicit
/// `Ack`, added specifically so this function can detect `UsernameTaken`
/// and retry with a fresh discriminator, per §6.1's "regenerated on
/// collision"). `Connection::recv`'s usual "decode the body as the type I
/// expect" doesn't work here since the response could be either an `Ack`
/// or an `Error` — this reads the raw frame and dispatches on its tag
/// instead.
async fn publish_bundle_wire(conn: &mut Connection, wire: PrekeyBundleWire) -> Result<()> {
    conn.send(FrameTag::PublishBundle, &PublishBundle { bundle: wire })
        .await?;
    let raw = conn.recv_raw().await?;
    let (tag, body) =
        dratchet_server::protocol::split_tag(&raw).map_err(|e| Error::Connection(e.to_string()))?;
    match tag {
        FrameTag::Ack => Ok(()),
        FrameTag::Error => {
            let err: ErrorFrame = dratchet_server::protocol::decode_body(body)
                .map_err(|e| Error::Connection(e.to_string()))?;
            if err.message == dratchet_server::error::Error::UsernameTaken.to_string() {
                Err(Error::UsernameTaken)
            } else {
                Err(Error::Connection(err.message))
            }
        }
        other => Err(Error::Connection(format!(
            "unexpected frame tag {other:?} from PublishBundle"
        ))),
    }
}

const ONE_TIME_PREKEY_BATCH: u32 = 10;
const DISCRIMINATOR_RETRY_ATTEMPTS: u32 = 5;

fn random_discriminator() -> u16 {
    (OsRng.next_u32() % 10_000) as u16
}

/// Shared publish loop behind [`publish_own_bundle`] and
/// [`reconcile_own_profile`]: generates a fresh one-time-prekey batch
/// once, then tries `username` under each discriminator `candidates`
/// yields in order, stopping at the first one the server accepts.
/// Whichever candidate wins is persisted as the new [`OwnProfile`].
async fn publish_under_candidates(
    db: &Db,
    conn: &mut Connection,
    account: &mut Account,
    username: &str,
    candidates: impl Iterator<Item = u16>,
) -> Result<OwnProfile> {
    let otp_publics = account.generate_one_time_prekeys(ONE_TIME_PREKEY_BATCH);
    let bundle = account.publish_bundle(false)?;
    let one_time_prekeys: Vec<OneTimePrekeyWire> = otp_publics
        .into_iter()
        .map(|otp| OneTimePrekeyWire {
            id: otp.id,
            key: otp.public.as_bytes().to_vec(),
        })
        .collect();

    let mut last_err = Error::UsernameTaken;
    for discriminator in candidates {
        let wire = PrekeyBundleWire {
            username: username.to_string(),
            discriminator,
            identity_key: bundle.identity_public_key.clone(),
            identity_dh_public: bundle.identity_dh_public.as_bytes().to_vec(),
            identity_dh_signature: bundle.identity_dh_signature.clone(),
            signed_prekey_id: bundle.signed_prekey.id,
            signed_prekey: bundle.signed_prekey.public.as_bytes().to_vec(),
            signed_prekey_sig: bundle.signed_prekey.signature.clone(),
            signed_prekey_expires_at: 0,
            one_time_prekeys: one_time_prekeys.clone(),
            registration_pow: Some(dratchet_server::abuse::solve_registration_pow(
                username,
                discriminator,
                &bundle.identity_public_key,
            )),
        };
        match publish_bundle_wire(conn, wire).await {
            Ok(()) => {
                db.save_account(account)?;
                let profile = OwnProfile {
                    username: username.to_string(),
                    discriminator,
                    signed_prekey_id: bundle.signed_prekey.id,
                };
                db.save_own_profile(&profile)?;
                return Ok(profile);
            }
            Err(Error::UsernameTaken) => {
                last_err = Error::UsernameTaken;
                continue;
            }
            Err(e) => return Err(e),
        }
    }
    Err(last_err)
}

/// Self-registration, `docs/ARCHITECTURE.md` §6.1: publish this device's
/// own prekey bundle under `desired_username`, picking a random 4-digit
/// discriminator and retrying with a fresh one on `Error::UsernameTaken`.
/// Persists both `account` (the freshly generated one-time prekeys' secret
/// halves need to survive for [`receive_first_contact_attempts`] to spend
/// later) and the resulting [`OwnProfile`].
pub async fn publish_own_bundle(
    db: &Db,
    conn: &mut Connection,
    account: &mut Account,
    desired_username: &str,
) -> Result<OwnProfile> {
    let candidates =
        std::iter::repeat_with(random_discriminator).take(DISCRIMINATOR_RETRY_ATTEMPTS as usize);
    publish_under_candidates(db, conn, account, desired_username, candidates).await
}

/// A rename is nothing more than re-publishing under a new username —
/// [`publish_own_bundle`] already handles the collision-retry and
/// persistence either way.
pub async fn rename_own_profile(
    db: &Db,
    conn: &mut Connection,
    account: &mut Account,
    new_username: &str,
) -> Result<OwnProfile> {
    publish_own_bundle(db, conn, account, new_username).await
}

/// What [`reconcile_own_profile`] found.
#[derive(Debug, Clone)]
pub enum ProfileReconciliation {
    /// No local [`OwnProfile`] exists yet — nothing to reconcile (a
    /// genuinely first-ever launch, before the user has registered).
    Unregistered,
    /// Reclaimed exactly the username *and* discriminator this device
    /// already believed it owned. The common case — nothing for a caller
    /// to surface.
    Unchanged(OwnProfile),
    /// The stored discriminator was no longer available under this
    /// username (someone else claimed it — realistically only possible
    /// after the directory server lost its in-memory state and forgot
    /// this device owned it) — a *different* discriminator was picked
    /// instead. A caller should tell the user, since their handle just
    /// changed without them asking, and should announce the new one to
    /// every already-Verified contact (`announce_profile`) so their
    /// existing conversations' peers find out too.
    DiscriminatorChanged { old: OwnProfile, new: OwnProfile },
}

/// Called once at startup (after authenticating, before any other use of
/// `account`/`conn`): if this device has ever registered, re-publish its
/// bundle — first trying to reclaim the *exact* username+discriminator
/// already stored locally, falling back to [`publish_under_candidates`]'s
/// usual random-discriminator retry only if that specific reclaim fails.
/// A plain [`publish_own_bundle`] call would skip straight to a random
/// discriminator and could silently "succeed" onto a different number
/// without anyone noticing — this exists specifically to detect that
/// case instead of hiding it.
///
/// The directory (`server/src/state.rs`'s `Inner`) is deliberately
/// in-memory only (`docs/SERVERS.md` §1.3/1.4) — a server restart forgets
/// every registration. Nothing here changes that; this only closes the
/// window during which a forgotten handle sits open for anyone else to
/// claim, by reclaiming it the moment this device reconnects rather than
/// waiting for the user to notice and manually re-register.
pub async fn reconcile_own_profile(
    db: &Db,
    conn: &mut Connection,
    account: &mut Account,
) -> Result<ProfileReconciliation> {
    let Some(existing) = db.load_own_profile()? else {
        return Ok(ProfileReconciliation::Unregistered);
    };

    let candidates = std::iter::once(existing.discriminator).chain(
        std::iter::repeat_with(random_discriminator).take(DISCRIMINATOR_RETRY_ATTEMPTS as usize),
    );
    let new = publish_under_candidates(db, conn, account, &existing.username, candidates).await?;

    if new.discriminator == existing.discriminator {
        Ok(ProfileReconciliation::Unchanged(new))
    } else {
        Ok(ProfileReconciliation::DiscriminatorChanged { old: existing, new })
    }
}

/// How many of this device's own one-time prekeys the directory still
/// has unconsumed, per `FetchOwnPrekeyCount` (`ARCHITECTURE.md` §3.4).
async fn own_prekey_count(conn: &mut Connection) -> Result<u32> {
    conn.send(FrameTag::FetchOwnPrekeyCount, &FetchOwnPrekeyCount {})
        .await?;
    let (_, count): (_, OwnPrekeyCount) = conn.recv().await?;
    Ok(count.remaining)
}

/// A fresh batch is this many prekeys (`publish_under_candidates`);
/// replenish once the published pool has drained to this fraction of
/// that, leaving a buffer before a `FetchBundle` ever actually finds it
/// empty (which degrades that handshake's forward secrecy by one DH term
/// rather than merely being a wasted round trip).
const PREKEY_REPLENISH_THRESHOLD: u32 = 3;

/// Call periodically (the Tauri poll loop does this on a slower cadence
/// than its normal message poll — querying and, when due, republishing
/// are both cheap, but there's no reason to do either every tick):
/// checks this device's remaining one-time-prekey pool via
/// [`own_prekey_count`] and, if it has drained to
/// [`PREKEY_REPLENISH_THRESHOLD`] or below, republishes a fresh full
/// batch under the exact username/discriminator already on record — the
/// same mechanism [`reconcile_own_profile`] uses to reclaim after a
/// restart, reused here to top up instead (and just as free of protocol
/// cost: `server/src/ws.rs`'s `publish_bundle` never requires proof-of-
/// work for a rotation/republish of an already-owned identity, only for
/// a brand-new registration). A no-op if this device has never
/// registered (`db.load_own_profile` returns `None`) or the pool isn't
/// low yet. Returns whether it actually republished — nothing here is
/// user-visible by itself, unlike `reconcile_own_profile`'s
/// `DiscriminatorChanged`, so a caller only needs this for logging.
pub async fn replenish_prekeys_if_low(
    db: &Db,
    conn: &mut Connection,
    account: &mut Account,
) -> Result<bool> {
    let Some(existing) = db.load_own_profile()? else {
        return Ok(false);
    };
    if own_prekey_count(conn).await? > PREKEY_REPLENISH_THRESHOLD {
        return Ok(false);
    }

    let candidates = std::iter::once(existing.discriminator).chain(
        std::iter::repeat_with(random_discriminator).take(DISCRIMINATOR_RETRY_ATTEMPTS as usize),
    );
    publish_under_candidates(db, conn, account, &existing.username, candidates).await?;
    Ok(true)
}

/// Send this side's current `username#NNNN` (§6.1's `ProfileAnnounce`,
/// `MESSAGE_SCHEMA.md`) to one already-Verified contact. Purely a
/// display-label update — see `ProfileAnnounce`'s doc for why this never
/// touches the conversation's ratchet. Callers broadcast this to every
/// Verified contact after [`reconcile_own_profile`] reports
/// `DiscriminatorChanged`, and after an ordinary user-initiated rename.
pub async fn announce_profile(
    db: &Db,
    conn: &mut Connection,
    account: &Account,
    contact: &Contact,
    own_profile: &OwnProfile,
) -> Result<()> {
    let conv_id = conversation_id_for(account, contact);
    let mut ratchet = db.load_ratchet(conv_id)?.ok_or(Error::NoSession)?;

    let envelope = ratchet.encrypt_payload(
        PAYLOAD_PROFILE_ANNOUNCE,
        &ProfileAnnounce {
            username: own_profile.username.clone(),
            discriminator: own_profile.discriminator,
        }
        .encode(),
    )?;
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
    Ok(())
}

/// Generate and persist a fresh pairing code for `docs/ARCHITECTURE.md`
/// §6.4's pairing-code-gated add-contact flow — display it in the UI to
/// be read out over an already-trusted channel (phone call, an existing
/// verified conversation, in person). Generating a new one invalidates
/// whatever was stored before, per §6.4: `Db::save_pairing_code` is a
/// singleton.
pub fn generate_pairing_code(db: &Db) -> Result<PairingCode> {
    let code = PairingCode::generate(vec![], now_unix());
    db.save_pairing_code(&code)?;
    Ok(code)
}

/// `docs/ARCHITECTURE.md` §6.4's pairing-code-gated add-contact — the
/// *initiator* side. Fetches `username#discriminator`'s bundle, runs
/// X3DH, and sends a `FirstContactWire` whose ratchet-encrypted content
/// carries `pairing_code` (the code the peer read out over an
/// already-trusted channel) plus this side's own `username#NNNN` (so the
/// peer's client can label the new contact without a directory
/// round-trip). The new contact is saved locally as already `Verified` —
/// the code exchange over a trusted side channel *is* this path's
/// authentication (matches §6.4's own documented limits: it authenticates
/// that whoever generated the code controls the account, no stronger than
/// the channel that carried it).
///
/// There is no reply to wait for (this crate's standing no-delivery-
/// receipt limitation — see [`decline_pending_wipe`]'s doc), so a wrong or
/// expired code produces no visible difference on this side either: the
/// peer's device just never surfaces anything, silently, by design (see
/// [`receive_first_contact_attempts`]).
pub async fn add_contact_by_username(
    db: &Db,
    conn: &mut Connection,
    account: &Account,
    own_profile: &OwnProfile,
    username: &str,
    discriminator: u16,
    pairing_code: &str,
) -> Result<Contact> {
    conn.send(
        FrameTag::FetchBundle,
        &FetchBundle {
            username: username.to_string(),
            discriminator,
        },
    )
    .await?;
    let (_, result): (_, BundleResult) = conn.recv().await?;
    let fetched = result.bundle.ok_or(Error::NoSuchAccount)?;

    let core_bundle = to_core_bundle(&fetched)?;
    let init = x3dh::initiate(
        account.identity_dh_secret(),
        account.identity_dh_public,
        &core_bundle,
    )?;

    let peer_fp = *fingerprint_of_public_key(&fetched.identity_key).as_bytes();
    let conv_id = conversation_id(account.identity.fingerprint().as_bytes(), &peer_fp);
    let mut ratchet = RatchetState::init_as_initiator(
        conv_id,
        init.root_key,
        core_bundle.signed_prekey.public,
        DEFAULT_MAX_SKIP,
    )?;

    let self_bundle = account.publish_bundle(false)?;
    let content = FirstContactContent {
        pairing_code: pairing_code.to_string(),
        username: own_profile.username.clone(),
        discriminator: own_profile.discriminator,
    }
    .encode();
    let envelope = ratchet.encrypt_payload(PAYLOAD_FIRST_CONTACT, &content)?;

    let wire = FirstContactWire {
        initiator_identity_key: self_bundle.identity_public_key,
        initiator_identity_dh_public: self_bundle.identity_dh_public.as_bytes().to_vec(),
        initiator_identity_dh_signature: self_bundle.identity_dh_signature,
        initiator_ephemeral_public: init.message.initiator_ephemeral_public.as_bytes().to_vec(),
        used_signed_prekey_id: init.message.used_signed_prekey_id,
        used_one_time_prekey_id: init.message.used_one_time_prekey_id,
        envelope: envelope.encode(),
    };

    conn.send(
        FrameTag::MailboxWrite,
        &MailboxWrite {
            mailbox_id: bootstrap_mailbox_id(&peer_fp).to_vec(),
            envelope: wire.encode(),
            ttl: 14 * 24 * 60 * 60,
        },
    )
    .await?;
    let (_, ack): (_, Ack) = conn.recv().await?;
    if !ack.ok {
        return Err(Error::NotAcknowledged);
    }

    let routing_id = random_routing_id();
    let contact = Contact {
        fingerprint: peer_fp.to_vec(),
        username: Some(fetched.username),
        discriminator: Some(fetched.discriminator),
        verification_state: VerificationState::Verified,
        mailbox_id: bootstrap_mailbox_id(&peer_fp).to_vec(),
        created_at: now_unix(),
        local_routing_id: routing_id.clone(),
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
    db.save_contact(&contact)?;
    db.save_ratchet(conv_id, &ratchet)?;

    announce_routing_id(db, conn, account, &contact, routing_id).await?;
    Ok(contact)
}

/// `docs/ARCHITECTURE.md` §6.4's pairing-code-gated add-contact — the
/// *responder* side. Scans the shared pre-transition inbox
/// (`bootstrap_mailbox_id(account's fp)` — the same one
/// [`receive_pending`]'s doc describes as shared across every
/// not-yet-transitioned contact) for entries that don't decode as an
/// ordinary `Envelope` — those are left alone for `receive_pending` to
/// process — and do decode as a `FirstContactWire`: verifies the
/// initiator's identity-binding signature, runs `x3dh::respond`, and
/// checks the enclosed pairing code against whatever this device
/// currently has stored (`Db::load_pairing_code`).
///
/// **On a match**: consumes the stored code (single-use), saves a new
/// already-`Verified` `Contact` + ratchet, announces this side's routing
/// id, and includes the new contact in the returned list.
///
/// **On anything else** — no code stored, wrong code, expired, attempts
/// exhausted, or a bad identity-binding signature — the mailbox entry is
/// still deleted (so it isn't reprocessed every poll), but nothing else
/// happens: no contact, no error, no reply to the sender. A leaked or
/// guessed username must never be enough by itself to make an attempt
/// appear here — that's the whole point of gating on the code rather than
/// the earlier "fetch a bundle, land in Pending" shape.
pub async fn receive_first_contact_attempts(
    db: &Db,
    conn: &mut Connection,
    account: &mut Account,
) -> Result<Vec<Contact>> {
    let own_fp = *account.identity.fingerprint().as_bytes();
    let inbox = bootstrap_mailbox_id(&own_fp).to_vec();

    conn.send(
        FrameTag::MailboxFetch,
        &MailboxFetch {
            mailbox_id: inbox.clone(),
        },
    )
    .await?;
    let (_, entries): (_, MailboxEntries) = conn.recv().await?;

    let mut new_contacts = Vec::new();
    let mut account_dirty = false;
    for entry in &entries.entries {
        // Ordinary ratchet envelopes (already-known contacts' traffic
        // sharing this same pre-transition inbox) decode successfully
        // here — leave those alone for `receive_pending` to handle.
        if Envelope::decode(&entry.envelope).is_ok() {
            continue;
        }
        let Ok(wire) = FirstContactWire::decode(&entry.envelope) else {
            continue;
        };

        if let Some(contact) = try_accept_first_contact(db, account, &wire, &mut account_dirty)? {
            let routing_id = contact.local_routing_id.clone();
            announce_routing_id(db, conn, account, &contact, routing_id).await?;
            new_contacts.push(contact);
        }

        conn.send(
            FrameTag::MailboxDelete,
            &MailboxDelete {
                mailbox_id: inbox.clone(),
                entry_id: entry.entry_id.clone(),
            },
        )
        .await?;
        let (_, ack): (_, Ack) = conn.recv().await?;
        if !ack.ok {
            return Err(Error::NotAcknowledged);
        }
    }

    if account_dirty {
        db.save_account(account)?;
    }
    Ok(new_contacts)
}

/// The actual accept/reject decision for one [`FirstContactWire`] —
/// factored out of [`receive_first_contact_attempts`] since that function
/// already has its hands full with the mailbox loop. Returns `Ok(None)`
/// for every rejection path (never an `Err`, since a malformed or
/// adversarial first-contact attempt must never abort the whole batch —
/// see the caller's `let Ok(...) = ... else { continue }` precedent one
/// level up for the same reasoning applied to decode failures).
fn try_accept_first_contact(
    db: &Db,
    account: &mut Account,
    wire: &FirstContactWire,
    account_dirty: &mut bool,
) -> Result<Option<Contact>> {
    if wire.verify_identity_binding().is_err() {
        return Ok(None);
    }
    let Ok(init_message) = wire.x3dh_init_message() else {
        return Ok(None);
    };

    // DRA-0023 (`docs/DELIVERY_FAILURE_FINDINGS.md`): peek, don't consume
    // yet. The pairing code that actually proves this attempt is genuine
    // lives *inside* the ratchet-encrypted envelope below, which can't be
    // decrypted without first deriving the root key from this secret — so
    // there's no way to check the code before using the secret. But
    // *using* it for the DH computation and *discarding it from local
    // storage forever* are different things: only the latter must wait
    // until the pairing-code check below actually succeeds, or literally
    // anyone (no code required, no rate limit applies to writing into an
    // already-existing bootstrap mailbox) could destroy this account's
    // entire locally-held one-time-prekey batch just by sending garbage
    // first-contact attempts naming every id in it — one-time-prekey ids
    // are small sequential integers (`Account::next_otp_id`), so guessing
    // them all needs no prior `FetchBundle` at all.
    let otp_id = init_message.used_one_time_prekey_id;
    let otp_secret_ref = otp_id.and_then(|id| account.peek_one_time_prekey_secret(id));
    if otp_id.is_some() && otp_secret_ref.is_none() {
        // Named an id we don't have (already consumed, or never existed) —
        // can't derive the same root key the initiator did.
        return Ok(None);
    }
    let root_key = x3dh::respond(
        account.identity_dh_secret(),
        account.signed_prekey_secret(),
        otp_secret_ref,
        &init_message,
    );

    let peer_fp = *fingerprint_of_public_key(&wire.initiator_identity_key).as_bytes();
    let conv_id = conversation_id(account.identity.fingerprint().as_bytes(), &peer_fp);
    let Ok(mut ratchet) = RatchetState::init_as_responder(
        conv_id,
        root_key,
        account.signed_prekey_secret().clone(),
        DEFAULT_MAX_SKIP,
    ) else {
        return Ok(None);
    };

    let Ok((PAYLOAD_FIRST_CONTACT, content)) =
        Envelope::decode(&wire.envelope).and_then(|env| ratchet.decrypt_payload(&env))
    else {
        return Ok(None);
    };
    let Ok(announced) = FirstContactContent::decode(&content) else {
        return Ok(None);
    };

    let Some(mut stored_code) = db.load_pairing_code()? else {
        return Ok(None);
    };
    let matched = stored_code.verify(&announced.pairing_code, &[], now_unix());
    db.save_pairing_code(&stored_code)?;
    if !matched {
        return Ok(None);
    }
    db.clear_pairing_code()?;

    // Only now, with a genuinely matching pairing code, actually discard
    // the one-time-prekey secret from local storage for good (DRA-0023).
    if let Some(id) = otp_id {
        account.take_one_time_prekey_secret(id);
        *account_dirty = true;
    }

    let contact = Contact {
        fingerprint: peer_fp.to_vec(),
        username: Some(announced.username),
        discriminator: Some(announced.discriminator),
        verification_state: VerificationState::Verified,
        mailbox_id: bootstrap_mailbox_id(&peer_fp).to_vec(),
        created_at: now_unix(),
        local_routing_id: random_routing_id(),
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
    db.save_contact(&contact)?;
    db.save_ratchet(conv_id, &ratchet)?;
    Ok(Some(contact))
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

    // TCP-style cumulative piggyback ack (`ARCHITECTURE.md` §4.6): ride
    // "everything I've received on your current chain so far" along on
    // this ordinary chat send, supplementary to the dedicated
    // `DeliveryAck` `receive_pending` already sends. `None` if nothing's
    // been received on the current receiving chain yet (most commonly,
    // this is the first message this side has ever sent).
    let piggyback_ack = ratchet
        .receiving_progress()
        .map(|(dh_pub, highest_n)| PiggybackAck { dh_pub, highest_n });
    let chat = ChatContent {
        text: content.to_vec(),
        piggyback_ack,
    };

    let envelope = encrypt_gated(&mut ratchet, contact, PAYLOAD_CHAT, &chat.encode())?;
    let send_n = envelope.n;
    let send_dh_pub = envelope.dh_pub.to_vec();

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
    Ok(db.save_message_now(
        conv_id,
        content.to_vec(),
        true,
        Some(send_n),
        Some(send_dh_pub),
    )?)
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
///
/// **Concurrency (DRA-0012, `docs/DELIVERY_FAILURE_FINDINGS.md`)**: two
/// overlapping calls for the same `(db, conversation)` pair used to be
/// able to race — each loading the ratchet at the same starting state,
/// each fetching (and independently processing) the same batch of
/// mailbox entries, and racing to `db.save_ratchet` at the end,
/// confirmed by `app/tests/concurrent_receive_pending_race.rs`: real
/// content duplication (each entry decrypted and stored twice), though
/// the ratchet itself was left self-consistent and usable afterward in
/// every trial, not permanently desynced. Previously this was purely
/// architectural — `poll_loop` (`ui/src-tauri/src/lib.rs`) happened to be
/// the sole call site and happened to hold `state.conn`'s mutex across
/// the whole call — not something this function's own signature
/// enforced. It now is: the `db.receive_lock(conv_id).lock().await`
/// below serializes every call for the same conversation regardless of
/// caller, so a second call site (a manual "sync now" command on its own
/// connection, a per-contact-parallel poll loop) can no longer violate
/// this silently. `save_message_now`'s `(conv_id, recv_dh_pub, recv_n)`
/// dedup (`store/src/messages.rs`) is a second, independent layer behind
/// this one — belt-and-suspenders against any future caller that
/// bypasses this lock (a second process against the same on-disk `Db`
/// file, for instance, which an in-process `tokio::sync::Mutex` can't
/// reach).
pub async fn receive_pending(
    db: &Db,
    conn: &mut Connection,
    account: &Account,
    contact: &Contact,
) -> Result<Received> {
    let conv_id = conversation_id_for(account, contact);
    let receive_lock = db.receive_lock(conv_id);
    let _receive_guard = receive_lock.lock().await;
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
    let mut delivered = Vec::new();
    let mut wipe_activity = false;
    let mut profile_changes = Vec::new();
    let mut skipped = 0usize;
    // Set when a `ConversationWipeRequest` this pass auto-complied with
    // included the session — the on-disk ratchet key is gone at that
    // point, and the trailing `db.save_ratchet` below (using the
    // still-live in-memory `ratchet`, needed to keep decrypting the rest
    // of this batch) must not resurrect it.
    let mut session_wiped = false;
    // `contact`'s verification state (used by `decrypt_gated`) doesn't
    // change mid-loop — only its `mailbox_id`, tracked separately above —
    // so gating against the caller's original `contact` for every entry
    // in this batch is correct. Wipe-policy decisions, by contrast,
    // *cannot* safely use this same stale-within-the-batch snapshot — a
    // `ConversationWipePolicyAnnounce` and the wipe request it's meant to
    // gate can land in the very same batch (a peer catching up after
    // being offline), so `apply_entry`'s wipe-request arm reloads
    // `contact` fresh from `db` itself rather than trusting this one.
    for entry in &entries.entries {
        // Set by a successfully-decrypted chat message below — the ratchet
        // header `n` it arrived with, still needed *after* this entry's
        // `MailboxDelete` below to send its `DeliveryAck` (`ARCHITECTURE.md`
        // §4.6). Sent only once the entry is confirmed deleted, not before:
        // sending it earlier and having the ack round trip itself fail
        // would abort this function before the delete ever ran, and a
        // still-undeleted entry gets refetched and reprocessed next time —
        // decrypting fine again (the ratchet's on-disk position hasn't
        // advanced past it either, since `db.save_ratchet` below hasn't run
        // yet) but re-saved as a second, duplicate `Message` record. Acking
        // only after the delete has already succeeded means a lost ack
        // costs nothing but the sender's delivered-indicator for this one
        // message — never a duplicate.
        let mut ack_after_delete: Option<(Vec<u8>, u32)> = None;

        match apply_entry(db, &mut ratchet, contact, conv_id, &entry.envelope) {
            Ok(EntryEffect::None) => {}
            Ok(EntryEffect::Message(message, dh_pub, acked_n, piggyback_delivered)) => {
                ack_after_delete = Some((dh_pub, acked_n));
                received.push(message);
                delivered.extend(piggyback_delivered);
            }
            Ok(EntryEffect::Delivered(message)) => delivered.push(message),
            Ok(EntryEffect::WipeActivity { session_wiped: sw }) => {
                wipe_activity = true;
                if sw {
                    session_wiped = true;
                }
            }
            Ok(EntryEffect::ProfileChange(notice)) => profile_changes.push(notice),
            Err(e) if is_per_entry_content_error(&e) => {
                // A property of *this one entry* — a corrupted/tampered
                // envelope, a message too far out of order for the
                // skipped-key cache, or (the case that motivated this)
                // this client's own not-yet-fetched message landing in
                // the shared pre-transition bootstrap mailbox, which is
                // never decryptable from the receiving side. Deleted like
                // any other processed entry below so it never wedges this
                // mailbox for every poll thereafter; everything else in
                // the batch still gets a chance.
                eprintln!(
                    "receive_pending: skipping an undecryptable/malformed mailbox entry: {e}"
                );
                skipped += 1;
            }
            // A local storage failure or invariant violation, not a
            // property of the incoming entry — abort rather than risk
            // silently losing or misprocessing whatever comes after it.
            Err(e) => return Err(e),
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

        // `ARCHITECTURE.md` §4.6: sent the moment a ratchet envelope
        // decrypts successfully, over the same mailbox path any other
        // message uses — no special-cased transport. Uses the same live
        // `ratchet` this whole batch already holds (not a fresh
        // `db.load_ratchet`), so it's just the next message in whatever
        // sending chain is currently active, persisted by the one
        // `db.save_ratchet` at the end of this function like everything
        // else this pass did to the ratchet.
        if let Some((acked_dh_pub, acked_n)) = ack_after_delete {
            let ack_content = DeliveryAck {
                conversation_id: conv_id.to_vec(),
                dh_pub: acked_dh_pub,
                acked_n,
            }
            .encode();
            let ack_envelope = ratchet.encrypt_payload(PAYLOAD_DELIVERY_ACK, &ack_content)?;
            conn.send(
                FrameTag::MailboxWrite,
                &MailboxWrite {
                    mailbox_id: contact.mailbox_id.clone(),
                    envelope: ack_envelope.encode(),
                    ttl: 14 * 24 * 60 * 60,
                },
            )
            .await?;
            let (_, ack): (_, Ack) = conn.recv().await?;
            if !ack.ok {
                return Err(Error::NotAcknowledged);
            }
        }
    }

    if !session_wiped {
        db.save_ratchet(conv_id, &ratchet)?;
    }
    Ok(Received {
        messages: received,
        delivered,
        wipe_activity,
        profile_changes,
        skipped,
    })
}

/// What processing one decrypted mailbox entry produced — [`receive_pending`]
/// folds this into its running accumulators, or (on `Err`) decides whether
/// to skip just this entry or abort the whole batch.
enum EntryEffect {
    None,
    /// A released chat message, the ratchet header `dh_pub`/`n` it
    /// arrived with (`receive_pending` needs those after this entry's
    /// `MailboxDelete` succeeds, to send back its `DeliveryAck`), and any
    /// of our own previously-sent messages this entry's `PiggybackAck`
    /// newly confirmed delivered (`Db::mark_messages_delivered_up_to`) —
    /// usually empty, non-empty whenever the sender's chat message
    /// carried a cumulative ack.
    Message(Message, Vec<u8>, u32, Vec<Message>),
    /// An incoming `DeliveryAck` matched one of our own previously-sent
    /// messages (`Db::mark_message_delivered`) — the now-delivered
    /// message, for a caller to react to (e.g. a UI checkmark).
    Delivered(Message),
    WipeActivity {
        session_wiped: bool,
    },
    ProfileChange(ProfileChangeNotice),
}

/// True for an error that's a property of *this one mailbox entry* —
/// corrupted/tampered ciphertext, a malformed envelope or decoded control
/// payload, a message too far out of order for the skipped-key cache, a
/// bad signature — as opposed to a local storage failure or an
/// inconsistent local invariant (`MalformedRecord`), which still aborts
/// the whole batch: continuing past *those* risks compounding a real
/// local problem rather than just dropping one bad piece of mail.
fn is_per_entry_content_error(e: &Error) -> bool {
    matches!(
        e,
        Error::Core(_) | Error::Store(dratchet_store::Error::Core(_))
    )
}

/// Decode + decrypt + dispatch one mailbox entry. Split out of
/// [`receive_pending`] so its caller can classify a failure (skip just
/// this entry vs. abort the batch) instead of the whole loop body living
/// inside a `match` arm's error path.
fn apply_entry(
    db: &Db,
    ratchet: &mut RatchetState,
    contact: &Contact,
    conv_id: [u8; 16],
    entry_envelope: &[u8],
) -> Result<EntryEffect> {
    let envelope = Envelope::decode(entry_envelope)?;
    match decrypt_gated(ratchet, contact, &envelope) {
        Ok((PAYLOAD_ROUTING_ID_ANNOUNCE, content)) => {
            let announce = RoutingIdAnnounce::decode(&content)?;
            db.record_peer_routing_id(&contact.fingerprint, announce.routing_id)?;
            Ok(EntryEffect::None)
        }
        Ok((PAYLOAD_CHAT, content)) => {
            let chat = ChatContent::decode(&content)?;
            // Cumulative piggyback ack, if the sender had anything to
            // report yet — resolves any of our own messages this client
            // may have marked `uncertain` (`Message::uncertain`'s doc)
            // even if their dedicated `DeliveryAck` never arrived.
            let piggyback_delivered = match &chat.piggyback_ack {
                Some(ack) => {
                    db.mark_messages_delivered_up_to(conv_id, &ack.dh_pub, ack.highest_n)?
                }
                None => Vec::new(),
            };
            // DRA-0012 (`docs/DELIVERY_FAILURE_FINDINGS.md`): idempotent on
            // `(recv_dh_pub, recv_n)` — the second, independent layer
            // behind `receive_pending`'s per-conversation lock. A
            // duplicate decrypt of the same mailbox entry (from a race
            // that slipped past the lock, or a crash-recovery reprocess
            // of a not-yet-deleted entry) returns the already-stored
            // message instead of inserting a second one.
            let recv_dh_pub = envelope.dh_pub.to_vec();
            let recv_n = envelope.n;
            let message = db.save_received_message_idempotent(
                conv_id,
                chat.text,
                recv_dh_pub.clone(),
                recv_n,
            )?;
            Ok(EntryEffect::Message(
                message,
                recv_dh_pub,
                recv_n,
                piggyback_delivered,
            ))
        }
        Ok((PAYLOAD_DELIVERY_ACK, content)) => {
            let ack = DeliveryAck::decode(&content)?;
            if ack.conversation_id != conv_id {
                return Err(dratchet_core::error::Error::MalformedPayload(
                    "DeliveryAck.conversation_id doesn't match the session it arrived on",
                )
                .into());
            }
            match db.mark_message_delivered(conv_id, &ack.dh_pub, ack.acked_n)? {
                Some(message) => Ok(EntryEffect::Delivered(message)),
                // Stale/duplicate ack, or one naming a (dh_pub, n) this
                // side never actually sent — not an error, just nothing
                // to do.
                None => Ok(EntryEffect::None),
            }
        }
        Ok((PAYLOAD_CONVERSATION_WIPE_POLICY_ANNOUNCE, content)) => {
            let announce = ConversationWipePolicyAnnounce::decode(&content)?;
            db.record_peer_wipe_policy(
                &contact.fingerprint,
                announce.ask_before_delete,
                announce.include_session,
            )?;
            Ok(EntryEffect::WipeActivity {
                session_wiped: false,
            })
        }
        Ok((PAYLOAD_CONVERSATION_WIPE_REQUEST, content)) => {
            // The requester's own `include_session` preference, carried in
            // the request itself since `docs/DELIVERY_FAILURE_FINDINGS.md`
            // finding #30 — folded into this side's effective decision
            // below (most-restrictive-wins) without depending on a prior
            // `ConversationWipePolicyAnnounce` having already landed.
            // Malformed content is per-entry-skippable like any other
            // decode failure here, not fatal to the whole batch.
            let requested = ConversationWipeRequestContent::decode(&content)?;
            // Reload from disk rather than trusting `contact`, the
            // snapshot `receive_pending` captured once before this whole
            // batch started. A `ConversationWipePolicyAnnounce` earlier
            // in this *same* batch already updated the persisted record
            // (the arm above, `record_peer_wipe_policy`) — the ask-
            // before-delete gate and the wipe boundary both need to see
            // that, not the pre-batch snapshot, or a peer who was simply
            // offline long enough to have an announce and its wipe
            // request land in one poll gets silently downgraded to the
            // old unscoped, unconfirmed behavior even though the
            // announce technically already arrived
            // (`docs/DELIVERY_FAILURE_FINDINGS.md`, the same-batch
            // staleness findings). Falls back to the passed-in `contact`
            // only in the pathological case it vanished entirely between
            // then and now.
            let current = db
                .load_contact(&contact.fingerprint)?
                .unwrap_or_else(|| contact.clone());
            // DRA-0021 (`docs/DELIVERY_FAILURE_FINDINGS.md`): unlike every
            // other arm here, a wipe request has a genuinely destructive
            // local effect (auto-comply deletes real message history
            // outright; even the ask-before-delete branch below arms a
            // confirmation prompt a user could be talked into approving).
            // §6.5 only ever gated *chat content*, on the theory that
            // everything else is inert "protocol machinery" — but this
            // payload isn't inert, so a session that isn't `Verified`
            // (including one explicitly reverted to `Mismatch`, §6.2/6.3's
            // hard-stop for a detected identity change) must never have it
            // take any local effect, exactly as `decrypt_gated` already
            // withholds chat content from the same untrusted session.
            if current.verification_state != VerificationState::Verified {
                return Ok(EntryEffect::None);
            }
            if current.effective_wipe_ask_before_delete() {
                // Not applied to this path: the requester's carried
                // preference isn't persisted anywhere between now and
                // `confirm_pending_wipe` running later, so an un-announced
                // `include_session` can still be missed here — a narrower
                // residual case than finding #30's (this one requires
                // *both* sides to have opted into ask-before-delete in the
                // first place, a much smaller population) left as a known
                // limitation rather than expanding this fix's scope.
                let mut pending = current.clone();
                pending.wipe_request_pending = true;
                db.save_contact(&pending)?;
                Ok(EntryEffect::WipeActivity {
                    session_wiped: false,
                })
            } else {
                let include_session =
                    current.effective_wipe_include_session() || requested.include_session;
                wipe_conversation_scoped(db, conv_id, &current, include_session)?;
                Ok(EntryEffect::WipeActivity {
                    session_wiped: include_session,
                })
            }
        }
        Ok((PAYLOAD_PROFILE_ANNOUNCE, content)) => {
            let announce = ProfileAnnounce::decode(&content)?;
            let old_handle = contact
                .username
                .as_deref()
                .map(|u| format!("{u}#{:04}", contact.discriminator.unwrap_or(0)));
            let (_, changed) = db.record_peer_profile(
                &contact.fingerprint,
                announce.username.clone(),
                announce.discriminator,
            )?;
            if changed {
                Ok(EntryEffect::ProfileChange(ProfileChangeNotice {
                    fingerprint: contact.fingerprint.clone(),
                    old_handle: old_handle.unwrap_or_default(),
                    new_handle: format!("{}#{:04}", announce.username, announce.discriminator),
                }))
            } else {
                Ok(EntryEffect::None)
            }
        }
        Ok(_) => Ok(EntryEffect::None), // other protocol payload types: consumed, nothing to surface yet
        Err(dratchet_store::Error::NotVerified) => Ok(EntryEffect::None), // chat content, withheld while Pending
        Err(e) => Err(e.into()),
    }
}

/// One contact's `username#NNNN` changing, surfaced by [`receive_pending`]
/// so a caller (the Tauri poll loop) can show the user something happened
/// rather than silently updating the sidebar handle underneath them.
pub struct ProfileChangeNotice {
    pub fingerprint: Vec<u8>,
    pub old_handle: String,
    pub new_handle: String,
}

/// What [`receive_pending`] actually did on one call.
pub struct Received {
    /// Newly received, released chat messages — what a caller used to get
    /// directly before this type existed.
    pub messages: Vec<Message>,
    /// Previously-sent messages a `DeliveryAck` arrived for this pass
    /// (`ARCHITECTURE.md` §4.6) — now `Message::delivered == true`. A
    /// caller (the Tauri poll loop) uses this to refresh a delivered
    /// indicator without needing to know which message ids to look for.
    pub delivered: Vec<Message>,
    /// Something about this conversation changed that isn't reflected in
    /// `messages` — a wipe-policy announcement was recorded, or a wipe
    /// request either auto-complied or set `Contact::wipe_request_pending`.
    /// A caller that refetches UI state only when something changed (the
    /// Tauri poll loop) needs this, since none of those side effects show
    /// up as a returned message.
    pub wipe_activity: bool,
    /// A `ProfileAnnounce` this pass processed that genuinely changed a
    /// contact's `username#NNNN` (never fires on first learning it, or on
    /// a re-announce of an unchanged value — see
    /// `Db::record_peer_profile`). Empty in the overwhelmingly common
    /// case; a caller surfaces each entry as a notice to the user.
    pub profile_changes: Vec<ProfileChangeNotice>,
    /// Mailbox entries this pass deleted without being able to process —
    /// a corrupted/tampered envelope, a message too far out of order for
    /// the skipped-key cache, or this client's own not-yet-fetched
    /// message landing in the shared pre-transition bootstrap mailbox
    /// (never decryptable from the receiving side). Not an error: the
    /// entry is gone either way, this just says how many were silently
    /// dropped rather than delivered, for a caller that wants to log or
    /// surface it.
    pub skipped: usize,
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

    // Stamp this side's own wipe boundary now that the announce is
    // actually acked — "how far this side had gotten the moment the peer
    // was told about the new policy," read back later by
    // `preview_conversation_wipe` to estimate how much of this side's
    // history the peer likely still has. Deliberately stamped after the
    // ack, not at the top of this function alongside the preference save:
    // if the send fails, no boundary should be recorded either.
    let (boundary_timestamp, boundary_sequence) = db.current_wipe_boundary();
    updated.wipe_boundary_timestamp = Some(boundary_timestamp);
    updated.wipe_boundary_sequence = Some(boundary_sequence);
    db.save_contact(&updated)?;

    Ok(updated)
}

/// A preview of what a [`request_conversation_wipe`] call would do right
/// now, without sending anything — read-only, no network access, safe to
/// call freely from the UI before the user commits to a wipe.
///
/// `peer_likely_keeps` is an estimate, never a guarantee: no mailbox
/// message in this protocol ever gets a delivery receipt, so this side
/// can only know its own `announce_wipe_policy` call was *sent*, not that
/// the peer actually received and processed it. `0` whenever this side
/// has never announced a wipe policy to this contact for this
/// conversation (`contact.wipe_boundary_timestamp.is_none()`) — with no
/// boundary recorded, a wipe request is unambiguous: everything goes.
pub struct WipePreview {
    /// How many messages `request_conversation_wipe` would remove from
    /// this side's own store — always everything, unconditionally.
    pub will_remove_locally: usize,
    /// How many of those same messages were saved before this side's own
    /// last-acked wipe-policy announce, and so likely still remain on the
    /// peer's device after they comply with the wipe request.
    pub peer_likely_keeps: usize,
}

pub fn preview_conversation_wipe(
    db: &Db,
    account: &Account,
    contact: &Contact,
) -> Result<WipePreview> {
    let conv_id = conversation_id_for(account, contact);
    let messages = db.list_messages(conv_id)?;
    let will_remove_locally = messages.len();
    let peer_likely_keeps = match (
        contact.wipe_boundary_timestamp,
        contact.wipe_boundary_sequence,
    ) {
        (Some(ts), seq) => {
            let boundary = (ts, seq.unwrap_or(0));
            messages
                .iter()
                .filter(|m| (m.timestamp, m.sequence) < boundary)
                .count()
        }
        (None, _) => 0,
    };
    Ok(WipePreview {
        will_remove_locally,
        peer_likely_keeps,
    })
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
///
/// Carries this side's own `include_session` preference in the request
/// content (`core::payload::ConversationWipeRequestContent`) — not just
/// the requester's own local wipe scope, but what the *recipient* needs
/// to correctly apply most-restrictive-wins without depending on a prior,
/// separately-landed `announce_wipe_policy` call having already reached
/// them (`docs/DELIVERY_FAILURE_FINDINGS.md` finding #30: without this,
/// an un-announced `include_session` preference desynced the two sides'
/// ratchets — one gone, one not — with no automatic recovery).
pub async fn request_conversation_wipe(
    db: &Db,
    conn: &mut Connection,
    account: &Account,
    contact: &Contact,
) -> Result<usize> {
    let conv_id = conversation_id_for(account, contact);
    let mut ratchet = db.load_ratchet(conv_id)?.ok_or(Error::NoSession)?;

    let include_session = contact.effective_wipe_include_session();
    let content = ConversationWipeRequestContent { include_session }.encode();
    let envelope = ratchet.encrypt_payload(PAYLOAD_CONVERSATION_WIPE_REQUEST, &content)?;
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
    Ok(db.wipe_conversation(conv_id, include_session)?)
}

/// The receiving side of §11.9a's "ask before deleting" path: the peer's
/// wipe request already set `Contact::wipe_request_pending` (via
/// `receive_pending`); this actually performs the wipe now and clears the
/// flag. No network access needed. Returns how many records were removed.
///
/// DRA-0020 (`docs/DELIVERY_FAILURE_FINDINGS.md`): reloads `contact`
/// fresh from `db` by fingerprint and refuses with
/// `Error::NoPendingWipeRequest` unless `wipe_request_pending` is
/// actually set on that fresh record — this used to trust the caller's
/// passed-in `contact` unconditionally, wiping real message history for
/// *any* contact this was called with, pending request or not. This is
/// the sole entry point for the destructive "ask before deleting" wipe;
/// nothing upstream of it (the Tauri command layer) re-validates this
/// invariant, so it belongs here, not only in the UI that happens to
/// gate the button on the same flag.
pub fn confirm_pending_wipe(db: &Db, account: &Account, contact: &Contact) -> Result<usize> {
    let fresh = db
        .load_contact(&contact.fingerprint)?
        .ok_or(Error::NoSuchAccount)?;
    if !fresh.wipe_request_pending {
        return Err(Error::NoPendingWipeRequest);
    }

    let conv_id = conversation_id_for(account, &fresh);
    let include_session = fresh.effective_wipe_include_session();
    let removed = wipe_conversation_scoped(db, conv_id, &fresh, include_session)?;

    let mut updated = fresh;
    updated.wipe_request_pending = false;
    db.save_contact(&updated)?;
    Ok(removed)
}

/// Complying with an *incoming* wipe request: scoped to
/// `contact.peer_wipe_boundary_timestamp`/`_sequence` when this side has
/// ever recorded one (`Db::record_peer_wipe_policy`, run whenever a
/// `ConversationWipePolicyAnnounce` from this peer was processed) — full,
/// unconditional `Db::wipe_conversation` otherwise, which is also exactly
/// today's behavior for a conversation where no policy was ever announced.
/// Shared by `apply_entry`'s auto-comply branch and `confirm_pending_wipe`'s
/// ask-before-delete branch so both read the same persisted boundary,
/// however long a pending confirmation sat unanswered.
fn wipe_conversation_scoped(
    db: &Db,
    conv_id: [u8; 16],
    contact: &Contact,
    include_session: bool,
) -> Result<usize> {
    match (
        contact.peer_wipe_boundary_timestamp,
        contact.peer_wipe_boundary_sequence,
    ) {
        (Some(ts), seq) => {
            Ok(db.wipe_conversation_since(conv_id, (ts, seq.unwrap_or(0)), include_session)?)
        }
        (None, _) => Ok(db.wipe_conversation(conv_id, include_session)?),
    }
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
