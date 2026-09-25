//! Contact records — one per peer, keyed by identity fingerprint. Storage
//! only in this sub-phase: `verification_state` is recorded here, but
//! *enforcing* §6.5's gate (no chat content while `Pending`) is Phase
//! 1.6.1's job, built on top of what this stores.

use serde::{Deserialize, Serialize};

use crate::db::{hex, Db, Scope};
use crate::error::{Error, Result};

/// A contact's progress through `docs/ARCHITECTURE.md` §6.2's mandatory
/// verification gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationState {
    /// A session exists (X3DH has run), but the fingerprint hasn't been
    /// confirmed through §6.3 (QR) or §6.4 (pairing code) yet. Not usable
    /// for application messages.
    Pending,
    /// Fingerprint confirmed — usable for application messages.
    Verified,
    /// A confirmed match reverted — either the confirmation itself failed
    /// (§6.3's "mismatch is a hard stop") or a previously-Verified
    /// contact's identity key later changed (§6.2). Never silently
    /// re-promoted to Verified; requires the user to re-verify.
    Mismatch,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    #[serde(with = "serde_bytes")]
    pub fingerprint: Vec<u8>,
    pub username: Option<String>,
    pub discriminator: Option<u16>,
    pub verification_state: VerificationState,
    /// The Tier 1 mailbox this conversation currently addresses — starts as
    /// `bootstrap_mailbox_id` and transitions to the routing-id-derived one
    /// once both sides have exchanged `RoutingIdAnnounce` (Phase 1.6.2, see
    /// `crate::routing`).
    #[serde(with = "serde_bytes")]
    pub mailbox_id: Vec<u8>,
    pub created_at: u64,
    /// This side's own fresh routing id for this conversation — generated
    /// once, at contact creation, and announced to the peer immediately
    /// (`crate::routing`).
    #[serde(with = "serde_bytes")]
    pub local_routing_id: Vec<u8>,
    /// The peer's routing id, once their `RoutingIdAnnounce` has arrived.
    /// `None` until then — `mailbox_id` stays on `bootstrap_mailbox_id`
    /// the whole time.
    #[serde(with = "serde_bytes")]
    pub peer_routing_id: Option<Vec<u8>>,
    /// This side's own preference, per `crate::wipe_policy` /
    /// `docs/ARCHITECTURE.md` §11.9a: ask for local confirmation before
    /// complying with an incoming per-conversation wipe request, rather
    /// than deleting immediately. Default `false` — fail toward the
    /// calmer outcome.
    pub wipe_ask_before_delete: bool,
    /// The peer's last-announced value of the same preference. `None`
    /// until a `ConversationWipePolicyAnnounce` has arrived.
    pub peer_wipe_ask_before_delete: Option<bool>,
    /// This side's own preference: also destroy the conversation's
    /// ratchet/session state (not just message history) when complying
    /// with a wipe request. Default `false`.
    pub wipe_include_session: bool,
    /// The peer's last-announced value of the same preference.
    pub peer_wipe_include_session: Option<bool>,
    /// The peer has requested a wipe of this conversation and the
    /// effective `wipe_ask_before_delete` policy withheld it pending
    /// local confirmation (`dratchet_app::confirm_pending_wipe`/
    /// `decline_pending_wipe`).
    pub wipe_request_pending: bool,
    /// This side's own local "wipe boundary" — the `(timestamp, sequence)`
    /// this side had reached (`crate::messages`' own tie-break pair) the
    /// moment it last successfully *sent* a `ConversationWipePolicyAnnounce`
    /// to this contact (`dratchet_app::announce_wipe_policy`). Used only
    /// locally, to estimate — never guarantee, since no mailbox message
    /// ever gets a delivery receipt — how much of this side's own history
    /// likely still survives on the peer's device before a wipe request is
    /// sent (`dratchet_app::preview_conversation_wipe`). `#[serde(default)]`
    /// so an already-persisted `Contact` predating this field decodes as
    /// `None` (no boundary ever recorded) rather than failing to decode.
    #[serde(default)]
    pub wipe_boundary_timestamp: Option<u64>,
    #[serde(default)]
    pub wipe_boundary_sequence: Option<u64>,
    /// The mirror image, this side's record of the *peer's* boundary:
    /// the `(timestamp, sequence)` this side had reached the moment it
    /// *processed* an incoming `ConversationWipePolicyAnnounce` from this
    /// peer (`Db::record_peer_wipe_policy`). `None` until the first such
    /// announcement arrives. This is what actually gates this side's own
    /// compliance with an incoming wipe request from this peer
    /// (`Db::wipe_conversation_since`) — everything already stored before
    /// this moment is protected; everything saved from this moment
    /// forward is in scope. A fresh announcement overwrites it — last one
    /// wins, no history kept.
    #[serde(default)]
    pub peer_wipe_boundary_timestamp: Option<u64>,
    #[serde(default)]
    pub peer_wipe_boundary_sequence: Option<u64>,
}

fn contact_key(fingerprint: &[u8]) -> String {
    format!("contact:{}", hex(fingerprint))
}

const CONTACT_KEY_PREFIX: &str = "contact:";

impl Db {
    pub fn save_contact(&self, contact: &Contact) -> Result<()> {
        let mut bytes = Vec::new();
        ciborium::into_writer(contact, &mut bytes)
            .expect("CBOR encoding of a well-formed struct cannot fail");
        self.put_encrypted(Scope::Contacts, &contact_key(&contact.fingerprint), &bytes)
    }

    pub fn load_contact(&self, fingerprint: &[u8]) -> Result<Option<Contact>> {
        match self.get_encrypted(Scope::Contacts, &contact_key(fingerprint))? {
            Some(bytes) => Ok(Some(decode_contact(&bytes)?)),
            None => Ok(None),
        }
    }

    pub fn delete_contact(&self, fingerprint: &[u8]) -> Result<()> {
        self.delete(&contact_key(fingerprint))
    }

    /// DRA-0051 (`docs/DELIVERY_FAILURE_FINDINGS.md`): a record that
    /// cannot be read is *skipped*, not fatal -- the same fix DRA-0048
    /// applied to `messages::list_messages`, for the same reason. This
    /// used to `collect::<Result<Vec<_>>>()` through `?`, so one
    /// unreadable contact took the whole list with it. Losing one
    /// damaged contact is strictly better than losing all of them, and
    /// an attacker able to write the file could have deleted that record
    /// outright anyway. The skip is counted and logged (never with
    /// content) so genuine corruption stays visible.
    pub fn list_contacts(&self) -> Result<Vec<Contact>> {
        let mut contacts = Vec::new();
        let mut unreadable = 0usize;
        for key in self.keys_with_prefix(CONTACT_KEY_PREFIX)? {
            match self.get_encrypted(Scope::Contacts, &key) {
                Ok(Some(bytes)) => match decode_contact(&bytes) {
                    Ok(contact) => contacts.push(contact),
                    Err(_) => unreadable += 1,
                },
                Ok(None) | Err(_) => unreadable += 1,
            }
        }
        if unreadable > 0 {
            tracing::warn!(
                unreadable,
                "skipped unreadable contact records while listing contacts — possible \
                 tampering or corruption of the local database",
            );
        }
        Ok(contacts)
    }
}

fn decode_contact(bytes: &[u8]) -> Result<Contact> {
    ciborium::from_reader(bytes)
        .map_err(|_| Error::MalformedRecord("stored contact is not valid CBOR for this shape"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;

    fn temp_db() -> Db {
        let dir = tempfile::tempdir().unwrap().keep();
        Db::create(dir.join("test.redb"), "pw").unwrap()
    }

    fn sample_contact(fingerprint: u8) -> Contact {
        Contact {
            fingerprint: vec![fingerprint; 32],
            username: Some("alice".to_string()),
            discriminator: Some(1234),
            verification_state: VerificationState::Pending,
            mailbox_id: vec![0xAB; 16],
            created_at: 1_700_000_000,
            local_routing_id: vec![0xCD; 32],
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
        }
    }

    /// Penetration-test finding DRA-0051: same shape as DRA-0048
    /// (`docs/DELIVERY_FAILURE_FINDINGS.md`), for the contact list rather
    /// than a conversation's messages.
    ///
    /// `list_contacts` decoded every record with `?` inside a
    /// `.collect::<Result<Vec<_>>>()`, so one record that failed to
    /// decrypt short-circuited the whole collection -- losing every
    /// other saved contact along with the damaged one. Since DRA-0041
    /// bound each record's own key as AEAD associated data, a relocated
    /// or rolled-back record fails its AEAD check outright rather than
    /// decrypting into the wrong place, so planting one junk contact
    /// record denies the owner their entire contact list -- every
    /// conversation, every verification state -- needing no key and no
    /// plaintext, just write access to the `.redb` file.
    #[test]
    fn one_unreadable_contact_does_not_deny_the_whole_contact_list() {
        let db = temp_db();

        let keep_one = sample_contact(1);
        let planted = sample_contact(2);
        let keep_two = sample_contact(3);
        db.save_contact(&keep_one).unwrap();
        db.save_contact(&planted).unwrap();
        db.save_contact(&keep_two).unwrap();
        assert_eq!(db.list_contacts().unwrap().len(), 3);

        // An attacker with the database file overwrites one contact
        // record's bytes with something that cannot decrypt. No key, no
        // plaintext, no ability to read anything -- just a write.
        let victim_key = contact_key(&planted.fingerprint);
        {
            let write_txn = db.database.begin_write().unwrap();
            {
                let mut table = write_txn.open_table(crate::db::RECORDS).unwrap();
                table.insert(victim_key.as_str(), &b"garbage"[..]).unwrap();
            }
            write_txn.commit().unwrap();
        }

        let surviving = db.list_contacts().expect(
            "VULNERABILITY: a single unreadable contact record makes the entire contact list \
             unreadable -- anyone able to write one junk record into the database file can deny \
             the owner access to every saved contact without decrypting any of them",
        );

        let mut fingerprints: Vec<u8> = surviving.iter().map(|c| c.fingerprint[0]).collect();
        fingerprints.sort();
        assert_eq!(
            fingerprints,
            vec![1, 3],
            "every still-readable contact must survive; only the damaged one is lost"
        );
    }

    #[test]
    fn save_then_load_round_trips() {
        let db = temp_db();
        let contact = sample_contact(1);
        db.save_contact(&contact).unwrap();

        let loaded = db.load_contact(&contact.fingerprint).unwrap().unwrap();
        assert_eq!(loaded.fingerprint, contact.fingerprint);
        assert_eq!(loaded.username, contact.username);
        assert_eq!(loaded.verification_state, VerificationState::Pending);
        assert_eq!(loaded.mailbox_id, contact.mailbox_id);
    }

    #[test]
    fn missing_contact_is_none_not_an_error() {
        let db = temp_db();
        assert!(db.load_contact(&[9u8; 32]).unwrap().is_none());
    }

    #[test]
    fn list_contacts_returns_every_saved_contact_and_nothing_else() {
        let db = temp_db();
        db.save_contact(&sample_contact(1)).unwrap();
        db.save_contact(&sample_contact(2)).unwrap();
        db.save_contact(&sample_contact(3)).unwrap();

        let mut fingerprints: Vec<u8> = db
            .list_contacts()
            .unwrap()
            .into_iter()
            .map(|c| c.fingerprint[0])
            .collect();
        fingerprints.sort();
        assert_eq!(fingerprints, vec![1, 2, 3]);
    }

    #[test]
    fn updating_verification_state_persists() {
        let db = temp_db();
        let mut contact = sample_contact(1);
        db.save_contact(&contact).unwrap();

        contact.verification_state = VerificationState::Verified;
        db.save_contact(&contact).unwrap();

        let loaded = db.load_contact(&contact.fingerprint).unwrap().unwrap();
        assert_eq!(loaded.verification_state, VerificationState::Verified);
    }

    #[test]
    fn delete_contact_removes_it() {
        let db = temp_db();
        let contact = sample_contact(1);
        db.save_contact(&contact).unwrap();
        db.delete_contact(&contact.fingerprint).unwrap();
        assert!(db.load_contact(&contact.fingerprint).unwrap().is_none());
    }
}
