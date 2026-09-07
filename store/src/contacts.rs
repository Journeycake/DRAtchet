//! Contact records — one per peer, keyed by identity fingerprint. Storage
//! only in this sub-phase: `verification_state` is recorded here, but
//! *enforcing* §6.5's gate (no chat content while `Pending`) is Phase
//! 1.6.1's job, built on top of what this stores.

use serde::{Deserialize, Serialize};

use crate::db::{hex, Db};
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
    /// once both sides have exchanged `RoutingIdAnnounce` (Phase 1.6.2).
    #[serde(with = "serde_bytes")]
    pub mailbox_id: Vec<u8>,
    pub created_at: u64,
    /// Disappearing-message timer for this conversation, per §11.5: `None`
    /// (the default) keeps messages until manually deleted; `Some(secs)`
    /// makes every *new* message eligible for `Db::sweep_expired_messages`
    /// `secs` seconds after it's saved. Changing this only affects
    /// messages saved from then on — never retroactive.
    pub disappearing_timer_secs: Option<u64>,
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
        self.put_encrypted(&contact_key(&contact.fingerprint), &bytes)
    }

    pub fn load_contact(&self, fingerprint: &[u8]) -> Result<Option<Contact>> {
        match self.get_encrypted(&contact_key(fingerprint))? {
            Some(bytes) => Ok(Some(decode_contact(&bytes)?)),
            None => Ok(None),
        }
    }

    pub fn delete_contact(&self, fingerprint: &[u8]) -> Result<()> {
        self.delete(&contact_key(fingerprint))
    }

    pub fn list_contacts(&self) -> Result<Vec<Contact>> {
        self.keys_with_prefix(CONTACT_KEY_PREFIX)?
            .into_iter()
            .map(|key| {
                let bytes = self
                    .get_encrypted(&key)?
                    .ok_or(Error::MalformedRecord("contact key listed but not found"))?;
                decode_contact(&bytes)
            })
            .collect()
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
            disappearing_timer_secs: None,
        }
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
