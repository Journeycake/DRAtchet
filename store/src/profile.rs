//! This device's own directory-facing profile — the `username#NNNN`
//! chosen at self-registration (`docs/ARCHITECTURE.md` §6.1) and the id
//! of the signed prekey most recently published under it. Distinct from
//! `Account` (the cryptographic identity, which has no username at all —
//! `username`/`discriminator` are purely wire-level addressing metadata,
//! chosen by whoever calls `PublishBundle`). Singleton, same shape as
//! `Db::save_account`/`load_account`.

use serde::{Deserialize, Serialize};

use crate::contacts::Contact;
use crate::db::{Db, Scope};
use crate::error::{Error, Result};

const OWN_PROFILE_KEY: &str = "own_profile";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnProfile {
    pub username: String,
    pub discriminator: u16,
    pub signed_prekey_id: u32,
}

impl Db {
    pub fn save_own_profile(&self, profile: &OwnProfile) -> Result<()> {
        let mut bytes = Vec::new();
        ciborium::into_writer(profile, &mut bytes)
            .expect("CBOR encoding of a well-formed struct cannot fail");
        self.put_encrypted(Scope::Identity, OWN_PROFILE_KEY, &bytes)
    }

    pub fn load_own_profile(&self) -> Result<Option<OwnProfile>> {
        match self.get_encrypted(Scope::Identity, OWN_PROFILE_KEY)? {
            Some(bytes) => Ok(Some(ciborium::from_reader(bytes.as_slice()).map_err(
                |_| Error::MalformedRecord("stored own profile is not valid CBOR for this shape"),
            )?)),
            None => Ok(None),
        }
    }

    /// Record a peer's just-arrived `ProfileAnnounce` — a rename or a
    /// post-restart reconciliation on *their* device, never anything that
    /// touches this conversation's ratchet (mirrors
    /// `routing::record_peer_routing_id`'s reload-mutate-save shape).
    /// Returns the updated `Contact` plus whether the handle actually
    /// changed (vs. the first time we ever learned it, or a duplicate
    /// re-announce of the same value) — a caller only wants to surface a
    /// notice for a genuine change, not every announce.
    pub fn record_peer_profile(
        &self,
        fingerprint: &[u8],
        username: String,
        discriminator: u16,
    ) -> Result<(Contact, bool)> {
        let mut contact = self
            .load_contact(fingerprint)?
            .ok_or(Error::MalformedRecord(
                "record_peer_profile: no such contact",
            ))?;

        let changed = contact.username.as_deref() != Some(username.as_str())
            || contact.discriminator != Some(discriminator);

        // DRA-0025 (`docs/DELIVERY_FAILURE_FINDINGS.md`): the same
        // ASCII-only floor DRA-0024 already enforces at directory
        // registration (`server::ws::publish_bundle`) — but that only
        // covers a *fresh registration*, not this peer-to-peer path. A
        // contact you already have (verified or not — this payload isn't
        // gated either) could rename themselves via `ProfileAnnounce` to
        // a Unicode homograph of a *different*, already-known contact's
        // handle (e.g. Cyrillic `а` standing in for Latin `a`) — a
        // distinct string, so DRA-0016's exact-match collision check
        // below never catches it, yet visually indistinguishable in the
        // UI. Declined the same way as a collision: no error, no batch
        // abort, this contact just keeps whatever it displayed before.
        if !dratchet_core::username::has_only_allowed_characters(&username) {
            tracing::warn!(
                fingerprint = %crate::db::hex(fingerprint),
                username,
                discriminator,
                "rejected a ProfileAnnounce with a non-ASCII or empty username",
            );
            return Ok((contact, false));
        }

        // DRA-0016 (`docs/DELIVERY_FAILURE_FINDINGS.md`): `ProfileAnnounce`
        // is protocol metadata, not chat content — `store::gate` never
        // gates it, and nothing here previously checked the announced
        // `username#NNNN` against every *other* locally-known contact.
        // Without this, any contact (verified or not — the gate doesn't
        // apply here) could announce a handle identical to a different,
        // already-known contact's, making two distinct fingerprints
        // display identically in the UI and inviting a user to type a
        // message into the impostor's thread believing it's the real
        // contact's. Declined exactly like an unrelated announce that
        // changes nothing — no error, no batch abort, just refused: the
        // real party (`existing_owner.fingerprint`) keeps that handle,
        // and `fingerprint` here keeps whatever it displayed before.
        let claimed_by_someone_else = self.list_contacts()?.iter().any(|existing_owner| {
            existing_owner.fingerprint != contact.fingerprint
                && existing_owner.username.as_deref() == Some(username.as_str())
                && existing_owner.discriminator == Some(discriminator)
        });
        if claimed_by_someone_else {
            tracing::warn!(
                fingerprint = %crate::db::hex(fingerprint),
                username,
                discriminator,
                "rejected a ProfileAnnounce claiming a handle another known contact already uses",
            );
            return Ok((contact, false));
        }

        // Only a genuine change *from an already-known handle* is worth a
        // caller-visible notice — the very first announce right after
        // pairing just confirms what was already known (e.g. from
        // `FirstContactContent`), not a reassignment.
        let previously_known = contact.username.is_some();

        if changed {
            contact.username = Some(username);
            contact.discriminator = Some(discriminator);
            self.save_contact(&contact)?;
        }
        Ok((contact, changed && previously_known))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;

    fn temp_db() -> Db {
        let dir = tempfile::tempdir().unwrap().keep();
        Db::create(dir.join("test.redb"), "pw").unwrap()
    }

    #[test]
    fn no_profile_before_registration() {
        let db = temp_db();
        assert!(db.load_own_profile().unwrap().is_none());
    }

    #[test]
    fn save_then_load_round_trips() {
        let db = temp_db();
        let profile = OwnProfile {
            username: "alice".into(),
            discriminator: 4821,
            signed_prekey_id: 1,
        };
        db.save_own_profile(&profile).unwrap();

        let loaded = db.load_own_profile().unwrap().unwrap();
        assert_eq!(loaded.username, "alice");
        assert_eq!(loaded.discriminator, 4821);
        assert_eq!(loaded.signed_prekey_id, 1);
    }

    #[test]
    fn saving_again_overwrites_the_previous_profile() {
        let db = temp_db();
        db.save_own_profile(&OwnProfile {
            username: "alice".into(),
            discriminator: 4821,
            signed_prekey_id: 1,
        })
        .unwrap();
        db.save_own_profile(&OwnProfile {
            username: "alice2".into(),
            discriminator: 4821,
            signed_prekey_id: 2,
        })
        .unwrap();

        let loaded = db.load_own_profile().unwrap().unwrap();
        assert_eq!(loaded.username, "alice2");
        assert_eq!(loaded.signed_prekey_id, 2);
    }

    fn sample_contact(username: Option<&str>, discriminator: Option<u16>) -> Contact {
        Contact {
            fingerprint: vec![1u8; 32],
            username: username.map(String::from),
            discriminator,
            verification_state: crate::contacts::VerificationState::Verified,
            mailbox_id: vec![0xABu8; 16],
            created_at: 0,
            local_routing_id: vec![0xCDu8; 32],
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

    #[test]
    fn record_peer_profile_updates_the_contact_and_reports_a_change() {
        let db = temp_db();
        let contact = sample_contact(Some("bob"), Some(1490));
        db.save_contact(&contact).unwrap();

        let (updated, changed) = db
            .record_peer_profile(&contact.fingerprint, "bob".into(), 9999)
            .unwrap();
        assert!(changed, "a genuine discriminator change must be reported");
        assert_eq!(updated.username.as_deref(), Some("bob"));
        assert_eq!(updated.discriminator, Some(9999));

        let reloaded = db.load_contact(&contact.fingerprint).unwrap().unwrap();
        assert_eq!(reloaded.discriminator, Some(9999));
    }

    #[test]
    fn record_peer_profile_learning_the_handle_for_the_first_time_is_not_a_change() {
        let db = temp_db();
        // A contact with no username yet — as if pairing hadn't yet
        // recorded one (shouldn't normally happen for the code-gated
        // add-contact flow, but the responder side of an in-person QR
        // pairing could plausibly land here).
        let contact = sample_contact(None, None);
        db.save_contact(&contact).unwrap();

        let (updated, changed) = db
            .record_peer_profile(&contact.fingerprint, "bob".into(), 1490)
            .unwrap();
        assert!(
            !changed,
            "learning a handle for the first time is not a reassignment"
        );
        assert_eq!(updated.username.as_deref(), Some("bob"));
    }

    #[test]
    fn record_peer_profile_is_a_no_op_when_nothing_changed() {
        let db = temp_db();
        let contact = sample_contact(Some("bob"), Some(1490));
        db.save_contact(&contact).unwrap();

        let (_, changed) = db
            .record_peer_profile(&contact.fingerprint, "bob".into(), 1490)
            .unwrap();
        assert!(!changed, "re-announcing the same handle is not a change");
    }

    /// DRA-0016 (penetration test, priority 3: poisoning/corrupting a
    /// conversation's identity). A distinct contact (a different
    /// fingerprint entirely — never verified, since `ProfileAnnounce`
    /// isn't gated by `store::gate` at all) announces the exact same
    /// `username#discriminator` an already-known, unrelated contact uses.
    /// Before the fix this silently succeeded, leaving two different
    /// fingerprints displaying identically in the UI.
    #[test]
    fn record_peer_profile_refuses_to_impersonate_an_already_known_contacts_handle() {
        let db = temp_db();

        let real_bob = sample_contact(Some("bob"), Some(1490));
        db.save_contact(&real_bob).unwrap();

        let mut impostor = sample_contact(None, None);
        impostor.fingerprint = vec![2u8; 32]; // a genuinely different identity
        db.save_contact(&impostor).unwrap();

        let (updated, changed) = db
            .record_peer_profile(&impostor.fingerprint, "bob".into(), 1490)
            .unwrap();
        assert!(
            !changed,
            "VULNERABILITY: a distinct contact was allowed to claim another known contact's \
             exact handle"
        );
        assert_eq!(
            updated.username, None,
            "the impostor's own contact record must not pick up the claimed handle"
        );

        // The real bob's handle must be completely untouched.
        let real_bob_reloaded = db.load_contact(&real_bob.fingerprint).unwrap().unwrap();
        assert_eq!(real_bob_reloaded.username.as_deref(), Some("bob"));
        assert_eq!(real_bob_reloaded.discriminator, Some(1490));
    }

    /// DRA-0025 (penetration test, priority 3/data obfuscation: a Unicode
    /// homograph impersonating an already-known contact via the
    /// peer-to-peer `ProfileAnnounce` path, distinct from DRA-0024's
    /// directory-registration fix). A different, already-known contact
    /// ("carol") exists; the contact under test announces a Cyrillic
    /// lookalike of "carol" — a distinct string, so DRA-0016's exact-match
    /// collision check alone would never catch it. Before this fix, the
    /// lookalike was accepted outright.
    #[test]
    fn record_peer_profile_refuses_a_unicode_homograph_of_an_already_known_contacts_handle() {
        let db = temp_db();

        let real_carol = sample_contact(Some("carol"), Some(4242));
        db.save_contact(&real_carol).unwrap();

        let mut impostor = sample_contact(None, None);
        impostor.fingerprint = vec![2u8; 32];
        db.save_contact(&impostor).unwrap();

        // Cyrillic "с" (U+0441) in place of Latin "c" -- a distinct
        // string, visually indistinguishable from "carol" in essentially
        // every font.
        let lookalike = "\u{0441}arol";
        assert_ne!(lookalike, "carol", "sanity check: distinct strings");

        let (updated, changed) = db
            .record_peer_profile(&impostor.fingerprint, lookalike.into(), 4242)
            .unwrap();
        assert!(
            !changed,
            "VULNERABILITY: a Unicode homograph of an already-known contact's handle was \
             accepted"
        );
        assert_eq!(
            updated.username, None,
            "the impostor's own contact record must not pick up the lookalike handle"
        );

        let real_carol_reloaded = db.load_contact(&real_carol.fingerprint).unwrap().unwrap();
        assert_eq!(real_carol_reloaded.username.as_deref(), Some("carol"));
    }

    /// The fix must not block a genuine, non-colliding rename — only an
    /// announce that collides with a *different* contact's current
    /// handle.
    #[test]
    fn record_peer_profile_still_allows_a_genuine_non_colliding_rename() {
        let db = temp_db();

        let other = sample_contact(Some("carol"), Some(4242));
        db.save_contact(&other).unwrap();

        let mut renaming = sample_contact(Some("bob"), Some(1490));
        renaming.fingerprint = vec![2u8; 32];
        db.save_contact(&renaming).unwrap();

        let (updated, changed) = db
            .record_peer_profile(&renaming.fingerprint, "bob".into(), 9999)
            .unwrap();
        assert!(
            changed,
            "a genuine rename to an unclaimed handle must go through"
        );
        assert_eq!(updated.discriminator, Some(9999));
    }
}
