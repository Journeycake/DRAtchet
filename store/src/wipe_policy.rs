//! Per-conversation wipe ("delete for everyone") — `docs/ARCHITECTURE.md`
//! §11.9a, `docs/MESSAGE_SCHEMA.md` §10. Distinct from `Db::quick_wipe`/
//! `full_wipe` (§11.9's device-seizure duress response, which crypto-
//! shreds *everything*): this is a bilateral, per-conversation action —
//! each side announces its own preferences for how an incoming wipe
//! request gets handled, and both compute the same *effective* policy
//! independently from (own preference, last-announced peer preference),
//! the same shape `store::gate`'s caller (`RecoveryProfileAnnounce`)
//! already established. `wipe_conversation` itself is a plain delete —
//! the same guarantee `delete_message`/`delete_contact` already provide,
//! not a crypto-shred; that stronger guarantee is reserved for §11.9's
//! device-seizure threat model, not ordinary per-conversation
//! housekeeping.

use std::sync::atomic::Ordering;

use crate::contacts::Contact;
use crate::db::Db;
use crate::error::Result;
use crate::messages::{message_key_prefix, now_unix};

impl Contact {
    /// Effective "ask before deleting" policy for this conversation:
    /// **unanimous** — both sides must prefer it, otherwise the default
    /// is delete-on-receipt. Deliberately the opposite merge direction
    /// from `docs/ARCHITECTURE.md` §7.2's recovery-profile min-merge —
    /// see `docs/MESSAGE_SCHEMA.md` §10 for why: requiring both sides to
    /// opt in avoids either side unilaterally blocking the other's
    /// ability to actually clear a conversation they both share.
    pub fn effective_wipe_ask_before_delete(&self) -> bool {
        self.wipe_ask_before_delete && self.peer_wipe_ask_before_delete.unwrap_or(false)
    }

    /// Effective "include session" scope for this conversation's wipe:
    /// either side asking for the fuller wipe (ratchet/session state, not
    /// just messages) gets the fuller wipe — the conventional most-
    /// restrictive-wins shape.
    pub fn effective_wipe_include_session(&self) -> bool {
        self.wipe_include_session || self.peer_wipe_include_session.unwrap_or(false)
    }
}

impl Db {
    /// This side's current `(timestamp, sequence)` position in
    /// `crate::messages`' own tie-break ordering — "the boundary a message
    /// saved right now would get." Exposed so callers outside this crate
    /// (`dratchet_app::announce_wipe_policy`) can stamp their own
    /// `Contact::wipe_boundary_timestamp`/`_sequence` without reaching into
    /// `Db::message_sequence`, which stays `pub(crate)`.
    pub fn current_wipe_boundary(&self) -> (u64, u64) {
        (now_unix(), self.message_sequence.load(Ordering::Relaxed))
    }

    /// Record the peer's just-arrived wipe-policy announcement —
    /// reload-mutate-save, mirroring `routing::record_peer_routing_id`'s
    /// shape exactly. Idempotent-safe: repeating the same announcement is
    /// a harmless no-op write.
    ///
    /// Also stamps `peer_wipe_boundary_timestamp`/`_sequence` to *this
    /// side's own* current `(now_unix(), message_sequence)` — the moment
    /// this side actually processed the announcement, not whenever the
    /// peer happened to send it. This is what later gates this side's own
    /// compliance with an incoming wipe request from that peer
    /// (`wipe_conversation_since`): everything already stored before this
    /// instant is protected; everything saved from this instant forward
    /// is in scope. A fresh announcement always overwrites it — last one
    /// wins, no history kept.
    pub fn record_peer_wipe_policy(
        &self,
        fingerprint: &[u8],
        ask_before_delete: bool,
        include_session: bool,
    ) -> Result<Contact> {
        let mut contact =
            self.load_contact(fingerprint)?
                .ok_or(crate::error::Error::MalformedRecord(
                    "record_peer_wipe_policy: no such contact",
                ))?;
        contact.peer_wipe_ask_before_delete = Some(ask_before_delete);
        contact.peer_wipe_include_session = Some(include_session);
        contact.peer_wipe_boundary_timestamp = Some(now_unix());
        contact.peer_wipe_boundary_sequence = Some(self.message_sequence.load(Ordering::Relaxed));
        self.save_contact(&contact)?;
        Ok(contact)
    }

    /// Delete every message stored for `conversation_id`, and — if
    /// `include_session` — the conversation's ratchet/session state too.
    /// Plain deletion (see module doc for why this isn't a crypto-shred).
    /// Returns how many records were removed.
    pub fn wipe_conversation(
        &self,
        conversation_id: [u8; 16],
        include_session: bool,
    ) -> Result<usize> {
        let mut removed = 0;
        for key in self.keys_with_prefix(&message_key_prefix(conversation_id))? {
            self.delete(&key)?;
            removed += 1;
        }
        if include_session {
            let key = Db::ratchet_key(conversation_id);
            if self
                .get_encrypted(crate::db::Scope::Content, &key)?
                .is_some()
            {
                self.delete(&key)?;
                removed += 1;
            }
        }
        Ok(removed)
    }

    /// Like `wipe_conversation`, but only removes messages at or after
    /// `boundary` — `(timestamp, sequence)`, the same tie-break pair
    /// `list_messages` already sorts by. Messages strictly before the
    /// boundary are left untouched. `include_session`, if true, still
    /// removes the ratchet/session state unconditionally — session state
    /// is a single blob, not a timeline, so "since a boundary" has no
    /// meaning for it. Returns how many messages (and, if applicable, the
    /// ratchet) were removed.
    pub fn wipe_conversation_since(
        &self,
        conversation_id: [u8; 16],
        boundary: (u64, u64),
        include_session: bool,
    ) -> Result<usize> {
        let mut removed = 0;
        for message in self.list_messages(conversation_id)? {
            if (message.timestamp, message.sequence) >= boundary {
                self.delete_message(conversation_id, &message.id)?;
                removed += 1;
            }
        }
        if include_session {
            let key = Db::ratchet_key(conversation_id);
            if self
                .get_encrypted(crate::db::Scope::Content, &key)?
                .is_some()
            {
                self.delete(&key)?;
                removed += 1;
            }
        }
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contacts::VerificationState;
    use crate::messages::Message;
    use dratchet_core::ratchet::{RatchetState, DEFAULT_MAX_SKIP};
    use dratchet_core::x3dh::bootstrap_mailbox_id;

    fn temp_db() -> Db {
        let dir = tempfile::tempdir().unwrap().keep();
        Db::create(dir.join("test.redb"), "pw").unwrap()
    }

    fn contact_with_prefs(
        fingerprint: u8,
        wipe_ask_before_delete: bool,
        peer_wipe_ask_before_delete: Option<bool>,
        wipe_include_session: bool,
        peer_wipe_include_session: Option<bool>,
    ) -> Contact {
        Contact {
            fingerprint: vec![fingerprint; 32],
            username: None,
            discriminator: None,
            verification_state: VerificationState::Verified,
            mailbox_id: bootstrap_mailbox_id(&[fingerprint; 32]).to_vec(),
            created_at: 0,
            local_routing_id: vec![0xCD; 32],
            peer_routing_id: None,
            wipe_ask_before_delete,
            peer_wipe_ask_before_delete,
            wipe_include_session,
            peer_wipe_include_session,
            wipe_request_pending: false,
            wipe_boundary_timestamp: None,
            wipe_boundary_sequence: None,
            peer_wipe_boundary_timestamp: None,
            peer_wipe_boundary_sequence: None,
        }
    }

    #[test]
    fn ask_before_delete_requires_unanimous_agreement() {
        // (own, peer) -> effective
        let cases = [
            (false, None, false),
            (false, Some(false), false),
            (false, Some(true), false),
            (true, None, false), // peer never announced -> defaults to false
            (true, Some(false), false),
            (true, Some(true), true), // the only true case
        ];
        for (own, peer, expected) in cases {
            let contact = contact_with_prefs(1, own, peer, false, None);
            assert_eq!(
                contact.effective_wipe_ask_before_delete(),
                expected,
                "own={own} peer={peer:?}"
            );
        }
    }

    #[test]
    fn include_session_is_most_restrictive_wins() {
        let cases = [
            (false, None, false),
            (false, Some(false), false),
            (false, Some(true), true),
            (true, None, true),
            (true, Some(false), true),
            (true, Some(true), true),
        ];
        for (own, peer, expected) in cases {
            let contact = contact_with_prefs(1, false, None, own, peer);
            assert_eq!(
                contact.effective_wipe_include_session(),
                expected,
                "own={own} peer={peer:?}"
            );
        }
    }

    #[test]
    fn record_peer_wipe_policy_persists_and_is_idempotent() {
        let db = temp_db();
        let contact = contact_with_prefs(1, false, None, false, None);
        db.save_contact(&contact).unwrap();

        let updated = db
            .record_peer_wipe_policy(&contact.fingerprint, true, true)
            .unwrap();
        assert_eq!(updated.peer_wipe_ask_before_delete, Some(true));
        assert_eq!(updated.peer_wipe_include_session, Some(true));

        let reloaded = db.load_contact(&contact.fingerprint).unwrap().unwrap();
        assert_eq!(reloaded.peer_wipe_ask_before_delete, Some(true));

        // Repeating is a harmless no-op.
        let again = db
            .record_peer_wipe_policy(&contact.fingerprint, true, true)
            .unwrap();
        assert_eq!(again.peer_wipe_ask_before_delete, Some(true));
    }

    fn sample_ratchet(conversation_id: [u8; 16]) -> RatchetState {
        let responder_secret = x25519_dalek::StaticSecret::from([9u8; 32]);
        let responder_public = x25519_dalek::PublicKey::from(&responder_secret);
        RatchetState::init_as_initiator(
            conversation_id,
            [5u8; 32],
            responder_public,
            DEFAULT_MAX_SKIP,
        )
        .unwrap()
    }

    fn sample_message(id: u8) -> Message {
        Message {
            id: vec![id; 16],
            sender_is_local: true,
            content: b"hello".to_vec(),
            timestamp: 100,
            sequence: 0,
            send_n: None,
            send_dh_pub: None,
            delivered: false,
            uncertain: false,
        }
    }

    #[test]
    fn wipe_conversation_messages_only_leaves_the_ratchet_and_other_conversations_alone() {
        let db = temp_db();
        let conv = [1u8; 16];
        let other_conv = [2u8; 16];

        db.save_message(conv, &sample_message(1)).unwrap();
        db.save_message(conv, &sample_message(2)).unwrap();
        db.save_ratchet(conv, &sample_ratchet(conv)).unwrap();
        db.save_message(other_conv, &sample_message(3)).unwrap();
        db.save_ratchet(other_conv, &sample_ratchet(other_conv))
            .unwrap();

        let removed = db.wipe_conversation(conv, false).unwrap();
        assert_eq!(removed, 2);

        assert!(db.list_messages(conv).unwrap().is_empty());
        assert!(
            db.load_ratchet(conv).unwrap().is_some(),
            "messages-only wipe must leave the ratchet intact"
        );
        assert_eq!(db.list_messages(other_conv).unwrap().len(), 1);
        assert!(db.load_ratchet(other_conv).unwrap().is_some());
    }

    #[test]
    fn wipe_conversation_with_session_also_removes_the_ratchet() {
        let db = temp_db();
        let conv = [3u8; 16];

        db.save_message(conv, &sample_message(1)).unwrap();
        db.save_ratchet(conv, &sample_ratchet(conv)).unwrap();

        let removed = db.wipe_conversation(conv, true).unwrap();
        assert_eq!(removed, 2, "one message + one ratchet record");

        assert!(db.list_messages(conv).unwrap().is_empty());
        assert!(db.load_ratchet(conv).unwrap().is_none());
    }

    fn sample_message_at(id: u8, timestamp: u64, sequence: u64) -> Message {
        Message {
            id: vec![id; 16],
            sender_is_local: true,
            content: b"hello".to_vec(),
            timestamp,
            sequence,
            send_n: None,
            send_dh_pub: None,
            delivered: false,
            uncertain: false,
        }
    }

    #[test]
    fn wipe_conversation_since_leaves_messages_before_the_boundary() {
        let db = temp_db();
        let conv = [5u8; 16];

        db.save_message(conv, &sample_message_at(1, 100, 0))
            .unwrap();
        db.save_message(conv, &sample_message_at(2, 200, 0))
            .unwrap();
        db.save_message(conv, &sample_message_at(3, 300, 0))
            .unwrap();

        let removed = db.wipe_conversation_since(conv, (200, 0), false).unwrap();
        assert_eq!(removed, 2, "messages at and after the boundary");

        let remaining = db.list_messages(conv).unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].timestamp, 100, "pre-boundary message survives");
    }

    #[test]
    fn wipe_conversation_since_removes_messages_at_and_after_the_boundary() {
        let db = temp_db();
        let conv = [6u8; 16];

        // Same-second tie broken by sequence, matching list_messages' sort key.
        db.save_message(conv, &sample_message_at(1, 500, 0))
            .unwrap();
        db.save_message(conv, &sample_message_at(2, 500, 1))
            .unwrap();
        db.save_message(conv, &sample_message_at(3, 500, 2))
            .unwrap();

        let removed = db.wipe_conversation_since(conv, (500, 1), false).unwrap();
        assert_eq!(removed, 2);

        let remaining = db.list_messages(conv).unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].sequence, 0);
    }

    #[test]
    fn wipe_conversation_since_still_removes_the_ratchet_unconditionally_when_include_session() {
        let db = temp_db();
        let conv = [7u8; 16];

        db.save_message(conv, &sample_message_at(1, 100, 0))
            .unwrap();
        db.save_message(conv, &sample_message_at(2, 900, 0))
            .unwrap();
        db.save_ratchet(conv, &sample_ratchet(conv)).unwrap();

        let removed = db.wipe_conversation_since(conv, (900, 0), true).unwrap();
        assert_eq!(removed, 2, "one post-boundary message + the ratchet");

        let remaining = db.list_messages(conv).unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].timestamp, 100, "pre-boundary message survives");
        assert!(
            db.load_ratchet(conv).unwrap().is_none(),
            "include_session removes the ratchet regardless of the boundary"
        );
    }

    #[test]
    fn wipe_conversation_never_touches_the_account_or_contacts() {
        let db = temp_db();
        let conv = [4u8; 16];
        let account = dratchet_core::account::Account::generate().unwrap();
        db.save_account(&account).unwrap();
        let contact = contact_with_prefs(9, false, None, false, None);
        db.save_contact(&contact).unwrap();
        db.save_message(conv, &sample_message(1)).unwrap();
        db.save_ratchet(conv, &sample_ratchet(conv)).unwrap();

        db.wipe_conversation(conv, true).unwrap();

        assert!(db.load_account().unwrap().is_some());
        assert!(db.load_contact(&contact.fingerprint).unwrap().is_some());
    }
}
