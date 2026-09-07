//! Phase 1.6.2: the routing-id exchange that lets a conversation's Tier 1
//! `mailbox_id` transition off `x3dh::bootstrap_mailbox_id` onto the
//! unlinkable, per-pairing routing-id-derived one — `docs/ARCHITECTURE.md`
//! §11.1's final adopted fix, mechanism as designed in this session's plan:
//! each side announces a fresh routing id over the bootstrap mailbox right
//! after the session is established (an ordinary, ungated
//! `PAYLOAD_ROUTING_ID_ANNOUNCE` ratchet message, not something carried in
//! the QR/pairing-code payload itself — see `docs/ARCHITECTURE.md` §6.3/
//! §6.4, unchanged by this).
//!
//! This module only computes and persists the transition; actually sending/
//! receiving the announce over the wire is the caller's job (a real client,
//! `store/tests/routing_id_exchange.rs` for this crate's own end-to-end
//! proof).

use dratchet_core::conversation_id;

use crate::contacts::Contact;
use crate::db::Db;
use crate::error::Result;

/// The Tier 1 mailbox id for a conversation once both routing ids are
/// known — the same sorted-hash `conversation_id` already uses for
/// identity fingerprints, reused here for a different pair of inputs (see
/// `docs/ARCHITECTURE.md` §6.3a).
pub fn compute_mailbox_id(local_routing_id: &[u8], peer_routing_id: &[u8]) -> [u8; 16] {
    conversation_id(local_routing_id, peer_routing_id)
}

impl Db {
    /// Record the peer's just-arrived routing id and, if this is the first
    /// time it's been seen for this contact, transition `mailbox_id` off
    /// `bootstrap_mailbox_id` onto the routing-id-derived one — persisted
    /// immediately. Idempotent: calling this again with the same value (a
    /// retransmitted/duplicate announce) is a no-op past the first call.
    pub fn record_peer_routing_id(
        &self,
        fingerprint: &[u8],
        peer_routing_id: Vec<u8>,
    ) -> Result<Contact> {
        let mut contact =
            self.load_contact(fingerprint)?
                .ok_or(crate::error::Error::MalformedRecord(
                    "record_peer_routing_id: no such contact",
                ))?;

        if contact.peer_routing_id.as_deref() != Some(peer_routing_id.as_slice()) {
            contact.mailbox_id =
                compute_mailbox_id(&contact.local_routing_id, &peer_routing_id).to_vec();
            contact.peer_routing_id = Some(peer_routing_id);
            self.save_contact(&contact)?;
        }
        Ok(contact)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contacts::VerificationState;
    use dratchet_core::x3dh::bootstrap_mailbox_id;

    fn temp_db() -> Db {
        let dir = tempfile::tempdir().unwrap().keep();
        Db::create(dir.join("test.redb"), "pw").unwrap()
    }

    fn fresh_pending_contact(fingerprint: u8, local_routing_id: Vec<u8>) -> Contact {
        Contact {
            fingerprint: vec![fingerprint; 32],
            username: None,
            discriminator: None,
            verification_state: VerificationState::Pending,
            mailbox_id: bootstrap_mailbox_id(&[fingerprint; 32]).to_vec(),
            created_at: 0,
            disappearing_timer_secs: None,
            local_routing_id,
            peer_routing_id: None,
        }
    }

    #[test]
    fn compute_mailbox_id_is_order_independent_and_matches_conversation_id() {
        let a = vec![1u8; 32];
        let b = vec![2u8; 32];
        assert_eq!(compute_mailbox_id(&a, &b), compute_mailbox_id(&b, &a));
        assert_eq!(compute_mailbox_id(&a, &b), conversation_id(&a, &b));
    }

    #[test]
    fn recording_the_peer_routing_id_transitions_off_the_bootstrap_mailbox() {
        let db = temp_db();
        let local_routing_id = vec![0xAAu8; 32];
        let contact = fresh_pending_contact(1, local_routing_id.clone());
        let bootstrap = contact.mailbox_id.clone();
        db.save_contact(&contact).unwrap();

        let peer_routing_id = vec![0xBBu8; 32];
        let updated = db
            .record_peer_routing_id(&contact.fingerprint, peer_routing_id.clone())
            .unwrap();

        assert_ne!(
            updated.mailbox_id, bootstrap,
            "mailbox_id must move off the bootstrap mailbox once the peer's routing id arrives"
        );
        assert_eq!(
            updated.mailbox_id,
            compute_mailbox_id(&local_routing_id, &peer_routing_id)
        );
        assert_eq!(updated.peer_routing_id, Some(peer_routing_id));

        // And it's actually persisted, not just returned.
        let reloaded = db.load_contact(&contact.fingerprint).unwrap().unwrap();
        assert_eq!(reloaded.mailbox_id, updated.mailbox_id);
    }

    /// Both sides independently computing the transition from their own
    /// (local, peer) pair must land on the identical mailbox id — the
    /// actual property that makes this work at all without a server ever
    /// minting or coordinating it.
    #[test]
    fn both_sides_converge_on_the_identical_mailbox_id() {
        let db_alice = temp_db();
        let db_bob = temp_db();

        let alice_routing_id = vec![0x11u8; 32];
        let bob_routing_id = vec![0x22u8; 32];

        let alice_contact = fresh_pending_contact(1, alice_routing_id.clone());
        db_alice.save_contact(&alice_contact).unwrap();
        let bob_contact = fresh_pending_contact(2, bob_routing_id.clone());
        db_bob.save_contact(&bob_contact).unwrap();

        let alice_updated = db_alice
            .record_peer_routing_id(&alice_contact.fingerprint, bob_routing_id)
            .unwrap();
        let bob_updated = db_bob
            .record_peer_routing_id(&bob_contact.fingerprint, alice_routing_id)
            .unwrap();

        assert_eq!(alice_updated.mailbox_id, bob_updated.mailbox_id);
    }

    #[test]
    fn recording_the_same_peer_routing_id_twice_is_a_no_op() {
        let db = temp_db();
        let contact = fresh_pending_contact(1, vec![0xAAu8; 32]);
        db.save_contact(&contact).unwrap();

        let peer_routing_id = vec![0xBBu8; 32];
        let first = db
            .record_peer_routing_id(&contact.fingerprint, peer_routing_id.clone())
            .unwrap();
        let second = db
            .record_peer_routing_id(&contact.fingerprint, peer_routing_id)
            .unwrap();

        assert_eq!(first.mailbox_id, second.mailbox_id);
    }
}
