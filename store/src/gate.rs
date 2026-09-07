//! `docs/ARCHITECTURE.md` §6.5's mandatory-verification gate, enforced
//! directly: chat content (`payload_type = PAYLOAD_CHAT`) is refused, both
//! ways, while a contact is anything other than `Verified`. Everything
//! else — the ratchet's own decrypt/encrypt, including protocol messages
//! like the Phase 1.6.2 routing-id exchange — runs exactly as it would for
//! a Verified contact, per §6.5's own text: "what's gated is *release* of
//! application content to and from the user, not the protocol machinery
//! underneath it."

use dratchet_core::envelope::Envelope;
use dratchet_core::payload::PAYLOAD_CHAT;
use dratchet_core::ratchet::RatchetState;

use crate::contacts::{Contact, VerificationState};
use crate::error::{Error, Result};

/// Encrypt `content` as `payload_type`, refusing outright (without
/// touching the ratchet at all) if this is chat content and `contact`
/// isn't `Verified` — nothing needs to advance the sending chain for a
/// message that's never actually sent.
pub fn encrypt_gated(
    ratchet: &mut RatchetState,
    contact: &Contact,
    payload_type: u8,
    content: &[u8],
) -> Result<Envelope> {
    if payload_type == PAYLOAD_CHAT && contact.verification_state != VerificationState::Verified {
        return Err(Error::NotVerified);
    }
    Ok(ratchet.encrypt_payload(payload_type, content)?)
}

/// Decrypt `envelope` — always actually running the ratchet step, so a
/// Pending contact's session (and anything it needs to complete
/// verification, like the routing-id exchange) keeps working correctly —
/// but withhold the *content* if it turns out to be chat content and
/// `contact` isn't `Verified`. The returned `payload_type` is always
/// accurate even on refusal, so a caller can tell "this was chat, blocked"
/// apart from "this was a protocol message, here it is."
pub fn decrypt_gated(
    ratchet: &mut RatchetState,
    contact: &Contact,
    envelope: &Envelope,
) -> Result<(u8, Vec<u8>)> {
    let (payload_type, content) = ratchet.decrypt_payload(envelope)?;
    if payload_type == PAYLOAD_CHAT && contact.verification_state != VerificationState::Verified {
        return Err(Error::NotVerified);
    }
    Ok((payload_type, content))
}

impl Contact {
    /// Mark this contact Verified — §6.3/§6.4's "match" outcome. The only
    /// way into the `Verified` state.
    pub fn mark_verified(&mut self) {
        self.verification_state = VerificationState::Verified;
    }

    /// Revert to a hard-stop mismatch — §6.3's "mismatch is a hard stop,
    /// never silently marked verified," and §6.2's "identity changed"
    /// case. There is deliberately no path back to `Verified` except
    /// `mark_verified` being called again after a fresh, successful
    /// verification — this method itself never does that.
    pub fn mark_mismatch(&mut self) {
        self.verification_state = VerificationState::Mismatch;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dratchet_core::payload::{PAYLOAD_DELIVERY_ACK, PAYLOAD_RECOVERY_PROFILE_ANNOUNCE};
    use dratchet_core::ratchet::DEFAULT_MAX_SKIP;
    use x25519_dalek::{PublicKey, StaticSecret};

    fn matched_pair() -> (RatchetState, RatchetState) {
        let conversation_id = [1u8; 16];
        let root_key = [42u8; 32];
        let responder_secret = StaticSecret::from([2u8; 32]);
        let responder_public = PublicKey::from(&responder_secret);
        (
            RatchetState::init_as_initiator(
                conversation_id,
                root_key,
                responder_public,
                DEFAULT_MAX_SKIP,
            )
            .unwrap(),
            RatchetState::init_as_responder(
                conversation_id,
                root_key,
                responder_secret,
                DEFAULT_MAX_SKIP,
            )
            .unwrap(),
        )
    }

    fn contact_with_state(state: VerificationState) -> Contact {
        Contact {
            fingerprint: vec![1u8; 32],
            username: None,
            discriminator: None,
            verification_state: state,
            mailbox_id: vec![0xAB; 16],
            created_at: 0,
            disappearing_timer_secs: None,
        }
    }

    #[test]
    fn chat_content_is_blocked_both_ways_while_pending() {
        let (mut alice, mut bob) = matched_pair();
        let pending = contact_with_state(VerificationState::Pending);

        assert!(matches!(
            encrypt_gated(&mut alice, &pending, PAYLOAD_CHAT, b"hi"),
            Err(Error::NotVerified)
        ));

        // Encrypt directly (bypassing the gate, as the real sender
        // wouldn't be able to) so there's something to attempt decrypting
        // on Bob's side.
        let envelope = alice.encrypt_payload(PAYLOAD_CHAT, b"hi").unwrap();
        assert!(matches!(
            decrypt_gated(&mut bob, &pending, &envelope),
            Err(Error::NotVerified)
        ));
    }

    #[test]
    fn chat_content_flows_normally_once_verified() {
        let (mut alice, mut bob) = matched_pair();
        let verified = contact_with_state(VerificationState::Verified);

        let envelope = encrypt_gated(&mut alice, &verified, PAYLOAD_CHAT, b"hello bob").unwrap();
        let (payload_type, content) = decrypt_gated(&mut bob, &verified, &envelope).unwrap();
        assert_eq!(payload_type, PAYLOAD_CHAT);
        assert_eq!(content, b"hello bob");
    }

    #[test]
    fn a_mismatch_contact_is_blocked_exactly_like_pending() {
        let (mut alice, mut bob) = matched_pair();
        let mismatch = contact_with_state(VerificationState::Mismatch);

        assert!(matches!(
            encrypt_gated(&mut alice, &mismatch, PAYLOAD_CHAT, b"hi"),
            Err(Error::NotVerified)
        ));
        let envelope = alice.encrypt_payload(PAYLOAD_CHAT, b"hi").unwrap();
        assert!(matches!(
            decrypt_gated(&mut bob, &mismatch, &envelope),
            Err(Error::NotVerified)
        ));
    }

    /// §6.5: the ratchet itself must keep advancing for a Pending contact
    /// — otherwise verification-adjacent protocol traffic (the routing-id
    /// exchange, Phase 1.6.2) could never get through in the first place.
    /// Proven directly: three chat messages refused while Pending still
    /// each advance Bob's receiving chain, so a fourth, non-chat payload
    /// decrypts correctly afterward — impossible if the gate had silently
    /// no-op'd on the ratchet instead of actually running it.
    #[test]
    fn the_ratchet_keeps_advancing_underneath_a_blocked_pending_contact() {
        let (mut alice, mut bob) = matched_pair();
        let pending = contact_with_state(VerificationState::Pending);

        for i in 0..3 {
            let envelope = alice
                .encrypt_payload(PAYLOAD_CHAT, format!("blocked {i}").as_bytes())
                .unwrap();
            assert!(matches!(
                decrypt_gated(&mut bob, &pending, &envelope),
                Err(Error::NotVerified)
            ));
        }

        // A non-chat protocol payload (standing in for Phase 1.6.2's
        // RoutingIdAnnounce) must still decrypt and be returned, ungated.
        let ack_envelope = alice
            .encrypt_payload(PAYLOAD_DELIVERY_ACK, b"ack-content")
            .unwrap();
        let (payload_type, content) = decrypt_gated(&mut bob, &pending, &ack_envelope).unwrap();
        assert_eq!(payload_type, PAYLOAD_DELIVERY_ACK);
        assert_eq!(content, b"ack-content");
    }

    #[test]
    fn non_chat_payloads_are_never_gated_even_while_pending() {
        let (mut alice, mut bob) = matched_pair();
        let pending = contact_with_state(VerificationState::Pending);

        let envelope = encrypt_gated(
            &mut alice,
            &pending,
            PAYLOAD_RECOVERY_PROFILE_ANNOUNCE,
            b"profile",
        )
        .unwrap();
        let (payload_type, content) = decrypt_gated(&mut bob, &pending, &envelope).unwrap();
        assert_eq!(payload_type, PAYLOAD_RECOVERY_PROFILE_ANNOUNCE);
        assert_eq!(content, b"profile");
    }

    #[test]
    fn mark_verified_then_mark_mismatch_is_a_hard_stop_not_reversible_by_itself() {
        let mut contact = contact_with_state(VerificationState::Pending);
        contact.mark_verified();
        assert_eq!(contact.verification_state, VerificationState::Verified);

        contact.mark_mismatch();
        assert_eq!(contact.verification_state, VerificationState::Mismatch);

        // Gating must reflect the reverted state immediately.
        let (mut alice, _bob) = matched_pair();
        assert!(matches!(
            encrypt_gated(&mut alice, &contact, PAYLOAD_CHAT, b"hi"),
            Err(Error::NotVerified)
        ));
    }
}
