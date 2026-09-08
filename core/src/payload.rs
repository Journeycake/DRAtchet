//! Payload tagging and padding, per `docs/MESSAGE_SCHEMA.md` §2.
//!
//! The plaintext carried inside a ratchet envelope's ciphertext is:
//! `[payload_type: 1 byte][content][padding to a fixed bucket]`.
//! Padding is applied to the *tagged* plaintext so a `DeliveryAck` and a
//! short chat message of similar length pad to the same bucket and aren't
//! distinguishable by size alone.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

pub const PAYLOAD_CHAT: u8 = 0;
pub const PAYLOAD_DELIVERY_ACK: u8 = 1;
pub const PAYLOAD_RECOVERY_PROFILE_ANNOUNCE: u8 = 2;
/// `docs/ARCHITECTURE.md` §11.1's final adopted mailbox-addressing fix,
/// Phase 1.6.2: each side announces a fresh routing id over
/// `x3dh::bootstrap_mailbox_id` right after the session is established, so
/// both can independently compute the routing-id-derived `mailbox_id`
/// (`crate::conversation_id`-style) every message after the first uses.
/// Not user-visible chat content, so `docs/ARCHITECTURE.md` §6.5's
/// mandatory-verification gate doesn't apply to it — see `store::gate`.
pub const PAYLOAD_ROUTING_ID_ANNOUNCE: u8 = 3;
/// Announces this side's per-conversation wipe preferences — `MESSAGE_SCHEMA.md`
/// §10. Same shape as `PAYLOAD_RECOVERY_PROFILE_ANNOUNCE`: sent at session
/// establishment and again whenever the announcing side's preferences
/// change, merged independently and identically by both clients, no
/// response needed.
pub const PAYLOAD_CONVERSATION_WIPE_POLICY_ANNOUNCE: u8 = 4;
/// A per-conversation "clear this chat" request — `MESSAGE_SCHEMA.md` §10.
/// Carries no fields; the conversation is already identified by which
/// ratchet/mailbox it arrived on. Ungated like `PAYLOAD_ROUTING_ID_ANNOUNCE`
/// — protocol machinery, not chat content.
pub const PAYLOAD_CONVERSATION_WIPE_REQUEST: u8 = 5;

/// Bucket size messages are padded to (next multiple of this, up to `MAX_PADDED_LEN`).
pub const PAD_BUCKET: usize = 160;
/// Hard cap: payloads larger than this pad up to this single "large message" bucket
/// instead of continuing to bucket by `PAD_BUCKET`, so very large messages (e.g. a
/// future attachment reference) don't produce an unbounded number of distinguishable
/// size buckets.
pub const MAX_PADDED_LEN: usize = 16 * 1024;

/// Tag `content` with `payload_type` and pad the result to a fixed bucket size.
///
/// Wire format of the returned bytes: `[payload_type][len: u32 LE][content][zero padding]`.
/// The explicit length prefix is required because padding is zero bytes, which are not
/// self-delimiting — without it, trailing zero bytes in `content` itself would be
/// indistinguishable from padding on unpad.
pub fn tag_and_pad(payload_type: u8, content: &[u8]) -> Result<Vec<u8>> {
    let tagged_len = 1 + 4 + content.len();
    if tagged_len > MAX_PADDED_LEN {
        return Err(Error::MalformedPayload("content too large to pad"));
    }
    let padded_len = if tagged_len >= MAX_PADDED_LEN.saturating_sub(PAD_BUCKET) {
        MAX_PADDED_LEN
    } else {
        tagged_len.div_ceil(PAD_BUCKET) * PAD_BUCKET
    };

    let mut out = Vec::with_capacity(padded_len);
    out.push(payload_type);
    out.extend_from_slice(&(content.len() as u32).to_le_bytes());
    out.extend_from_slice(content);
    out.resize(padded_len, 0);
    Ok(out)
}

/// Recover `(payload_type, content)` from a tagged-and-padded plaintext.
pub fn untag_and_unpad(data: &[u8]) -> Result<(u8, Vec<u8>)> {
    if data.len() < 5 {
        return Err(Error::MalformedPayload(
            "shorter than the tag+length header",
        ));
    }
    let payload_type = data[0];
    let content_len = u32::from_le_bytes([data[1], data[2], data[3], data[4]]) as usize;
    let content_start: usize = 5;
    let content_end = content_start
        .checked_add(content_len)
        .ok_or(Error::MalformedPayload("length field overflows"))?;
    if content_end > data.len() {
        return Err(Error::MalformedPayload(
            "length field exceeds padded plaintext",
        ));
    }
    Ok((payload_type, data[content_start..content_end].to_vec()))
}

/// `PAYLOAD_ROUTING_ID_ANNOUNCE`'s content — CBOR-encoded, the same
/// pattern `MESSAGE_SCHEMA.md` §7 already documents for `DeliveryAck`/
/// `RecoveryProfileAnnounce`: a small struct carried as an ordinary
/// ratchet message's plaintext, tagged and padded like any other payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutingIdAnnounce {
    #[serde(with = "serde_bytes")]
    pub routing_id: Vec<u8>,
}

impl RoutingIdAnnounce {
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        ciborium::into_writer(self, &mut bytes)
            .expect("CBOR encoding of a well-formed struct cannot fail");
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ciborium::from_reader(bytes)
            .map_err(|_| Error::MalformedPayload("not a valid RoutingIdAnnounce"))
    }
}

/// `PAYLOAD_CONVERSATION_WIPE_POLICY_ANNOUNCE`'s content — `MESSAGE_SCHEMA.md`
/// §10. Each side's own preference for how a per-conversation "clear this
/// chat" request (`PAYLOAD_CONVERSATION_WIPE_REQUEST`) gets handled on
/// *this* side when the *other* side is the one who requested it. The
/// effective policy for a conversation is computed independently and
/// identically by both clients from (own preference, last-announced peer
/// preference) — see `store::wipe_policy` for the two merge functions;
/// this struct only carries the raw announced values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConversationWipePolicyAnnounce {
    /// Ask locally before complying with an incoming wipe request, rather
    /// than deleting immediately.
    pub ask_before_delete: bool,
    /// Also destroy the conversation's ratchet/session state (not just
    /// message history) when complying with a wipe request.
    pub include_session: bool,
}

impl ConversationWipePolicyAnnounce {
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        ciborium::into_writer(self, &mut bytes)
            .expect("CBOR encoding of a well-formed struct cannot fail");
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ciborium::from_reader(bytes)
            .map_err(|_| Error::MalformedPayload("not a valid ConversationWipePolicyAnnounce"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        for content in [
            &b""[..],
            b"hi",
            b"a longer message than the first one, still short",
        ] {
            let padded = tag_and_pad(PAYLOAD_CHAT, content).unwrap();
            let (ty, recovered) = untag_and_unpad(&padded).unwrap();
            assert_eq!(ty, PAYLOAD_CHAT);
            assert_eq!(recovered, content);
        }
    }

    #[test]
    fn short_messages_of_different_length_pad_to_the_same_bucket() {
        let short = tag_and_pad(PAYLOAD_CHAT, b"yes").unwrap();
        let longer = tag_and_pad(PAYLOAD_CHAT, b"no thanks, not today").unwrap();
        assert_eq!(short.len(), longer.len());
        assert_eq!(short.len(), PAD_BUCKET);
    }

    #[test]
    fn delivery_ack_is_not_distinguishable_from_a_short_chat_message_by_size() {
        let ack_content = 20u32.to_be_bytes(); // stand-in for a small CBOR DeliveryAck
        let ack = tag_and_pad(PAYLOAD_DELIVERY_ACK, &ack_content).unwrap();
        let chat = tag_and_pad(PAYLOAD_CHAT, b"ok").unwrap();
        assert_eq!(ack.len(), chat.len());
    }

    #[test]
    fn trailing_zero_bytes_in_content_survive_round_trip() {
        // Guards against the "padding looks like more padding" bug: without the
        // explicit length prefix, this would silently lose the trailing zero.
        let content = [1u8, 2, 3, 0, 0];
        let padded = tag_and_pad(PAYLOAD_CHAT, &content).unwrap();
        let (_, recovered) = untag_and_unpad(&padded).unwrap();
        assert_eq!(recovered, content);
    }

    #[test]
    fn oversized_content_is_rejected() {
        let big = vec![0u8; MAX_PADDED_LEN];
        assert!(tag_and_pad(PAYLOAD_CHAT, &big).is_err());
    }

    #[test]
    fn routing_id_announce_round_trips_through_encode_and_tag_and_pad() {
        let announce = RoutingIdAnnounce {
            routing_id: vec![7u8; 32],
        };
        let encoded = announce.encode();
        let decoded = RoutingIdAnnounce::decode(&encoded).unwrap();
        assert_eq!(decoded, announce);

        // And through the same tag-and-pad wrapping any other payload gets.
        let padded = tag_and_pad(PAYLOAD_ROUTING_ID_ANNOUNCE, &encoded).unwrap();
        let (ty, content) = untag_and_unpad(&padded).unwrap();
        assert_eq!(ty, PAYLOAD_ROUTING_ID_ANNOUNCE);
        assert_eq!(RoutingIdAnnounce::decode(&content).unwrap(), announce);
    }

    #[test]
    fn garbage_bytes_are_rejected_not_panicking() {
        assert!(RoutingIdAnnounce::decode(&[0xFF, 0x00, 0x01]).is_err());
    }

    #[test]
    fn conversation_wipe_policy_announce_round_trips_through_encode_and_tag_and_pad() {
        for (ask_before_delete, include_session) in
            [(false, false), (false, true), (true, false), (true, true)]
        {
            let announce = ConversationWipePolicyAnnounce {
                ask_before_delete,
                include_session,
            };
            let encoded = announce.encode();
            let decoded = ConversationWipePolicyAnnounce::decode(&encoded).unwrap();
            assert_eq!(decoded, announce);

            let padded = tag_and_pad(PAYLOAD_CONVERSATION_WIPE_POLICY_ANNOUNCE, &encoded).unwrap();
            let (ty, content) = untag_and_unpad(&padded).unwrap();
            assert_eq!(ty, PAYLOAD_CONVERSATION_WIPE_POLICY_ANNOUNCE);
            assert_eq!(
                ConversationWipePolicyAnnounce::decode(&content).unwrap(),
                announce
            );
        }
    }

    #[test]
    fn conversation_wipe_request_is_empty_content_tagged_and_padded_like_any_other_payload() {
        let padded = tag_and_pad(PAYLOAD_CONVERSATION_WIPE_REQUEST, &[]).unwrap();
        let (ty, content) = untag_and_unpad(&padded).unwrap();
        assert_eq!(ty, PAYLOAD_CONVERSATION_WIPE_REQUEST);
        assert!(content.is_empty());
    }

    #[test]
    fn conversation_wipe_policy_announce_garbage_bytes_are_rejected_not_panicking() {
        assert!(ConversationWipePolicyAnnounce::decode(&[0xFF, 0x00, 0x01]).is_err());
    }
}
