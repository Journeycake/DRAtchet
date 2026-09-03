//! Wire protocol for the Signaling & Presence Service, per `docs/SERVERS.md`
//! §1 and the message field tables in `docs/MESSAGE_SCHEMA.md` §1/§6/§7.
//!
//! **Framing (implementation detail, not specified in `MESSAGE_SCHEMA.md` —
//! documented here and cross-referenced from there):** every WebSocket
//! binary frame is `[tag: u8][CBOR body]`. The tag byte multiplexes the
//! connection the same way `payload_type` multiplexes a ratchet envelope's
//! plaintext (`MESSAGE_SCHEMA.md` §2) — a single byte, not a full string
//! discriminator inside the CBOR body, keeping every frame's type
//! identifiable before the (potentially malformed) CBOR body is even
//! touched.
//!
//! All binary fields use `serde_bytes` so they encode as CBOR byte strings,
//! not arrays of integers — required for `identity_key` and friends to
//! round-trip as the raw fixed-size bytes `MESSAGE_SCHEMA.md`'s encoding
//! conventions specify, not a JSON-ism.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

macro_rules! frame_tags {
    ($($tag:literal => $name:ident),+ $(,)?) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        #[repr(u8)]
        pub enum FrameTag {
            $($name = $tag),+
        }

        impl FrameTag {
            pub fn from_u8(b: u8) -> Option<Self> {
                match b {
                    $($tag => Some(FrameTag::$name)),+,
                    _ => None,
                }
            }
        }
    };
}

frame_tags! {
    0x01 => AuthChallenge,
    0x02 => AuthResponse,
    0x03 => PublishBundle,
    0x04 => FetchBundle,
    0x05 => BundleResult,
    0x06 => PresenceAnnounce,
    0x07 => PresenceUpdate,
    0x08 => PresenceSubscribe,
    0x09 => RendezvousOffer,
    0x0A => RendezvousAnswer,
    0x0B => MailboxWrite,
    0x0C => MailboxFetch,
    0x0D => MailboxEntries,
    0x0E => MailboxDelete,
    0x0F => Ack,
    0x10 => Error,
}

/// Encode a typed frame body as `[tag][CBOR]`.
pub fn encode<T: Serialize>(tag: FrameTag, body: &T) -> Vec<u8> {
    let mut out = vec![tag as u8];
    ciborium::into_writer(body, &mut out)
        .expect("CBOR encoding of a well-formed struct cannot fail");
    out
}

/// Split a raw frame into its tag and CBOR body bytes, without parsing the
/// body yet — the caller dispatches on the tag before decoding, so an
/// unrecognized tag is rejected in one branch rather than deep inside a
/// generic CBOR-shape error. Never panics on malformed/truncated/adversarial
/// input; every failure is a plain `Err`.
pub fn split_tag(frame: &[u8]) -> Result<(FrameTag, &[u8])> {
    let (&tag_byte, body) = frame
        .split_first()
        .ok_or(Error::MalformedFrame("empty frame"))?;
    let tag = FrameTag::from_u8(tag_byte).ok_or(Error::MalformedFrame("unknown frame tag"))?;
    Ok((tag, body))
}

/// Decode a CBOR body into `T`, wrapping any parse failure — malformed,
/// truncated, or adversarially-crafted bytes — as a plain protocol error,
/// never a panic.
pub fn decode_body<T: for<'de> Deserialize<'de>>(body: &[u8]) -> Result<T> {
    ciborium::from_reader(body)
        .map_err(|_| Error::MalformedFrame("body did not decode as expected CBOR shape"))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthChallenge {
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthResponse {
    #[serde(with = "serde_bytes")]
    pub identity_fingerprint: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OneTimePrekeyWire {
    pub id: u32,
    #[serde(with = "serde_bytes")]
    pub key: Vec<u8>,
}

/// Mirrors `MESSAGE_SCHEMA.md` §1 exactly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrekeyBundleWire {
    pub username: String,
    pub discriminator: u16,
    #[serde(with = "serde_bytes")]
    pub identity_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub identity_dh_public: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub identity_dh_signature: Vec<u8>,
    pub signed_prekey_id: u32,
    #[serde(with = "serde_bytes")]
    pub signed_prekey: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub signed_prekey_sig: Vec<u8>,
    pub signed_prekey_expires_at: u64,
    pub one_time_prekeys: Vec<OneTimePrekeyWire>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PublishBundle {
    pub bundle: PrekeyBundleWire,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FetchBundle {
    pub username: String,
    pub discriminator: u16,
}

/// The *fetched* shape of a bundle — unlike `PrekeyBundleWire` (the
/// *published* batch), a fetch response hands back at most one one-time
/// prekey, consumed from the stored batch and removed
/// (`ARCHITECTURE.md` §3.4's single-use, discard-after-use rule), mirroring
/// `core::prekey::PrekeyBundle`'s own singular `one_time_prekey` field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchedBundleWire {
    pub username: String,
    pub discriminator: u16,
    #[serde(with = "serde_bytes")]
    pub identity_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub identity_dh_public: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub identity_dh_signature: Vec<u8>,
    pub signed_prekey_id: u32,
    #[serde(with = "serde_bytes")]
    pub signed_prekey: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub signed_prekey_sig: Vec<u8>,
    pub signed_prekey_expires_at: u64,
    pub one_time_prekey: Option<OneTimePrekeyWire>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BundleResult {
    pub bundle: Option<FetchedBundleWire>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(u8)]
pub enum PresenceState {
    Online = 0,
    Away = 1,
    Offline = 2,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PresenceAnnounce {
    pub state: u8,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PresenceUpdate {
    #[serde(with = "serde_bytes")]
    pub identity_fingerprint: Vec<u8>,
    pub state: u8,
    pub last_seen: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PresenceSubscribe {
    #[serde(with = "serde_bytes")]
    pub identity_fingerprint: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RendezvousOffer {
    #[serde(with = "serde_bytes")]
    pub peer_fingerprint: Vec<u8>,
    pub sdp_offer: String,
    pub ice_candidates: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RendezvousAnswer {
    #[serde(with = "serde_bytes")]
    pub peer_fingerprint: Vec<u8>,
    pub sdp_answer: String,
    pub ice_candidates: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MailboxWrite {
    #[serde(with = "serde_bytes")]
    pub mailbox_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub envelope: Vec<u8>,
    pub ttl: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MailboxFetch {
    #[serde(with = "serde_bytes")]
    pub mailbox_id: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailboxEntryWire {
    #[serde(with = "serde_bytes")]
    pub entry_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub envelope: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MailboxEntries {
    pub entries: Vec<MailboxEntryWire>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MailboxDelete {
    #[serde(with = "serde_bytes")]
    pub mailbox_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub entry_id: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Ack {
    pub ok: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorFrame {
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_a_typed_frame() {
        let body = AuthChallenge {
            nonce: vec![7u8; 32],
        };
        let frame = encode(FrameTag::AuthChallenge, &body);
        assert_eq!(frame[0], FrameTag::AuthChallenge as u8);
        let (tag, rest) = split_tag(&frame).unwrap();
        assert_eq!(tag, FrameTag::AuthChallenge);
        let decoded: AuthChallenge = decode_body(rest).unwrap();
        assert_eq!(decoded.nonce, body.nonce);
    }

    #[test]
    fn empty_frame_is_rejected_not_panicking() {
        assert!(split_tag(&[]).is_err());
    }

    #[test]
    fn unknown_tag_is_rejected() {
        assert!(split_tag(&[0xFF, 1, 2, 3]).is_err());
    }

    #[test]
    fn truncated_and_garbage_cbor_body_is_rejected_not_panicking() {
        for body in [
            &b""[..],
            &b"\x00"[..],
            &b"\xff\xff\xff\xff"[..],
            &vec![0u8; 3][..],
        ] {
            let result: Result<AuthChallenge> = decode_body(body);
            assert!(result.is_err());
        }
    }

    #[test]
    fn byte_fields_encode_as_cbor_byte_strings_not_integer_arrays() {
        let body = AuthChallenge {
            nonce: vec![1, 2, 3],
        };
        let frame = encode(FrameTag::AuthChallenge, &body);
        // CBOR byte string major type 2, length 3 (0x43), immediately
        // followed by the three raw bytes, must appear somewhere in the
        // encoded map — not an array-of-3-integers encoding (0x83 01 02
        // 03), which would be semantically wrong for key material per
        // MESSAGE_SCHEMA.md's encoding conventions.
        let needle = [0x43u8, 1, 2, 3];
        assert!(
            frame.windows(needle.len()).any(|w| w == needle),
            "expected a CBOR byte-string encoding of [1,2,3] somewhere in {frame:02x?}"
        );
        assert!(
            !frame.windows(4).any(|w| w == [0x83, 1, 2, 3]),
            "nonce must not be encoded as a CBOR array of integers"
        );
    }
}
