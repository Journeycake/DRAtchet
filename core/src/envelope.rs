//! Fixed-layout ratchet message envelope, per `docs/MESSAGE_SCHEMA.md` §2.
//!
//! ```text
//! offset  size  field
//! 0       1     version
//! 1       16    conversation_id
//! 17      32    dh_pub
//! 49      4     pn
//! 53      4     n
//! 57      4     ciphertext_len
//! 61      *     ciphertext (AEAD tag included, per the AEAD API's convention)
//! ```
//!
//! Bytes `0..61` (everything but the ciphertext) are the AEAD associated data —
//! authenticated but not encrypted, per the design's stated header-as-AAD trade-off.

use crate::error::{Error, Result};

pub const HEADER_LEN: usize = 61;
pub const CURRENT_VERSION: u8 = 1;

#[derive(Debug, Clone)]
pub struct Envelope {
    pub version: u8,
    pub conversation_id: [u8; 16],
    pub dh_pub: [u8; 32],
    pub pn: u32,
    pub n: u32,
    /// AEAD ciphertext, tag included.
    pub ciphertext: Vec<u8>,
}

impl Envelope {
    pub fn header_bytes(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0] = self.version;
        out[1..17].copy_from_slice(&self.conversation_id);
        out[17..49].copy_from_slice(&self.dh_pub);
        out[49..53].copy_from_slice(&self.pn.to_be_bytes());
        out[53..57].copy_from_slice(&self.n.to_be_bytes());
        out[57..61].copy_from_slice(&(self.ciphertext.len() as u32).to_be_bytes());
        out
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.ciphertext.len());
        out.extend_from_slice(&self.header_bytes());
        out.extend_from_slice(&self.ciphertext);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER_LEN {
            return Err(Error::MalformedEnvelope("shorter than the fixed header"));
        }
        let version = bytes[0];
        if version != CURRENT_VERSION {
            return Err(Error::MalformedEnvelope("unsupported version"));
        }
        let mut conversation_id = [0u8; 16];
        conversation_id.copy_from_slice(&bytes[1..17]);
        let mut dh_pub = [0u8; 32];
        dh_pub.copy_from_slice(&bytes[17..49]);
        let pn = u32::from_be_bytes(bytes[49..53].try_into().unwrap());
        let n = u32::from_be_bytes(bytes[53..57].try_into().unwrap());
        let ciphertext_len = u32::from_be_bytes(bytes[57..61].try_into().unwrap()) as usize;

        let ciphertext_end = HEADER_LEN
            .checked_add(ciphertext_len)
            .ok_or(Error::MalformedEnvelope("ciphertext_len overflows"))?;
        if ciphertext_end != bytes.len() {
            return Err(Error::MalformedEnvelope(
                "ciphertext_len doesn't match the remaining bytes",
            ));
        }

        Ok(Envelope {
            version,
            conversation_id,
            dh_pub,
            pn,
            n,
            ciphertext: bytes[HEADER_LEN..].to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Envelope {
        Envelope {
            version: CURRENT_VERSION,
            conversation_id: [7u8; 16],
            dh_pub: [9u8; 32],
            pn: 3,
            n: 5,
            ciphertext: vec![1, 2, 3, 4, 5, 6, 7, 8],
        }
    }

    #[test]
    fn round_trips() {
        let env = sample();
        let bytes = env.encode();
        let decoded = Envelope::decode(&bytes).unwrap();
        assert_eq!(decoded.version, env.version);
        assert_eq!(decoded.conversation_id, env.conversation_id);
        assert_eq!(decoded.dh_pub, env.dh_pub);
        assert_eq!(decoded.pn, env.pn);
        assert_eq!(decoded.n, env.n);
        assert_eq!(decoded.ciphertext, env.ciphertext);
    }

    #[test]
    fn header_is_exactly_61_bytes() {
        assert_eq!(sample().header_bytes().len(), HEADER_LEN);
    }

    #[test]
    fn rejects_truncated_input() {
        let bytes = sample().encode();
        assert!(Envelope::decode(&bytes[..HEADER_LEN - 1]).is_err());
    }

    #[test]
    fn rejects_length_mismatch() {
        let mut bytes = sample().encode();
        bytes.push(0xFF); // trailing garbage not accounted for by ciphertext_len
        assert!(Envelope::decode(&bytes).is_err());
    }
}
