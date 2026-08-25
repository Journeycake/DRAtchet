//! DRAtchet v0 crypto core: X3DH handshake + Double Ratchet message layer.
//!
//! No transport, no UI — see `docs/ARCHITECTURE.md` §9 (Roadmap) for where this
//! sits. The point of this crate is to make good on the project's central design
//! claim: key rotation driven by turn-taking (Double Ratchet), not a literal
//! per-message keypair, tolerates real message queueing. `tests/queue_depth.rs`
//! is the test that actually proves it.

pub mod account;
pub mod envelope;
pub mod error;
pub mod identity;
pub mod payload;
pub mod prekey;
pub mod ratchet;
pub mod x3dh;

pub use error::{Error, Result};

use sha2::{Digest, Sha256};

/// `conversation_id = SHA-256(sorted(fingerprint_A, fingerprint_B))[:16]`, per
/// `docs/MESSAGE_SCHEMA.md` §2 — both sides compute this independently from the
/// two identity fingerprints, no server needs to mint it.
pub fn conversation_id(fingerprint_a: &[u8], fingerprint_b: &[u8]) -> [u8; 16] {
    let (first, second) = if fingerprint_a <= fingerprint_b {
        (fingerprint_a, fingerprint_b)
    } else {
        (fingerprint_b, fingerprint_a)
    };
    let mut hasher = Sha256::new();
    hasher.update(first);
    hasher.update(second);
    let digest = hasher.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conversation_id_is_order_independent() {
        let a = b"alice-fingerprint";
        let b = b"bob-fingerprint";
        assert_eq!(conversation_id(a, b), conversation_id(b, a));
    }
}
