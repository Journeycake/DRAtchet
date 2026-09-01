//! Long-term identity, per `docs/ARCHITECTURE.md` §3.1.
//!
//! A raw Ed25519 signing keypair — not wrapped in an OpenPGP certificate.
//! v0 originally carried this as an OpenPGP (RFC 9580) certificate via
//! `sequoia-openpgp`, but that was dropped: OpenPGP's ECDH packet encoding
//! is built for wrapping a symmetric session key directly, not for handing
//! out a raw scalar to do an arbitrary external Diffie-Hellman with (the
//! exact thing X3DH's identity DH key, `IK` in `x3dh.rs`/`prekey.rs`,
//! needs) — the same mismatch a future post-quantum (ML-KEM) key would hit
//! trying to live inside an OpenPGP packet. Raw key material sidesteps
//! both: it's just bytes in this project's own extensible CBOR schema, so
//! a new key type is a new optional field, not a packet-format workaround.
//! The certificate/packet machinery (policy objects, subkey search, packet
//! downcasting) also disappears entirely — this module is a fraction of
//! the size its OpenPGP-backed predecessor was.
//!
//! The identity key provides the account's fingerprint and signs prekey
//! public keys to authenticate them. The X3DH/ratchet Diffie-Hellman
//! operations themselves use a separate, dedicated X25519 keypair (see
//! `x3dh.rs`, `prekey.rs`) — kept apart from this Ed25519 signing key
//! because they're different key types for different purposes, not because
//! of any packaging constraint.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

/// SHA-256 of an identity's raw Ed25519 public key — this project's
/// replacement for an OpenPGP certificate's own fingerprint mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }
}

pub struct Identity {
    signing_key: SigningKey,
}

impl Identity {
    /// Generate a fresh identity: a random Ed25519 signing keypair.
    pub fn generate() -> Result<Self> {
        let signing_key = SigningKey::generate(&mut OsRng);
        Ok(Identity { signing_key })
    }

    pub fn fingerprint(&self) -> Fingerprint {
        let digest = Sha256::digest(self.signing_key.verifying_key().as_bytes());
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        Fingerprint(out)
    }

    /// Export the raw 32-byte Ed25519 public key.
    pub fn export_public_key(&self) -> Result<Vec<u8>> {
        Ok(self.signing_key.verifying_key().to_bytes().to_vec())
    }

    /// Sign a prekey's raw public key bytes, binding it to `prekey_id` and this
    /// identity's fingerprint so a signature can't be replayed onto a different
    /// prekey id. Returns a raw 64-byte Ed25519 signature.
    pub fn sign_prekey(&self, prekey_id: u32, prekey_public: &[u8; 32]) -> Result<Vec<u8>> {
        let message = prekey_signing_payload(prekey_id, prekey_public);
        let sig = self.signing_key.sign(&message);
        Ok(sig.to_bytes().to_vec())
    }

    /// Verify a prekey signature produced by [`Identity::sign_prekey`], given the
    /// signer's public key (as exported by [`Identity::export_public_key`]).
    pub fn verify_prekey_signature(
        signer_public_key_bytes: &[u8],
        prekey_id: u32,
        prekey_public: &[u8; 32],
        signature_bytes: &[u8],
    ) -> Result<()> {
        let public_key_array: [u8; 32] = signer_public_key_bytes
            .try_into()
            .map_err(|_| Error::InvalidPrekeySignature)?;
        let verifying_key = VerifyingKey::from_bytes(&public_key_array)
            .map_err(|_| Error::InvalidPrekeySignature)?;
        let signature =
            Signature::from_slice(signature_bytes).map_err(|_| Error::InvalidPrekeySignature)?;

        let message = prekey_signing_payload(prekey_id, prekey_public);
        verifying_key
            .verify(&message, &signature)
            .map_err(|_| Error::InvalidPrekeySignature)
    }
}

fn prekey_signing_payload(prekey_id: u32, prekey_public: &[u8; 32]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(4 + 32);
    msg.extend_from_slice(&prekey_id.to_be_bytes());
    msg.extend_from_slice(prekey_public);
    msg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_and_exports() {
        let id = Identity::generate().unwrap();
        let exported = id.export_public_key().unwrap();
        assert_eq!(exported.len(), 32);
        assert!(!id.fingerprint().to_hex().is_empty());
    }

    #[test]
    fn signs_and_verifies_a_prekey() {
        let id = Identity::generate().unwrap();
        let public_key_bytes = id.export_public_key().unwrap();
        let prekey_public = [42u8; 32];

        let sig = id.sign_prekey(7, &prekey_public).unwrap();
        Identity::verify_prekey_signature(&public_key_bytes, 7, &prekey_public, &sig)
            .expect("signature should verify");
    }

    #[test]
    fn rejects_signature_for_a_different_prekey_id() {
        let id = Identity::generate().unwrap();
        let public_key_bytes = id.export_public_key().unwrap();
        let prekey_public = [42u8; 32];

        let sig = id.sign_prekey(7, &prekey_public).unwrap();
        let result = Identity::verify_prekey_signature(&public_key_bytes, 8, &prekey_public, &sig);
        assert!(
            result.is_err(),
            "signature bound to id=7 must not verify for id=8"
        );
    }

    #[test]
    fn rejects_signature_for_a_different_prekey_value() {
        let id = Identity::generate().unwrap();
        let public_key_bytes = id.export_public_key().unwrap();

        let sig = id.sign_prekey(7, &[42u8; 32]).unwrap();
        let tampered_public = [43u8; 32];
        let result =
            Identity::verify_prekey_signature(&public_key_bytes, 7, &tampered_public, &sig);
        assert!(
            result.is_err(),
            "signature must not verify for a tampered prekey value"
        );
    }

    #[test]
    fn rejects_signature_from_a_different_identity() {
        let alice = Identity::generate().unwrap();
        let mallory = Identity::generate().unwrap();
        let mallory_public_key_bytes = mallory.export_public_key().unwrap();
        let prekey_public = [42u8; 32];

        let sig = alice.sign_prekey(7, &prekey_public).unwrap();
        let result =
            Identity::verify_prekey_signature(&mallory_public_key_bytes, 7, &prekey_public, &sig);
        assert!(
            result.is_err(),
            "Alice's signature must not verify against Mallory's public key"
        );
    }

    #[test]
    fn rejects_malformed_public_key_and_signature_bytes_without_panicking() {
        let prekey_public = [42u8; 32];
        assert!(
            Identity::verify_prekey_signature(&[0u8; 3], 7, &prekey_public, &[0u8; 64]).is_err()
        );
        assert!(
            Identity::verify_prekey_signature(&[0u8; 32], 7, &prekey_public, &[0u8; 3]).is_err()
        );
    }
}
