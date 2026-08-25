//! Long-term OpenPGP identity, per `docs/ARCHITECTURE.md` §3.1.
//!
//! The identity certificate provides the account's fingerprint and signs
//! prekey public keys to authenticate them. The X3DH/ratchet Diffie-Hellman
//! operations themselves use dedicated X25519 keys (see `x3dh.rs`, `prekey.rs`)
//! rather than keys extracted from the certificate's own OpenPGP packets: OpenPGP's
//! ECDH packet encoding is built for wrapping a symmetric session key directly, not
//! for handing out a raw scalar to do an arbitrary external Diffie-Hellman with, and
//! papering over that mismatch by reaching into sequoia's internal MPI representation
//! is exactly the kind of subtle-bug-prone shortcut a first implementation shouldn't
//! take without interop test vectors to check it against. The identity key's stated
//! ECDH *capability* is still real; this crate just doesn't use it for X3DH.

use openpgp::cert::CertBuilder;
use openpgp::crypto::KeyPair;
use openpgp::packet::signature::SignatureBuilder;
use openpgp::packet::Any;
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::SerializeInto;
use openpgp::types::SignatureType;
use openpgp::{Cert, Fingerprint};
use sequoia_openpgp as openpgp;

use crate::error::{Error, Result};

pub struct Identity {
    cert: Cert,
}

impl Identity {
    /// Generate a fresh identity: an OpenPGP certificate with an Ed25519 primary
    /// (certification + signing capable) and a Curve25519 ECDH encryption subkey.
    pub fn generate(userid: &str) -> Result<Self> {
        let (cert, _revocation) = CertBuilder::new()
            .add_userid(userid)
            .set_cipher_suite(openpgp::cert::CipherSuite::Cv25519)
            .add_signing_subkey()
            .add_transport_encryption_subkey()
            .generate()
            .map_err(Error::OpenPgp)?;
        Ok(Identity { cert })
    }

    pub fn fingerprint(&self) -> Fingerprint {
        self.cert.fingerprint()
    }

    /// Export the certificate as an OpenPGP transferable public key (binary).
    pub fn export_public_cert(&self) -> Result<Vec<u8>> {
        SerializeInto::to_vec(&self.cert.armored()).map_err(Error::OpenPgp)
    }

    /// Sign a prekey's raw public key bytes, binding it to `prekey_id` and this
    /// identity's fingerprint so a signature can't be replayed onto a different
    /// prekey id. Returns a detached OpenPGP signature packet (binary).
    pub fn sign_prekey(&self, prekey_id: u32, prekey_public: &[u8; 32]) -> Result<Vec<u8>> {
        let policy = StandardPolicy::new();
        let signing_keypair = self
            .cert
            .keys()
            .with_policy(&policy, None)
            .alive()
            .revoked(false)
            .for_signing()
            .secret()
            .next()
            .ok_or_else(|| Error::OpenPgp(anyhow::anyhow!("no usable signing subkey")))?
            .key()
            .clone()
            .into_keypair()
            .map_err(Error::OpenPgp)?;

        let message = prekey_signing_payload(prekey_id, prekey_public);
        let sig = SignatureBuilder::new(SignatureType::Binary)
            .sign_message(&mut keypair_as_signer(signing_keypair), message)
            .map_err(Error::OpenPgp)?;
        // `Signature` only implements `Marshal` (packet *body* only, no CTB/length
        // header) — wrap it in a `Packet` first to get a standalone, parseable
        // packet stream matching what `Packet::from_bytes` expects on the read side.
        let packet = openpgp::Packet::from(sig);
        SerializeInto::to_vec(&packet).map_err(Error::OpenPgp)
    }

    /// Verify a prekey signature produced by [`Identity::sign_prekey`], given the
    /// signer's public certificate (as exported by [`Identity::export_public_cert`]).
    pub fn verify_prekey_signature(
        signer_cert_bytes: &[u8],
        prekey_id: u32,
        prekey_public: &[u8; 32],
        signature_bytes: &[u8],
    ) -> Result<()> {
        let cert = Cert::from_bytes(signer_cert_bytes).map_err(Error::OpenPgp)?;
        let policy = StandardPolicy::new();
        let packet = openpgp::Packet::from_bytes(signature_bytes).map_err(Error::OpenPgp)?;
        let sig: openpgp::packet::Signature = packet
            .downcast()
            .map_err(|_| Error::InvalidPrekeySignature)?;

        let message = prekey_signing_payload(prekey_id, prekey_public);

        for ka in cert
            .keys()
            .with_policy(&policy, None)
            .alive()
            .revoked(false)
        {
            let sig = sig.clone();
            if sig.verify_message(ka.key(), &message).is_ok() {
                return Ok(());
            }
        }
        Err(Error::InvalidPrekeySignature)
    }
}

fn prekey_signing_payload(prekey_id: u32, prekey_public: &[u8; 32]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(4 + 32);
    msg.extend_from_slice(&prekey_id.to_be_bytes());
    msg.extend_from_slice(prekey_public);
    msg
}

/// Adapt a [`KeyPair`] to the `Signer` trait object `SignatureBuilder::sign_message` wants.
fn keypair_as_signer(keypair: KeyPair) -> KeyPair {
    keypair
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_and_exports() {
        let id = Identity::generate("alice@example.test").unwrap();
        let exported = id.export_public_cert().unwrap();
        assert!(!exported.is_empty());
        assert!(!id.fingerprint().to_hex().is_empty());
    }

    #[test]
    fn signs_and_verifies_a_prekey() {
        let id = Identity::generate("alice@example.test").unwrap();
        let cert_bytes = id.export_public_cert().unwrap();
        let prekey_public = [42u8; 32];

        let sig = id.sign_prekey(7, &prekey_public).unwrap();
        Identity::verify_prekey_signature(&cert_bytes, 7, &prekey_public, &sig)
            .expect("signature should verify");
    }

    #[test]
    fn rejects_signature_for_a_different_prekey_id() {
        let id = Identity::generate("alice@example.test").unwrap();
        let cert_bytes = id.export_public_cert().unwrap();
        let prekey_public = [42u8; 32];

        let sig = id.sign_prekey(7, &prekey_public).unwrap();
        let result = Identity::verify_prekey_signature(&cert_bytes, 8, &prekey_public, &sig);
        assert!(
            result.is_err(),
            "signature bound to id=7 must not verify for id=8"
        );
    }

    #[test]
    fn rejects_signature_for_a_different_prekey_value() {
        let id = Identity::generate("alice@example.test").unwrap();
        let cert_bytes = id.export_public_cert().unwrap();

        let sig = id.sign_prekey(7, &[42u8; 32]).unwrap();
        let tampered_public = [43u8; 32];
        let result = Identity::verify_prekey_signature(&cert_bytes, 7, &tampered_public, &sig);
        assert!(
            result.is_err(),
            "signature must not verify for a tampered prekey value"
        );
    }

    #[test]
    fn rejects_signature_from_a_different_identity() {
        let alice = Identity::generate("alice@example.test").unwrap();
        let mallory = Identity::generate("mallory@example.test").unwrap();
        let mallory_cert_bytes = mallory.export_public_cert().unwrap();
        let prekey_public = [42u8; 32];

        let sig = alice.sign_prekey(7, &prekey_public).unwrap();
        let result =
            Identity::verify_prekey_signature(&mallory_cert_bytes, 7, &prekey_public, &sig);
        assert!(
            result.is_err(),
            "Alice's signature must not verify against Mallory's cert"
        );
    }
}
