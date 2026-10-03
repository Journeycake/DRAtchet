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

/// Compute the fingerprint of a raw Ed25519 public key, given only the
/// public bytes — no private key required. A directory holding published
/// bundles (only ever public key material) needs this to index and look up
/// identities by fingerprint the same way an `Identity` computes its own.
pub fn fingerprint_of_public_key(public_key_bytes: &[u8]) -> Fingerprint {
    let digest = Sha256::digest(public_key_bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Fingerprint(out)
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
        fingerprint_of_public_key(self.signing_key.verifying_key().as_bytes())
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
        self.sign(&message)
    }

    /// Verify a prekey signature produced by [`Identity::sign_prekey`], given the
    /// signer's public key (as exported by [`Identity::export_public_key`]).
    pub fn verify_prekey_signature(
        signer_public_key_bytes: &[u8],
        prekey_id: u32,
        prekey_public: &[u8; 32],
        signature_bytes: &[u8],
    ) -> Result<()> {
        let message = prekey_signing_payload(prekey_id, prekey_public);
        verify_signature(signer_public_key_bytes, &message, signature_bytes)
    }

    /// Sign a Signaling & Presence Service connection-auth challenge
    /// (`SERVERS.md` §1.2).
    ///
    /// **DRA-0039 (`docs/DELIVERY_FAILURE_FINDINGS.md`), why this exists
    /// instead of calling [`Identity::sign`] on the nonce directly:** the
    /// nonce is chosen entirely by the *server*, which this project's own
    /// threat model treats as untrusted, and `AuthChallenge::nonce` is an
    /// unbounded `Vec<u8>`. Signing it verbatim made the client a signing
    /// oracle: a malicious relay could send a 36-byte "nonce" shaped
    /// exactly like [`prekey_signing_payload`]'s output and harvest a
    /// signature that verifies as a *prekey* signature under the victim's
    /// identity key. Both payloads are now domain-separated by a distinct,
    /// non-prefix-colliding tag, so a signature made for one context can
    /// never be replayed into the other.
    pub fn sign_auth_challenge(&self, nonce: &[u8]) -> Result<Vec<u8>> {
        self.sign(&auth_challenge_signing_payload(nonce))
    }

    /// Verify a signature produced by [`Identity::sign_auth_challenge`] —
    /// the server side of DRA-0039's domain separation.
    pub fn verify_auth_challenge_signature(
        signer_public_key_bytes: &[u8],
        nonce: &[u8],
        signature_bytes: &[u8],
    ) -> Result<()> {
        verify_signature(
            signer_public_key_bytes,
            &auth_challenge_signing_payload(nonce),
            signature_bytes,
        )
    }

    /// Sign an arbitrary message with this identity's key — the general-purpose
    /// primitive the domain-separated helpers above are built on.
    ///
    /// **Never call this on bytes a remote party chose.** Doing so turns
    /// this identity into a signing oracle for every other context that
    /// signs with the same key (DRA-0039). Use
    /// [`Identity::sign_auth_challenge`] or [`Identity::sign_prekey`],
    /// which prefix a context tag, instead.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let sig = self.signing_key.sign(message);
        Ok(sig.to_bytes().to_vec())
    }

    /// Export this identity's raw 32-byte Ed25519 secret key — the seed the
    /// full keypair (and so the public key/fingerprint) is deterministically
    /// derived from. Like `RatchetState::export`, **not an at-rest-safe
    /// format on its own**: local storage must encrypt this before
    /// persisting it and decrypt before calling
    /// [`Identity::from_secret_key`].
    pub fn export_secret_key(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// The inverse of [`Identity::export_secret_key`].
    pub fn from_secret_key(secret_key: [u8; 32]) -> Self {
        Identity {
            signing_key: SigningKey::from_bytes(&secret_key),
        }
    }
}

/// Verify an arbitrary Ed25519 signature against a raw 32-byte public key —
/// the general-purpose primitive [`Identity::verify_prekey_signature`] is
/// built on top of. Free function, not tied to an `Identity` instance, since
/// verifying doesn't require holding any key material of one's own.
pub fn verify_signature(
    public_key_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<()> {
    let public_key_array: [u8; 32] = public_key_bytes
        .try_into()
        .map_err(|_| Error::InvalidSignature)?;
    let verifying_key =
        VerifyingKey::from_bytes(&public_key_array).map_err(|_| Error::InvalidSignature)?;
    let signature = Signature::from_slice(signature_bytes).map_err(|_| Error::InvalidSignature)?;
    verifying_key
        .verify(message, &signature)
        .map_err(|_| Error::InvalidSignature)
}

/// DRA-0039: the context tag that makes a prekey signature unusable in any
/// other signing context. Neither this nor [`AUTH_CHALLENGE_DOMAIN_TAG`] is
/// a prefix of the other, so no payload built with one can ever collide
/// with a payload built with the other, whatever the caller-supplied bytes
/// are.
const PREKEY_DOMAIN_TAG: &[u8] = b"dratchet-prekey-signature-v1";
/// DRA-0039: the matching tag for connection-auth challenges.
const AUTH_CHALLENGE_DOMAIN_TAG: &[u8] = b"dratchet-auth-challenge-v1";

fn prekey_signing_payload(prekey_id: u32, prekey_public: &[u8; 32]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(PREKEY_DOMAIN_TAG.len() + 4 + 32);
    msg.extend_from_slice(PREKEY_DOMAIN_TAG);
    msg.extend_from_slice(&prekey_id.to_be_bytes());
    msg.extend_from_slice(prekey_public);
    msg
}

fn auth_challenge_signing_payload(nonce: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(AUTH_CHALLENGE_DOMAIN_TAG.len() + nonce.len());
    msg.extend_from_slice(AUTH_CHALLENGE_DOMAIN_TAG);
    msg.extend_from_slice(nonce);
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
    fn secret_key_export_then_import_reconstructs_the_same_identity() {
        let id = Identity::generate().unwrap();
        let restored = Identity::from_secret_key(id.export_secret_key());

        assert_eq!(restored.fingerprint(), id.fingerprint());
        assert_eq!(
            restored.export_public_key().unwrap(),
            id.export_public_key().unwrap()
        );

        // And it can actually still sign/verify, not just report the same
        // fingerprint.
        let prekey_public = [9u8; 32];
        let sig = restored.sign_prekey(1, &prekey_public).unwrap();
        Identity::verify_prekey_signature(
            &id.export_public_key().unwrap(),
            1,
            &prekey_public,
            &sig,
        )
        .expect(
            "a signature from the restored identity must verify against the original's public key",
        );
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

    /// Penetration-test finding DRA-0039, the core property: a signature
    /// the client produced for the *connection-auth* context must never
    /// verify as a *prekey* signature.
    ///
    /// The attack this closes: `AuthChallenge::nonce` is an unbounded
    /// `Vec<u8>` chosen entirely by the server, which this project's threat
    /// model treats as untrusted, and the client used to sign it verbatim.
    /// A malicious relay sends a 36-byte "nonce" shaped exactly like a
    /// prekey signing payload (`prekey_id ‖ prekey_public`), harvests the
    /// reply, and now holds a valid prekey signature under the victim's
    /// identity key — enough to publish a bundle in the victim's name
    /// carrying the *attacker's* keys, which the directory accepts as an
    /// ordinary rotation because the fingerprint still matches.
    #[test]
    fn an_auth_challenge_signature_can_never_be_replayed_as_a_prekey_signature() {
        let identity = Identity::generate().unwrap();
        let public_key = identity.export_public_key().unwrap();

        // The attacker's own X25519 key, and the prekey id they want it
        // bound to.
        let attacker_prekey_public = [0x42u8; 32];
        let target_prekey_id: u32 = 1;

        // A malicious server's "nonce": byte-for-byte a prekey signing
        // payload, as the pre-fix code would have built it.
        let mut malicious_nonce = Vec::new();
        malicious_nonce.extend_from_slice(&target_prekey_id.to_be_bytes());
        malicious_nonce.extend_from_slice(&attacker_prekey_public);

        let harvested = identity.sign_auth_challenge(&malicious_nonce).unwrap();

        assert!(
            Identity::verify_prekey_signature(
                &public_key,
                target_prekey_id,
                &attacker_prekey_public,
                &harvested,
            )
            .is_err(),
            "VULNERABILITY: a signature harvested from the connection-auth handshake verified as \
             a prekey signature under this identity -- a malicious relay can mint prekey \
             signatures for attacker-controlled keys and take over the victim's directory entry"
        );
    }

    /// DRA-0039, the mirror property: a genuine prekey signature must not
    /// be accepted as proof of a connection-auth challenge either.
    #[test]
    fn a_prekey_signature_can_never_be_replayed_as_an_auth_challenge_signature() {
        let identity = Identity::generate().unwrap();
        let public_key = identity.export_public_key().unwrap();
        let prekey_public = [9u8; 32];
        let prekey_id: u32 = 3;

        let prekey_signature = identity.sign_prekey(prekey_id, &prekey_public).unwrap();

        let mut nonce_the_server_would_have_issued = Vec::new();
        nonce_the_server_would_have_issued.extend_from_slice(&prekey_id.to_be_bytes());
        nonce_the_server_would_have_issued.extend_from_slice(&prekey_public);

        assert!(
            Identity::verify_auth_challenge_signature(
                &public_key,
                &nonce_the_server_would_have_issued,
                &prekey_signature,
            )
            .is_err(),
            "VULNERABILITY: a prekey signature authenticated a connection as this identity"
        );
    }

    /// The fix must not be overly strict: both domain-separated paths must
    /// still verify their own genuine signatures.
    #[test]
    fn both_domain_separated_paths_still_verify_their_own_signatures() {
        let identity = Identity::generate().unwrap();
        let public_key = identity.export_public_key().unwrap();

        let prekey_public = [5u8; 32];
        let prekey_signature = identity.sign_prekey(11, &prekey_public).unwrap();
        assert!(Identity::verify_prekey_signature(
            &public_key,
            11,
            &prekey_public,
            &prekey_signature
        )
        .is_ok());

        let nonce = [7u8; 32];
        let auth_signature = identity.sign_auth_challenge(&nonce).unwrap();
        assert!(
            Identity::verify_auth_challenge_signature(&public_key, &nonce, &auth_signature).is_ok()
        );
    }
}
