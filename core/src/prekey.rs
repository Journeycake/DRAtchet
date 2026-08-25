//! Prekey bundle, per `docs/ARCHITECTURE.md` §3.2 and `docs/MESSAGE_SCHEMA.md` §1.

use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::identity::Identity;

/// A signed prekey, kept by its owner alongside the secret half needed to respond
/// to an X3DH handshake. Rotated periodically in the full design; v0 just models
/// the keypair + signature, not the rotation schedule.
pub struct SignedPrekey {
    pub id: u32,
    pub secret: StaticSecret,
    pub public: PublicKey,
    /// Detached OpenPGP signature over `(id, public)`, by the owning identity.
    pub signature: Vec<u8>,
}

impl SignedPrekey {
    pub fn generate(id: u32, identity: &Identity) -> crate::error::Result<Self> {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        let signature = identity.sign_prekey(id, public.as_bytes())?;
        Ok(SignedPrekey {
            id,
            secret,
            public,
            signature,
        })
    }

    pub fn public_bundle_entry(&self) -> SignedPrekeyPublic {
        SignedPrekeyPublic {
            id: self.id,
            public: self.public,
            signature: self.signature.clone(),
        }
    }
}

#[derive(Clone)]
pub struct SignedPrekeyPublic {
    pub id: u32,
    pub public: PublicKey,
    pub signature: Vec<u8>,
}

/// A one-time prekey: generated in bulk, handed out once per new session, then
/// discarded — the genuinely single-use, discard-after-use keypair in the system
/// (`docs/ARCHITECTURE.md` §3.4).
pub struct OneTimePrekey {
    pub id: u32,
    pub secret: StaticSecret,
    pub public: PublicKey,
}

impl OneTimePrekey {
    pub fn generate(id: u32) -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        OneTimePrekey { id, secret, public }
    }

    pub fn public_bundle_entry(&self) -> OneTimePrekeyPublic {
        OneTimePrekeyPublic {
            id: self.id,
            public: self.public,
        }
    }
}

#[derive(Clone, Copy)]
pub struct OneTimePrekeyPublic {
    pub id: u32,
    pub public: PublicKey,
}

/// What a client fetches from the directory to start a new session with someone,
/// per `docs/MESSAGE_SCHEMA.md` §1. `identity_dh_public` is the long-term X3DH
/// identity DH key (separate from the OpenPGP signing identity — see `identity.rs`).
pub struct PrekeyBundle {
    pub identity_cert_bytes: Vec<u8>,
    pub identity_dh_public: PublicKey,
    pub identity_dh_signature: Vec<u8>,
    pub signed_prekey: SignedPrekeyPublic,
    pub one_time_prekey: Option<OneTimePrekeyPublic>,
}

impl PrekeyBundle {
    /// Verify the signed prekey's signature (and, if present, the identity DH key's own
    /// signature) against the bundled certificate before trusting anything in it.
    pub fn verify(&self) -> crate::error::Result<()> {
        Identity::verify_prekey_signature(
            &self.identity_cert_bytes,
            crate::account::IDENTITY_DH_SIGNATURE_ID,
            self.identity_dh_public.as_bytes(),
            &self.identity_dh_signature,
        )?;
        Identity::verify_prekey_signature(
            &self.identity_cert_bytes,
            self.signed_prekey.id,
            self.signed_prekey.public.as_bytes(),
            &self.signed_prekey.signature,
        )
    }
}
