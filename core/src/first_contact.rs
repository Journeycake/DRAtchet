//! `FirstContactWire` — the wire shape for `docs/ARCHITECTURE.md` §6.4's
//! now-atomic, pairing-code-gated first contact (`MESSAGE_SCHEMA.md`
//! documents this in full). Distinct from every payload in `payload.rs`:
//! it travels *alongside* a ratchet envelope rather than *as* one, since
//! the recipient has no ratchet to decrypt anything with until this
//! message's cleartext fields let them derive one via `x3dh::respond`.
//!
//! Field split, deliberate: everything `x3dh::respond` needs, plus the
//! identity-binding signature (so the responder can verify the DH key is
//! genuinely bound to the claimed signing identity before trusting
//! anything derived from it — the same check `PrekeyBundle::verify` does
//! for a directory-fetched bundle), stays in the clear: the same public
//! key material a directory fetch already exposes. The pairing code and
//! the initiator's chosen username/discriminator travel *inside* the
//! ratchet-encrypted `envelope` instead (payload_type =
//! `payload::PAYLOAD_FIRST_CONTACT`), so a passive observer of the relay
//! never sees the pairing code.

use serde::{Deserialize, Serialize};
use x25519_dalek::PublicKey;

use crate::account::IDENTITY_DH_SIGNATURE_ID;
use crate::error::{Error, Result};
use crate::identity::Identity;
use crate::x3dh::X3dhInitMessage;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirstContactWire {
    #[serde(with = "serde_bytes")]
    pub initiator_identity_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub initiator_identity_dh_public: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub initiator_identity_dh_signature: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub initiator_ephemeral_public: Vec<u8>,
    pub used_signed_prekey_id: u32,
    pub used_one_time_prekey_id: Option<u32>,
    /// Ratchet-encrypted (via the root key `x3dh::respond` derives from
    /// the fields above), payload_type = `PAYLOAD_FIRST_CONTACT`, content
    /// = `payload::FirstContactContent`.
    #[serde(with = "serde_bytes")]
    pub envelope: Vec<u8>,
}

impl FirstContactWire {
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        ciborium::into_writer(self, &mut bytes)
            .expect("CBOR encoding of a well-formed struct cannot fail");
        bytes
    }

    /// Decode a `FirstContactWire` from mailbox entry bytes. Callers try
    /// `Envelope::decode` first — a normal ratchet envelope is a
    /// fixed-layout binary format, not CBOR, so the two shapes are
    /// reliably distinguishable.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ciborium::from_reader(bytes)
            .map_err(|_| Error::MalformedPayload("not a valid FirstContactWire"))
    }

    /// Verify `initiator_identity_dh_signature` binds
    /// `initiator_identity_dh_public` to `initiator_identity_key` — must
    /// pass before trusting anything derived from these fields.
    pub fn verify_identity_binding(&self) -> Result<()> {
        let dh_public: [u8; 32] = self
            .initiator_identity_dh_public
            .as_slice()
            .try_into()
            .map_err(|_| {
                Error::MalformedPayload("initiator_identity_dh_public must be 32 bytes")
            })?;
        Identity::verify_prekey_signature(
            &self.initiator_identity_key,
            IDENTITY_DH_SIGNATURE_ID,
            &dh_public,
            &self.initiator_identity_dh_signature,
        )
    }

    /// Recover the `X3dhInitMessage` shape `x3dh::respond` needs. Callers
    /// should call `verify_identity_binding` first.
    pub fn x3dh_init_message(&self) -> Result<X3dhInitMessage> {
        let identity_dh_public: [u8; 32] = self
            .initiator_identity_dh_public
            .as_slice()
            .try_into()
            .map_err(|_| {
                Error::MalformedPayload("initiator_identity_dh_public must be 32 bytes")
            })?;
        let ephemeral_public: [u8; 32] = self
            .initiator_ephemeral_public
            .as_slice()
            .try_into()
            .map_err(|_| Error::MalformedPayload("initiator_ephemeral_public must be 32 bytes"))?;
        Ok(X3dhInitMessage {
            initiator_identity_dh_public: PublicKey::from(identity_dh_public),
            initiator_ephemeral_public: PublicKey::from(ephemeral_public),
            used_signed_prekey_id: self.used_signed_prekey_id,
            used_one_time_prekey_id: self.used_one_time_prekey_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use rand_core::OsRng;
    use x25519_dalek::StaticSecret;

    fn sample_wire() -> (Identity, FirstContactWire) {
        let identity = Identity::generate().unwrap();
        let identity_dh_secret = StaticSecret::random_from_rng(OsRng);
        let identity_dh_public = PublicKey::from(&identity_dh_secret);
        let identity_dh_signature = identity
            .sign_prekey(IDENTITY_DH_SIGNATURE_ID, identity_dh_public.as_bytes())
            .unwrap();
        let ephemeral_secret = StaticSecret::random_from_rng(OsRng);
        let ephemeral_public = PublicKey::from(&ephemeral_secret);

        let wire = FirstContactWire {
            initiator_identity_key: identity.export_public_key().unwrap(),
            initiator_identity_dh_public: identity_dh_public.as_bytes().to_vec(),
            initiator_identity_dh_signature: identity_dh_signature,
            initiator_ephemeral_public: ephemeral_public.as_bytes().to_vec(),
            used_signed_prekey_id: 1,
            used_one_time_prekey_id: Some(7),
            envelope: vec![1, 2, 3],
        };
        (identity, wire)
    }

    #[test]
    fn round_trips_through_encode_and_decode() {
        let (_, wire) = sample_wire();
        let decoded = FirstContactWire::decode(&wire.encode()).unwrap();
        assert_eq!(decoded.initiator_identity_key, wire.initiator_identity_key);
        assert_eq!(decoded.envelope, wire.envelope);
        assert_eq!(
            decoded.used_one_time_prekey_id,
            wire.used_one_time_prekey_id
        );
    }

    #[test]
    fn a_genuine_identity_binding_verifies() {
        let (_, wire) = sample_wire();
        assert!(wire.verify_identity_binding().is_ok());
    }

    #[test]
    fn a_substituted_dh_key_fails_verification() {
        let (_, mut wire) = sample_wire();
        let other_secret = StaticSecret::random_from_rng(OsRng);
        wire.initiator_identity_dh_public = PublicKey::from(&other_secret).as_bytes().to_vec();
        assert!(wire.verify_identity_binding().is_err());
    }

    #[test]
    fn garbage_bytes_are_rejected_not_panicking() {
        assert!(FirstContactWire::decode(&[0xFF, 0x00, 0x01]).is_err());
    }
}
