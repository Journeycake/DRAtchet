//! Runs X3DH directly against a peer's [`PairingBundle`]/[`PairingResponse`]
//! — no server involved (`ARCHITECTURE.md` §6.3a) — and builds the
//! resulting [`RatchetState`]. Conversion between the wire shapes in
//! `pairing.rs` and `core::prekey`/`core::x3dh`'s typed values mirrors
//! `server/src/ws.rs::to_core_bundle`'s pattern for the same kind of
//! wire-to-core conversion.

use dratchet_core::account::Account;
use dratchet_core::identity;
use dratchet_core::prekey::{OneTimePrekeyPublic, PrekeyBundle, SignedPrekeyPublic};
use dratchet_core::ratchet::{RatchetState, DEFAULT_MAX_SKIP};
use dratchet_core::x3dh::{self, X3dhInitMessage};
use rand_core::{OsRng, RngCore};
use x25519_dalek::PublicKey;

use crate::pairing::{OneTimePrekeyWire, PairingBundle, PairingResponse};

fn parse_public_key(bytes: &[u8], what: &'static str) -> Result<PublicKey, String> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| format!("{what} must be 32 bytes"))?;
    Ok(PublicKey::from(arr))
}

fn to_core_bundle(bundle: &PairingBundle) -> Result<PrekeyBundle, String> {
    Ok(PrekeyBundle {
        identity_public_key: bundle.identity_key.clone(),
        identity_dh_public: parse_public_key(&bundle.identity_dh_public, "identity_dh_public")?,
        identity_dh_signature: bundle.identity_dh_signature.clone(),
        signed_prekey: SignedPrekeyPublic {
            id: bundle.signed_prekey_id,
            public: parse_public_key(&bundle.signed_prekey, "signed_prekey")?,
            signature: bundle.signed_prekey_sig.clone(),
        },
        one_time_prekey: bundle
            .one_time_prekey
            .as_ref()
            .map(|otp| -> Result<OneTimePrekeyPublic, String> {
                Ok(OneTimePrekeyPublic {
                    id: otp.id,
                    public: parse_public_key(&otp.key, "one_time_prekey.key")?,
                })
            })
            .transpose()?,
    })
}

pub fn random_routing_id() -> Vec<u8> {
    let mut buf = [0u8; 32];
    OsRng.fill_bytes(&mut buf);
    buf.to_vec()
}

/// Build the bundle a fresh identity shares first — the responder's half of
/// the exchange. `account` must already have exactly the one-time prekey
/// batch it's willing to offer generated (`Account::generate_one_time_prekeys`);
/// this takes the single one included via `publish_bundle(true)`.
pub fn build_pairing_bundle(
    account: &Account,
    routing_id: Vec<u8>,
) -> Result<PairingBundle, String> {
    let core_bundle = account.publish_bundle(true).map_err(|e| e.to_string())?;
    Ok(PairingBundle {
        identity_key: core_bundle.identity_public_key,
        identity_dh_public: core_bundle.identity_dh_public.as_bytes().to_vec(),
        identity_dh_signature: core_bundle.identity_dh_signature,
        signed_prekey_id: core_bundle.signed_prekey.id,
        signed_prekey: core_bundle.signed_prekey.public.as_bytes().to_vec(),
        signed_prekey_sig: core_bundle.signed_prekey.signature,
        one_time_prekey: core_bundle.one_time_prekey.map(|otp| OneTimePrekeyWire {
            id: otp.id,
            key: otp.public.as_bytes().to_vec(),
        }),
        routing_id,
    })
}

/// Run X3DH as the initiator against a peer's [`PairingBundle`], returning
/// the resulting ratchet (ready to send/receive immediately) and the
/// [`PairingResponse`] to share back so the peer can complete their side.
pub fn initiate(
    account: &Account,
    peer_bundle: &PairingBundle,
    my_routing_id: Vec<u8>,
) -> Result<(RatchetState, PairingResponse), String> {
    let core_bundle = to_core_bundle(peer_bundle)?;
    core_bundle.verify().map_err(|e| e.to_string())?;

    let result = x3dh::initiate(
        account.identity_dh_secret(),
        account.identity_dh_public,
        &core_bundle,
    )
    .map_err(|e| e.to_string())?;

    let my_fp = account.identity.fingerprint();
    let peer_fp = identity::fingerprint_of_public_key(&peer_bundle.identity_key);
    let conversation_id = dratchet_core::conversation_id(my_fp.as_bytes(), peer_fp.as_bytes());

    let ratchet = RatchetState::init_as_initiator(
        conversation_id,
        result.root_key,
        core_bundle.signed_prekey.public,
        DEFAULT_MAX_SKIP,
    )
    .map_err(|e| e.to_string())?;

    let identity_key = account
        .identity
        .export_public_key()
        .map_err(|e| e.to_string())?;
    let response = PairingResponse {
        identity_key,
        identity_dh_public: account.identity_dh_public.as_bytes().to_vec(),
        ephemeral_public: result
            .message
            .initiator_ephemeral_public
            .as_bytes()
            .to_vec(),
        used_signed_prekey_id: result.message.used_signed_prekey_id,
        used_one_time_prekey_id: result.message.used_one_time_prekey_id,
        routing_id: my_routing_id,
    };
    Ok((ratchet, response))
}

/// Complete the responder's side of X3DH once the initiator's
/// [`PairingResponse`] arrives, and build the matching ratchet.
/// `account` must be the same one whose bundle the initiator paired
/// against — its signed prekey secret becomes the ratchet's own starting
/// DH keypair, matching how the initiator's `init_as_initiator` used that
/// same signed prekey's public half.
pub fn respond(
    account: &mut Account,
    peer_response: &PairingResponse,
) -> Result<RatchetState, String> {
    let init_message = X3dhInitMessage {
        initiator_identity_dh_public: parse_public_key(
            &peer_response.identity_dh_public,
            "identity_dh_public",
        )?,
        initiator_ephemeral_public: parse_public_key(
            &peer_response.ephemeral_public,
            "ephemeral_public",
        )?,
        used_signed_prekey_id: peer_response.used_signed_prekey_id,
        used_one_time_prekey_id: peer_response.used_one_time_prekey_id,
    };

    let one_time_prekey_secret = peer_response
        .used_one_time_prekey_id
        .and_then(|id| account.take_one_time_prekey_secret(id));

    let root_key = x3dh::respond(
        account.identity_dh_secret(),
        account.signed_prekey_secret(),
        one_time_prekey_secret.as_ref(),
        &init_message,
    );

    let my_fp = account.identity.fingerprint();
    let peer_fp = identity::fingerprint_of_public_key(&peer_response.identity_key);
    let conversation_id = dratchet_core::conversation_id(my_fp.as_bytes(), peer_fp.as_bytes());

    RatchetState::init_as_responder(
        conversation_id,
        root_key,
        account.signed_prekey_secret().clone(),
        DEFAULT_MAX_SKIP,
    )
    .map_err(|e| e.to_string())
}
