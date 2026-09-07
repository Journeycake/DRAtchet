//! Out-of-band pairing exchange — Option B (`docs/ARCHITECTURE.md` §6.3a):
//! the X3DH handshake happens directly between the two clients, never
//! touching the server, and the server is used only for temporary Tier 1
//! mailbox queueing addressed by a routing id neither identity is ever
//! registered under.
//!
//! For this reference CLI client, the QR code `ARCHITECTURE.md` §6.3a
//! describes is stood in for by a base64-encoded CBOR blob the user copies
//! and pastes into their peer's terminal — real QR rendering/scanning
//! belongs to the eventual Tauri UI, but the *data format* below is the
//! real thing, not a placeholder.
//!
//! Two blobs, exchanged in order:
//!
//! 1. [`PairingBundle`] — whoever generates one first (arbitrarily, "the
//!    responder" in X3DH terms) shares this. Shaped like
//!    `dratchet_server::protocol::FetchedBundleWire` (the directory's
//!    fetch-response shape) but deliberately a separate type: this one is
//!    exchanged directly between clients and never touches
//!    `PublishBundle`/the directory at all.
//! 2. [`PairingResponse`] — the other side ("the initiator") runs X3DH
//!    against the bundle above and shares this back, so the responder can
//!    complete their half of the handshake and land on the same root key.
//!
//! Both carry a fresh, single-use **routing id** — never the long-term
//! identity fingerprint (`ARCHITECTURE.md` §6.3a explains why: so the
//! relay can never correlate this conversation's traffic with either
//! party's long-term identity or any other conversation they have). The
//! Tier 1 `mailbox_id` for the whole pairing is
//! `dratchet_core::conversation_id(routing_id_a, routing_id_b)` — the same
//! sorted-hash function already used for the ratchet's own (identity-
//! keyed, and never sent to the server) `conversation_id`, reused here for
//! a different pair of inputs.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OneTimePrekeyWire {
    pub id: u32,
    #[serde(with = "serde_bytes")]
    pub key: Vec<u8>,
}

/// Shared first by whoever generates a pairing exchange — carries
/// everything the other side needs to run X3DH as the initiator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingBundle {
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
    pub one_time_prekey: Option<OneTimePrekeyWire>,
    /// Fresh, single-use, never the identity fingerprint — see the module
    /// doc above.
    #[serde(with = "serde_bytes")]
    pub routing_id: Vec<u8>,
}

/// Shared back by whoever received a [`PairingBundle`] and ran X3DH against
/// it — everything the original bundle's owner needs to complete their side
/// of the handshake (`core::x3dh::respond`) and derive the same root key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingResponse {
    #[serde(with = "serde_bytes")]
    pub identity_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub identity_dh_public: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub ephemeral_public: Vec<u8>,
    pub used_signed_prekey_id: u32,
    pub used_one_time_prekey_id: Option<u32>,
    #[serde(with = "serde_bytes")]
    pub routing_id: Vec<u8>,
}

/// CBOR-encode, then base64-encode, for copy-paste — the stand-in for
/// rendering a QR code.
pub fn encode_blob<T: Serialize>(value: &T) -> String {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)
        .expect("CBOR encoding of a well-formed struct cannot fail");
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes)
}

/// The inverse of [`encode_blob`] — the stand-in for scanning a QR code.
pub fn decode_blob<T: for<'de> Deserialize<'de>>(text: &str) -> Result<T, String> {
    let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, text.trim())
        .map_err(|e| format!("not valid base64: {e}"))?;
    ciborium::from_reader(bytes.as_slice()).map_err(|e| format!("not a valid pairing blob: {e}"))
}
