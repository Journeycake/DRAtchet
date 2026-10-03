use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("AEAD encryption/decryption failed (tampered, wrong key, or corrupted envelope)")]
    Aead,

    #[error("envelope is malformed: {0}")]
    MalformedEnvelope(&'static str),

    #[error("skipped-message key cache would exceed MAX_SKIP ({0}); refusing to derive further")]
    MaxSkipExceeded(u32),

    #[error("max_skip {got} is out of the supported configurable range [{min}, {max}]")]
    InvalidMaxSkip { got: u32, min: u32, max: u32 },

    #[error("no matching message key found for this header (already used, or too old)")]
    UnknownMessageKey,

    #[error("ratchet has not been initialized for {0}")]
    RatchetNotInitialized(&'static str),

    #[error("signature verification failed")]
    InvalidSignature,

    #[error("payload is malformed: {0}")]
    MalformedPayload(&'static str),

    #[error("exported ratchet state is malformed: {0}")]
    MalformedExportedState(&'static str),

    /// DRA-0037: a Diffie-Hellman output carried no contribution from the
    /// private key, meaning the peer supplied a low-order X25519 point
    /// (RFC 7748's order-8 subgroup) — the resulting root key would be
    /// computable by anyone, so the handshake is refused outright.
    #[error("handshake rejected: peer supplied a low-order (non-contributory) public key")]
    NonContributoryHandshake,

    /// DRA-0042 (`docs/DELIVERY_FAILURE_FINDINGS.md`): the envelope's
    /// `conversation_id` names a different conversation than the ratchet
    /// asked to decrypt it. The sender chooses that field, so a session
    /// must never accept an envelope that claims to belong somewhere else.
    #[error("envelope rejected: its conversation_id is not this session's")]
    ConversationIdMismatch,
}

pub type Result<T> = std::result::Result<T, Error>;
