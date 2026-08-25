use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("AEAD encryption/decryption failed (tampered, wrong key, or corrupted envelope)")]
    Aead,

    #[error("envelope is malformed: {0}")]
    MalformedEnvelope(&'static str),

    #[error("skipped-message key cache would exceed MAX_SKIP ({0}); refusing to derive further")]
    MaxSkipExceeded(u32),

    #[error("no matching message key found for this header (already used, or too old)")]
    UnknownMessageKey,

    #[error("ratchet has not been initialized for {0}")]
    RatchetNotInitialized(&'static str),

    #[error("OpenPGP identity operation failed: {0}")]
    OpenPgp(#[from] anyhow::Error),

    #[error("prekey signature verification failed")]
    InvalidPrekeySignature,

    #[error("payload is malformed: {0}")]
    MalformedPayload(&'static str),
}

pub type Result<T> = std::result::Result<T, Error>;
