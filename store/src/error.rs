use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    // redb's own error types are each fairly large (its enums carry
    // formatted-context variants); boxed here so a single big variant
    // doesn't force every `Result<T, Error>` in this crate to be
    // oversized (clippy's `result_large_err`) — manual `From` impls below
    // keep `?` working directly against redb's own (unboxed) error types
    // at call sites, same ergonomics as `#[from]` would give.
    #[error("database error: {0}")]
    Database(Box<redb::DatabaseError>),

    #[error("database transaction error: {0}")]
    Transaction(Box<redb::TransactionError>),

    #[error("database table error: {0}")]
    Table(Box<redb::TableError>),

    #[error("database commit error: {0}")]
    Commit(Box<redb::CommitError>),

    #[error("database storage error: {0}")]
    Storage(Box<redb::StorageError>),

    #[error("wrong passphrase, or the database is corrupted")]
    WrongPassphraseOrCorrupted,

    #[error("passphrase hashing failed: {0}")]
    PassphraseHash(String),

    #[error("stored record is malformed: {0}")]
    MalformedRecord(&'static str),

    #[error("stored record failed to decrypt (corrupted or tampered)")]
    DecryptionFailed,

    /// §6.5's mandatory-verification gate: chat content cannot be sent to
    /// or released from a contact that isn't `Verified` yet. Distinct from
    /// `DecryptionFailed` — the ratchet decrypt itself succeeded; this is a
    /// policy refusal, not a cryptographic one.
    #[error("contact is not verified — chat content is blocked until §6.2's mandatory gate is satisfied")]
    NotVerified,

    #[error(transparent)]
    Core(#[from] dratchet_core::error::Error),
}

impl From<redb::DatabaseError> for Error {
    fn from(e: redb::DatabaseError) -> Self {
        Error::Database(Box::new(e))
    }
}

impl From<redb::TransactionError> for Error {
    fn from(e: redb::TransactionError) -> Self {
        Error::Transaction(Box::new(e))
    }
}

impl From<redb::TableError> for Error {
    fn from(e: redb::TableError) -> Self {
        Error::Table(Box::new(e))
    }
}

impl From<redb::CommitError> for Error {
    fn from(e: redb::CommitError) -> Self {
        Error::Commit(Box::new(e))
    }
}

impl From<redb::StorageError> for Error {
    fn from(e: redb::StorageError) -> Self {
        Error::Storage(Box::new(e))
    }
}

pub type Result<T> = std::result::Result<T, Error>;
