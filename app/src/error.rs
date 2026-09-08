#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Store(#[from] dratchet_store::Error),

    #[error(transparent)]
    Core(#[from] dratchet_core::error::Error),

    /// `dratchet_client::net::Connection`'s methods return `Result<_,
    /// String>` rather than a typed error — wrapped here so callers of
    /// this crate only ever see one error type.
    #[error("connection error: {0}")]
    Connection(String),

    #[error("no ratchet session exists yet for this contact")]
    NoSession,

    #[error("the server did not acknowledge the request")]
    NotAcknowledged,

    #[error("filesystem error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<String> for Error {
    fn from(e: String) -> Self {
        Error::Connection(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
