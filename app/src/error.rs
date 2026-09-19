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

    /// `publish_own_bundle`/`rename_own_profile`: the chosen `username#NNNN`
    /// is already registered to a different identity. Callers retry with a
    /// fresh discriminator up to a small attempt limit before surfacing
    /// this.
    #[error("that username is already taken")]
    UsernameTaken,

    /// `add_contact_by_username`: no account is registered under the given
    /// `username#NNNN`.
    #[error("no account is registered under that username")]
    NoSuchAccount,

    /// `add_contact_by_username` (DRA-0040,
    /// `docs/DELIVERY_FAILURE_FINDINGS.md`): the fetched bundle's signed
    /// prekey is past its published expiry, so the directory is serving a
    /// key its owner has already rotated away from.
    #[error("that account's published signed prekey has expired")]
    SignedPrekeyExpired,

    /// `confirm_pending_wipe` (DRA-0020,
    /// `docs/DELIVERY_FAILURE_FINDINGS.md`): the contact reloaded fresh
    /// from `db` doesn't actually have `wipe_request_pending` set — either
    /// it never was, or it was already resolved (confirmed, declined, or
    /// superseded) by the time this ran. Refuses to wipe rather than
    /// trusting the caller's claim that a request is pending.
    #[error("no wipe request is actually pending for this contact")]
    NoPendingWipeRequest,

    #[error("filesystem error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<String> for Error {
    fn from(e: String) -> Self {
        Error::Connection(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
