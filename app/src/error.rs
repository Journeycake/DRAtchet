#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Store(#[from] dratchet_store::Error),

    #[error(transparent)]
    Core(#[from] dratchet_core::error::Error),

    /// The transport to the server failed: couldn't connect, a send
    /// failed, or the socket errored or closed. DRA-0058: this means *only*
    /// that -- it's what a caller should reconnect on.
    #[error("connection error: {0}")]
    Connection(String),

    /// DRA-0058: the server received a request and refused it, for the
    /// reason in `code` (e.g. rate limited, not the mailbox owner). The
    /// connection is fine and should be kept.
    #[error("server refused the request: {message}")]
    ServerRefused {
        code: dratchet_server::protocol::ErrorCode,
        message: String,
    },

    /// DRA-0058: a malformed or unexpected frame or bundle, or a failed
    /// handshake/pairing step -- a problem with this one exchange, not
    /// with the connection.
    #[error("protocol error: {0}")]
    Protocol(String),

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

/// DRA-0058: keeps the client's three kinds of failure apart.
impl From<dratchet_client::net::NetError> for Error {
    fn from(e: dratchet_client::net::NetError) -> Self {
        use dratchet_client::net::NetError;
        match e {
            NetError::Connection(msg) => Error::Connection(msg),
            NetError::Refused { code, message } => Error::ServerRefused { code, message },
            NetError::Protocol(msg) => Error::Protocol(msg),
        }
    }
}

/// The remaining `String` errors come from `dratchet_client::handshake`
/// and `::pairing` (key parsing, signature checks), which never touch the
/// network. DRA-0058: these used to become `Connection`, so a failed
/// pairing also looked like a dropped connection.
impl From<String> for Error {
    fn from(e: String) -> Self {
        Error::Protocol(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
