use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("malformed frame: {0}")]
    MalformedFrame(&'static str),

    #[error("authentication required for this operation")]
    AuthRequired,

    #[error("authentication failed")]
    AuthFailed,

    #[error("connection is already authenticated")]
    AlreadyAuthenticated,

    #[error("bundle is not internally consistent: {0}")]
    InvalidBundle(&'static str),

    #[error("username is already registered to a different identity")]
    UsernameTaken,

    #[error("registering a new username requires a valid proof-of-work solution")]
    ProofOfWorkRequired,

    #[error("rate limit exceeded for this target, try again shortly")]
    RateLimited,

    #[error("not found")]
    NotFound,

    /// A `MailboxFetch`/`MailboxDelete` named a mailbox id that matches
    /// another registered identity's bootstrap mailbox
    /// (`dratchet_core::x3dh::bootstrap_mailbox_id`) — deliberately a
    /// deterministic hash of a public fingerprint, so the intended
    /// recipient's own client can compute it before any relationship
    /// exists, but that also means anyone who knows the target's
    /// fingerprint can compute the same id. Read/delete access to a
    /// bootstrap mailbox is restricted to the identity it actually
    /// belongs to; write access (first-contact delivery) is intentionally
    /// unrestricted (docs/DELIVERY_FAILURE_FINDINGS.md, DRA-0014).
    #[error("this mailbox belongs to a different identity")]
    NotMailboxOwner,

    /// DRA-0015 (`docs/DELIVERY_FAILURE_FINDINGS.md`) — the envelope on a
    /// `MailboxWrite` exceeded `state::MAX_ENVELOPE_LEN`.
    #[error("envelope exceeds the maximum allowed size")]
    EnvelopeTooLarge,

    /// DRA-0015 — the target mailbox already holds `state::MAX_MAILBOX_ENTRIES`
    /// unexpired entries.
    #[error("mailbox is full, try again once existing entries are collected")]
    MailboxFull,
}

pub type Result<T> = std::result::Result<T, Error>;
