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

    /// DRA-0017 — the caller has already written
    /// `state::MAX_ENTRIES_PER_WRITER_PER_MAILBOX` unexpired entries of
    /// their own into this mailbox. Distinct from `MailboxFull` (the
    /// mailbox as a whole is at capacity) so a client can tell "the other
    /// side is flooding, not me" apart from an ordinary full mailbox.
    #[error("you have already written your share of this mailbox's capacity")]
    WriterQuotaExceeded,

    /// DRA-0018 — the caller has exhausted their
    /// `crate::abuse::NewMailboxRateLimiter` budget for originating
    /// brand-new mailbox ids; try again shortly.
    #[error("rate limit exceeded for creating new mailboxes, try again shortly")]
    NewMailboxRateLimited,

    /// DRA-0019 — `PublishBundle.one_time_prekeys` exceeded
    /// `state::MAX_ONE_TIME_PREKEYS_PER_PUBLISH`.
    #[error("too many one-time prekeys in a single publish")]
    TooManyOneTimePrekeys,

    /// DRA-0019 — `PublishBundle.username` exceeded `state::MAX_USERNAME_LEN`.
    #[error("username exceeds the maximum allowed length")]
    UsernameTooLong,

    /// DRA-0024 (`docs/DELIVERY_FAILURE_FINDINGS.md`) — `PublishBundle.username`
    /// contained a character outside `state::USERNAME_ALLOWED_CHARS`, or was
    /// empty. A narrow, ASCII-only floor against Unicode homograph/confusables
    /// impersonation (e.g. Cyrillic `а` standing in for Latin `a`), the same
    /// "deliberately modest, a floor not a wall" spirit as the registration
    /// proof-of-work.
    #[error("username may only contain ASCII letters, digits, '_', and '-'")]
    UsernameInvalidCharacters,

    /// DRA-0026 (`docs/DELIVERY_FAILURE_FINDINGS.md`) — a `RendezvousOffer`/
    /// `RendezvousAnswer`'s `sdp_offer`/`sdp_answer` exceeded `state::MAX_SDP_LEN`.
    #[error("SDP payload exceeds the maximum allowed length")]
    SdpTooLarge,

    /// DRA-0026 — a `RendezvousOffer`/`RendezvousAnswer` carried more ICE
    /// candidates than `state::MAX_ICE_CANDIDATES`, or one exceeding
    /// `state::MAX_ICE_CANDIDATE_LEN`.
    #[error("too many or too large ICE candidates")]
    IceCandidatesInvalid,
}

pub type Result<T> = std::result::Result<T, Error>;
