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
}

pub type Result<T> = std::result::Result<T, Error>;
