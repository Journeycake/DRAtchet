//! DRAtchet local encrypted storage (`docs/ARCHITECTURE.md` §5, Phase 1.5) —
//! accounts, contacts, ratchet sessions, and messages, persisted in `redb`
//! (a pure-Rust embedded database) with every value encrypted at rest via
//! `chacha20poly1305`. Deliberately not SQLCipher: the whole workspace has
//! stayed pure Rust with zero native/C dependencies since dropping
//! OpenPGP/sequoia earlier in the project, and SQLCipher would reintroduce
//! exactly that.

pub mod error;

mod contacts;
mod db;
mod gate;
mod messages;
mod routing;
pub mod sweep;
mod verification;

pub use contacts::{Contact, VerificationState};
pub use db::Db;
pub use error::{Error, Result};
pub use gate::{decrypt_gated, encrypt_gated};
pub use messages::Message;
pub use routing::compute_mailbox_id;
pub use sweep::spawn_periodic_sweep;
pub use verification::{
    PairingCode, QrVerificationPayload, PAIRING_CODE_MAX_ATTEMPTS, PAIRING_CODE_TTL_SECS,
    QR_VALIDITY_SECS,
};
