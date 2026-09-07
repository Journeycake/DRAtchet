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

pub use contacts::{Contact, VerificationState};
pub use db::Db;
pub use error::{Error, Result};
pub use gate::{decrypt_gated, encrypt_gated};
pub use messages::Message;
