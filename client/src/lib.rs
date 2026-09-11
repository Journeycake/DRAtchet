//! DRAtchet reference CLI client — library surface, split out from
//! `main.rs` the same way `dratchet-server` splits its binary from its
//! testable internals, so `tests/` can drive a full two-party pairing and
//! chat exchange against a real, running server without going through
//! interactive stdio at all.

pub mod handshake;
pub mod net;
pub mod pairing;
