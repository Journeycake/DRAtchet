//! A narrow, ASCII-only character-set floor for `username#NNNN` handles,
//! shared by every place one gets accepted from an untrusted party —
//! `server/src/ws.rs`'s `publish_bundle` (a fresh directory registration)
//! and `store/src/profile.rs`'s `record_peer_profile` (a peer announcing
//! their own handle directly, `PAYLOAD_PROFILE_ANNOUNCE`). Single source
//! of truth so the two enforcement points can't drift apart.
//!
//! DRA-0024/DRA-0025 (`docs/DELIVERY_FAILURE_FINDINGS.md`): without this,
//! a Unicode homograph (e.g. Cyrillic `а`, U+0430, standing in for Latin
//! `a`) is visually indistinguishable from the real character in
//! essentially every font, letting one identity impersonate another's
//! `username#NNNN` display. Deliberately narrow rather than a full
//! Unicode confusables-skeleton solution (real feature work, not a
//! bounded fix) — this closes the specific homograph attack outright for
//! the ASCII case, at the accepted cost of non-ASCII handles not being
//! supported at all.
/// The hard ceiling on a `username`'s length, in bytes, shared by the
/// same two enforcement points as [`has_only_allowed_characters`].
///
/// DRA-0043 (`docs/DELIVERY_FAILURE_FINDINGS.md`): DRA-0019 put this cap
/// on the directory-registration path (`server::ws::publish_bundle`) but
/// not on the peer-to-peer one, so a contact could announce a handle
/// bounded only by the transport's 1 MiB frame cap and have it persisted
/// into their contact record and rendered in the UI. The character
/// allowlist above does not help: a megabyte of `a` is entirely
/// well-formed ASCII.
pub const MAX_LEN: usize = 64;

/// The full floor a username from an untrusted party must clear: within
/// [`MAX_LEN`] *and* drawn only from the allowed characters. Prefer this
/// over calling either check alone.
pub fn is_acceptable(username: &str) -> bool {
    username.len() <= MAX_LEN && has_only_allowed_characters(username)
}

pub fn has_only_allowed_characters(username: &str) -> bool {
    !username.is_empty()
        && username
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ordinary_ascii_handles() {
        assert!(has_only_allowed_characters("alice"));
        assert!(has_only_allowed_characters("real_user-42"));
    }

    #[test]
    fn is_acceptable_rejects_an_overlong_but_otherwise_well_formed_handle() {
        let long = "a".repeat(MAX_LEN + 1);
        assert!(
            has_only_allowed_characters(&long),
            "sanity check: it clears the character allowlist on its own"
        );
        assert!(!is_acceptable(&long));
        assert!(is_acceptable(&"a".repeat(MAX_LEN)));
    }

    #[test]
    fn rejects_empty_and_non_ascii() {
        assert!(!has_only_allowed_characters(""));
        assert!(!has_only_allowed_characters("\u{0430}lice")); // Cyrillic а
    }
}
