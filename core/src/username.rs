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
    fn rejects_empty_and_non_ascii() {
        assert!(!has_only_allowed_characters(""));
        assert!(!has_only_allowed_characters("\u{0430}lice")); // Cyrillic а
    }
}
