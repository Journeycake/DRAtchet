//! This device's local preference for how much a new-message OS
//! notification is allowed to reveal (`docs/ARCHITECTURE.md` §11.10) —
//! purely a display choice, never sent anywhere or negotiated with a
//! peer, since it only governs what *this* device's own notification
//! tray shows. Defaults to the most private level rather than the most
//! informative one, matching this project's general posture of not
//! surfacing metadata unless the user opts in.

use serde::{Deserialize, Serialize};

use crate::db::{Db, Scope};
use crate::error::{Error, Result};

const NOTIFICATION_PREVIEW_LEVEL_KEY: &str = "notification_preview_level";

/// How much a new-message notification shows, from least to most
/// revealing. Mirrors the shape of a native Messages app's own
/// "Show Previews" setting, minus the lock-state-aware "when unlocked"
/// tier — Tauri has no portable way to observe OS lock state across
/// Windows/macOS/Linux, so this is a plain, always-applied choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum NotificationPreviewLevel {
    /// "New message" — no sender, no content. The default.
    #[default]
    None,
    /// The sender's `username#NNNN`, no message content.
    HandleOnly,
    /// The sender's handle plus the message content (or, for more than
    /// one new message from the same sender in one notification, a
    /// count rather than concatenated content).
    HandleAndMessage,
}

impl Db {
    pub fn save_notification_preview_level(&self, level: NotificationPreviewLevel) -> Result<()> {
        let mut bytes = Vec::new();
        ciborium::into_writer(&level, &mut bytes)
            .expect("CBOR encoding of a well-formed enum cannot fail");
        self.put_encrypted(Scope::Identity, NOTIFICATION_PREVIEW_LEVEL_KEY, &bytes)
    }

    /// The saved level, or [`NotificationPreviewLevel::None`] if nothing
    /// has been saved yet — the private default, not an error.
    pub fn load_notification_preview_level(&self) -> Result<NotificationPreviewLevel> {
        match self.get_encrypted(Scope::Identity, NOTIFICATION_PREVIEW_LEVEL_KEY)? {
            Some(bytes) => ciborium::from_reader(bytes.as_slice()).map_err(|_| {
                Error::MalformedRecord(
                    "stored notification preview level is not valid CBOR for this shape",
                )
            }),
            None => Ok(NotificationPreviewLevel::default()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_db() -> Db {
        let dir = tempfile::tempdir().unwrap().keep();
        Db::create(dir.join("test.redb"), "pw").unwrap()
    }

    #[test]
    fn defaults_to_the_most_private_level_before_anything_is_saved() {
        let db = temp_db();
        assert_eq!(
            db.load_notification_preview_level().unwrap(),
            NotificationPreviewLevel::None
        );
    }

    #[test]
    fn save_then_load_round_trips_every_level() {
        let db = temp_db();
        for level in [
            NotificationPreviewLevel::None,
            NotificationPreviewLevel::HandleOnly,
            NotificationPreviewLevel::HandleAndMessage,
        ] {
            db.save_notification_preview_level(level).unwrap();
            assert_eq!(db.load_notification_preview_level().unwrap(), level);
        }
    }

    #[test]
    fn saving_again_overwrites_the_previous_level() {
        let db = temp_db();
        db.save_notification_preview_level(NotificationPreviewLevel::HandleAndMessage)
            .unwrap();
        db.save_notification_preview_level(NotificationPreviewLevel::None)
            .unwrap();
        assert_eq!(
            db.load_notification_preview_level().unwrap(),
            NotificationPreviewLevel::None
        );
    }
}
