//! Message records, stored per conversation, with §11.5's disappearing-
//! message timer: a message with `expires_at` in the past is purged —
//! genuinely deleted, not just hidden — the moment anything looks at it,
//! via either `list_messages` (sweep-on-read) or the explicit
//! `sweep_expired_messages` (for a caller, e.g. the eventual Tauri shell,
//! to call periodically even when nothing is actively being viewed).

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::contacts::Contact;
use crate::db::{hex, Db, Scope};
use crate::error::{Error, Result};

#[derive(Clone, Serialize, Deserialize)]
pub struct Message {
    /// Random, not sequential — see `save_message`'s doc for why.
    #[serde(with = "serde_bytes")]
    pub id: Vec<u8>,
    pub sender_is_local: bool,
    #[serde(with = "serde_bytes")]
    pub content: Vec<u8>,
    /// Unix seconds.
    pub timestamp: u64,
    /// `None` = kept until manually deleted (§11.5's default). `Some(t)` =
    /// purged once `t` has passed.
    pub expires_at: Option<u64>,
}

/// Hand-written, not `#[derive(Debug)]`: `content` is plaintext message
/// text — printing it via `{:?}` would put chat content in a log file or
/// crash report. Every other field is harmless metadata.
impl fmt::Debug for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Message")
            .field("id", &hex(&self.id))
            .field("sender_is_local", &self.sender_is_local)
            .field(
                "content",
                &format!("<{} bytes redacted>", self.content.len()),
            )
            .field("timestamp", &self.timestamp)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

const MESSAGE_KEY_GLOBAL_PREFIX: &str = "message:";

fn message_key(conversation_id: [u8; 16], message_id: &[u8]) -> String {
    format!("message:{}:{}", hex(&conversation_id), hex(message_id))
}

pub(crate) fn message_key_prefix(conversation_id: [u8; 16]) -> String {
    format!("message:{}:", hex(&conversation_id))
}

pub(crate) fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after the Unix epoch")
        .as_secs()
}

fn is_expired(message: &Message, now: u64) -> bool {
    matches!(message.expires_at, Some(t) if t <= now)
}

impl Db {
    /// Store a message under a fresh random id (not a sequential counter —
    /// avoids needing a persisted per-conversation counter just to avoid
    /// key collisions; `list_messages` sorts by `timestamp` for display
    /// order, which is the property that actually matters).
    pub fn save_message(&self, conversation_id: [u8; 16], message: &Message) -> Result<()> {
        let mut bytes = Vec::new();
        ciborium::into_writer(message, &mut bytes)
            .expect("CBOR encoding of a well-formed struct cannot fail");
        tracing::debug!(
            conversation = %hex(&conversation_id),
            message_id = %hex(&message.id),
            "message saved",
        );
        self.put_encrypted(
            Scope::Content,
            &message_key(conversation_id, &message.id),
            &bytes,
        )
    }

    /// Build and store a new message, applying `contact`'s *current*
    /// `disappearing_timer_secs` (§11.5) — the convenience path a chat UI
    /// actually sends through, so a later change to the timer can never
    /// retroactively affect a message already saved under the old setting.
    pub fn save_message_now(
        &self,
        conversation_id: [u8; 16],
        contact: &Contact,
        content: Vec<u8>,
        sender_is_local: bool,
    ) -> Result<Message> {
        let now = now_unix();
        let message = Message {
            id: random_message_id(),
            sender_is_local,
            content,
            timestamp: now,
            expires_at: contact.disappearing_timer_secs.map(|secs| now + secs),
        };
        self.save_message(conversation_id, &message)?;
        Ok(message)
    }

    pub fn delete_message(&self, conversation_id: [u8; 16], message_id: &[u8]) -> Result<()> {
        self.delete(&message_key(conversation_id, message_id))
    }

    /// Every non-expired message stored for `conversation_id`, oldest
    /// first. Any message found expired while listing is purged on the
    /// spot (sweep-on-read), not merely omitted.
    pub fn list_messages(&self, conversation_id: [u8; 16]) -> Result<Vec<Message>> {
        let now = now_unix();
        let mut messages = Vec::new();
        for key in self.keys_with_prefix(&message_key_prefix(conversation_id))? {
            let bytes = self
                .get_encrypted(Scope::Content, &key)?
                .ok_or(Error::MalformedRecord("message key listed but not found"))?;
            let message = decode_message(&bytes)?;
            if is_expired(&message, now) {
                self.delete(&key)?;
            } else {
                messages.push(message);
            }
        }
        messages.sort_by_key(|m| m.timestamp);
        Ok(messages)
    }

    /// Purge every expired message across *all* conversations, returning
    /// how many were removed — for a caller to run periodically
    /// independent of whether any conversation is currently being viewed
    /// (`list_messages`'s sweep-on-read only reaches messages someone
    /// actually lists).
    pub fn sweep_expired_messages(&self) -> Result<usize> {
        let now = now_unix();
        let mut swept = 0;
        for key in self.keys_with_prefix(MESSAGE_KEY_GLOBAL_PREFIX)? {
            let Some(bytes) = self.get_encrypted(Scope::Content, &key)? else {
                continue;
            };
            let message = decode_message(&bytes)?;
            if is_expired(&message, now) {
                self.delete(&key)?;
                swept += 1;
            }
        }
        Ok(swept)
    }
}

fn random_message_id() -> Vec<u8> {
    use rand_core::{OsRng, RngCore};
    let mut buf = [0u8; 16];
    OsRng.fill_bytes(&mut buf);
    buf.to_vec()
}

fn decode_message(bytes: &[u8]) -> Result<Message> {
    ciborium::from_reader(bytes)
        .map_err(|_| Error::MalformedRecord("stored message is not valid CBOR for this shape"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;
    use rand_core::{OsRng, RngCore};

    fn temp_db() -> Db {
        let dir = tempfile::tempdir().unwrap().keep();
        Db::create(dir.join("test.redb"), "pw").unwrap()
    }

    fn random_id() -> Vec<u8> {
        let mut buf = [0u8; 16];
        OsRng.fill_bytes(&mut buf);
        buf.to_vec()
    }

    fn sample_message(timestamp: u64, content: &str) -> Message {
        Message {
            id: random_id(),
            sender_is_local: true,
            content: content.as_bytes().to_vec(),
            timestamp,
            expires_at: None,
        }
    }

    #[test]
    fn messages_debug_output_never_contains_the_plaintext_content() {
        let message = sample_message(100, "a secret only the recipient should read");
        let debug_output = format!("{message:?}");
        assert!(
            !debug_output.contains("secret"),
            "plaintext message content must never appear in Debug output: {debug_output}"
        );
    }

    #[test]
    fn save_and_list_returns_messages_in_timestamp_order() {
        let db = temp_db();
        let conv = [1u8; 16];

        // Saved deliberately out of chronological order.
        db.save_message(conv, &sample_message(300, "third"))
            .unwrap();
        db.save_message(conv, &sample_message(100, "first"))
            .unwrap();
        db.save_message(conv, &sample_message(200, "second"))
            .unwrap();

        let messages = db.list_messages(conv).unwrap();
        let contents: Vec<String> = messages
            .iter()
            .map(|m| String::from_utf8(m.content.clone()).unwrap())
            .collect();
        assert_eq!(contents, vec!["first", "second", "third"]);
    }

    #[test]
    fn messages_in_different_conversations_never_mix() {
        let db = temp_db();
        let conv_a = [1u8; 16];
        let conv_b = [2u8; 16];

        db.save_message(conv_a, &sample_message(100, "for a"))
            .unwrap();
        db.save_message(conv_b, &sample_message(100, "for b"))
            .unwrap();

        let a = db.list_messages(conv_a).unwrap();
        let b = db.list_messages(conv_b).unwrap();
        assert_eq!(a.len(), 1);
        assert_eq!(b.len(), 1);
        assert_eq!(String::from_utf8(a[0].content.clone()).unwrap(), "for a");
        assert_eq!(String::from_utf8(b[0].content.clone()).unwrap(), "for b");
    }

    #[test]
    fn delete_message_removes_only_that_message() {
        let db = temp_db();
        let conv = [1u8; 16];
        let keep = sample_message(100, "keep");
        let remove = sample_message(200, "remove");
        db.save_message(conv, &keep).unwrap();
        db.save_message(conv, &remove).unwrap();

        db.delete_message(conv, &remove.id).unwrap();

        let messages = db.list_messages(conv).unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].id, keep.id);
    }

    #[test]
    fn empty_conversation_returns_no_messages_not_an_error() {
        let db = temp_db();
        assert!(db.list_messages([9u8; 16]).unwrap().is_empty());
    }

    fn sample_contact(disappearing_timer_secs: Option<u64>) -> Contact {
        Contact {
            fingerprint: vec![1u8; 32],
            username: None,
            discriminator: None,
            verification_state: crate::contacts::VerificationState::Verified,
            mailbox_id: vec![0xAB; 16],
            created_at: now_unix(),
            disappearing_timer_secs,
            local_routing_id: vec![0xCD; 32],
            peer_routing_id: None,
            wipe_ask_before_delete: false,
            peer_wipe_ask_before_delete: None,
            wipe_include_session: false,
            peer_wipe_include_session: None,
            wipe_request_pending: false,
        }
    }

    /// A message whose timer has already passed must be gone — genuinely
    /// deleted, not merely hidden — the moment it's listed.
    #[test]
    fn list_messages_purges_an_already_expired_message_on_read() {
        let db = temp_db();
        let conv = [1u8; 16];
        let mut expired = sample_message(100, "expired");
        expired.expires_at = Some(now_unix() - 10);
        db.save_message(conv, &expired).unwrap();

        let messages = db.list_messages(conv).unwrap();
        assert!(
            messages.is_empty(),
            "an already-expired message must not be returned"
        );

        // And it's really gone, not just filtered — a raw fetch by key
        // finds nothing either.
        assert!(db
            .get_encrypted(Scope::Content, &message_key(conv, &expired.id))
            .unwrap()
            .is_none());
    }

    /// The mirror image: a message whose timer hasn't passed yet must
    /// survive being listed.
    #[test]
    fn list_messages_never_touches_a_not_yet_expired_message() {
        let db = temp_db();
        let conv = [1u8; 16];
        let mut not_yet = sample_message(100, "not yet");
        not_yet.expires_at = Some(now_unix() + 3600);
        db.save_message(conv, &not_yet).unwrap();

        let messages = db.list_messages(conv).unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].id, not_yet.id);
    }

    #[test]
    fn sweep_expired_messages_purges_across_conversations_and_reports_the_count() {
        let db = temp_db();
        let conv_a = [1u8; 16];
        let conv_b = [2u8; 16];

        let mut expired_a = sample_message(100, "expired a");
        expired_a.expires_at = Some(now_unix() - 10);
        let mut expired_b = sample_message(100, "expired b");
        expired_b.expires_at = Some(now_unix() - 10);
        let kept = sample_message(100, "kept");
        let mut not_yet = sample_message(100, "not yet");
        not_yet.expires_at = Some(now_unix() + 3600);

        db.save_message(conv_a, &expired_a).unwrap();
        db.save_message(conv_a, &kept).unwrap();
        db.save_message(conv_b, &expired_b).unwrap();
        db.save_message(conv_b, &not_yet).unwrap();

        let swept = db.sweep_expired_messages().unwrap();
        assert_eq!(swept, 2);

        let a = db.list_messages(conv_a).unwrap();
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].id, kept.id);
        let b = db.list_messages(conv_b).unwrap();
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].id, not_yet.id);
    }

    #[test]
    fn save_message_now_applies_the_contacts_current_timer() {
        let db = temp_db();
        let conv = [1u8; 16];
        let contact = sample_contact(Some(3600));

        let message = db
            .save_message_now(conv, &contact, b"hi".to_vec(), true)
            .unwrap();

        let expires_at = message.expires_at.expect("timer should have been applied");
        assert!(expires_at > now_unix(), "expiry should be in the future");
        assert!(
            expires_at <= now_unix() + 3600,
            "expiry should be roughly now + the contact's timer"
        );
    }

    /// Changing a conversation's timer must only affect messages saved
    /// *after* the change — never retroactively touch what's already
    /// there.
    #[test]
    fn changing_the_timer_does_not_retroactively_affect_existing_messages() {
        let db = temp_db();
        let conv = [1u8; 16];

        let no_timer_contact = sample_contact(None);
        let before = db
            .save_message_now(conv, &no_timer_contact, b"before".to_vec(), true)
            .unwrap();
        assert_eq!(before.expires_at, None);

        let timed_contact = sample_contact(Some(3600));
        let after = db
            .save_message_now(conv, &timed_contact, b"after".to_vec(), true)
            .unwrap();
        assert!(after.expires_at.is_some());

        // Re-fetching confirms the stored records themselves, not just the
        // in-memory return values, reflect this.
        let messages = db.list_messages(conv).unwrap();
        let before_stored = messages.iter().find(|m| m.id == before.id).unwrap();
        let after_stored = messages.iter().find(|m| m.id == after.id).unwrap();
        assert_eq!(before_stored.expires_at, None);
        assert!(after_stored.expires_at.is_some());
    }
}
