//! Message records, stored per conversation. There is no time-based
//! expiry here — deletion is exclusively user-triggered, via
//! `Db::delete_message`/`Db::wipe_conversation` (`ARCHITECTURE.md`
//! §11.9a's per-conversation purge/emergency-purge pair), never a
//! background timer. (An earlier per-conversation disappearing-message
//! timer lived here; removed because it contradicted that decision — see
//! §11.5's current text.)

use std::fmt;
use std::sync::atomic::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

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
    /// Unix seconds — coarse, and *not* on its own enough to order
    /// messages for display (see `sequence`): plenty of real usage sends
    /// several messages within the same second, and `list_messages`'
    /// tie-break without a second key would otherwise fall back to
    /// `keys_with_prefix`'s redb-key order, which is effectively random
    /// (`id` is random, not sequential). Kept for display ("sent at
    /// 2:30 PM") and as the primary sort key across longer gaps.
    pub timestamp: u64,
    /// Tie-breaks `timestamp` with a real ordering guarantee —
    /// `Db::message_sequence`, an in-memory counter incremented once per
    /// `save_message_now` call. Resets to 0 on every `create`/`open`,
    /// which is fine: it only ever needs to disambiguate messages saved
    /// within the same wall-clock second, and that can only happen
    /// within one continuous run.
    pub sequence: u64,
    /// Only meaningful when `sender_is_local` — the ratchet header `n`
    /// (`docs/MESSAGE_SCHEMA.md` §2) this message was sent with, i.e. its
    /// position within whatever sending chain was active at the time.
    /// `None` for a received message (nothing sends *us* a `DeliveryAck`
    /// to attach an `n` to) and for any locally-sent message predating
    /// this field. Used to match an incoming `DeliveryAck.acked_n`
    /// (`dratchet_core::payload::DeliveryAck`) back to the message it
    /// acknowledges — see `Db::mark_message_delivered`'s doc for the
    /// matching heuristic and its known limitation.
    pub send_n: Option<u32>,
    /// Only meaningful when `sender_is_local` — whether a `DeliveryAck`
    /// for this message has been received (`ARCHITECTURE.md` §4.6).
    /// Always `false` for a received message; not itself a signal of
    /// anything there (a received message is definitionally already
    /// delivered to us).
    pub delivered: bool,
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
            .field("sequence", &self.sequence)
            .field("send_n", &self.send_n)
            .field("delivered", &self.delivered)
            .finish()
    }
}

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

    /// Build and store a new message — the convenience path a chat UI
    /// actually sends through. Assigns the next `message_sequence` value,
    /// the real ordering guarantee `list_messages` sorts by (see
    /// `Message::sequence`'s doc) — `save_message` (the lower-level
    /// primitive) does not do this itself, so any caller building a
    /// `Message` by hand is responsible for setting `sequence` sensibly.
    ///
    /// `send_n` is the ratchet header `n` this message was actually sent
    /// with (`Some`, for a locally-sent chat message — see `Message::send_n`'s
    /// doc) or `None` for a received message.
    pub fn save_message_now(
        &self,
        conversation_id: [u8; 16],
        content: Vec<u8>,
        sender_is_local: bool,
        send_n: Option<u32>,
    ) -> Result<Message> {
        let message = Message {
            id: random_message_id(),
            sender_is_local,
            content,
            timestamp: now_unix(),
            sequence: self.message_sequence.fetch_add(1, Ordering::Relaxed),
            send_n,
            delivered: false,
        };
        self.save_message(conversation_id, &message)?;
        Ok(message)
    }

    pub fn delete_message(&self, conversation_id: [u8; 16], message_id: &[u8]) -> Result<()> {
        self.delete(&message_key(conversation_id, message_id))
    }

    /// Every message stored for `conversation_id`, oldest first.
    pub fn list_messages(&self, conversation_id: [u8; 16]) -> Result<Vec<Message>> {
        let mut messages = Vec::new();
        for key in self.keys_with_prefix(&message_key_prefix(conversation_id))? {
            let bytes = self
                .get_encrypted(Scope::Content, &key)?
                .ok_or(Error::MalformedRecord("message key listed but not found"))?;
            messages.push(decode_message(&bytes)?);
        }
        messages.sort_by_key(|m| (m.timestamp, m.sequence));
        Ok(messages)
    }

    /// Handle an incoming `DeliveryAck.acked_n` (`dratchet_core::payload::DeliveryAck`,
    /// `ARCHITECTURE.md` §4.6): find the locally-sent, not-yet-delivered
    /// message in `conversation_id` this ack refers to, mark it delivered,
    /// and return it — or `Ok(None)` if nothing matches (a stale/duplicate
    /// ack for an already-delivered message, or one naming an `n` this
    /// side never actually sent).
    ///
    /// **Matching heuristic and its known limitation**: `acked_n` alone is
    /// only unique *within one sending chain* — every Double Ratchet DH
    /// step resets the new chain's `n` back to 0, and the wire schema
    /// carries no `dh_pub` alongside `acked_n` to disambiguate which chain
    /// produced it (see `DeliveryAck`'s doc). This picks the
    /// lowest-`sequence` (oldest) matching, undelivered, locally-sent
    /// message — correct as long as a chain's messages are acked
    /// before the next chain's `n` values start repeating, which holds for
    /// ordinary turn-taking but is not a hard guarantee under a
    /// sufficiently out-of-order ack arrival. Tracked as a real, open
    /// limitation in `docs/DELIVERY_FAILURE_FINDINGS.md`, not silently
    /// assumed away.
    pub fn mark_message_delivered(
        &self,
        conversation_id: [u8; 16],
        acked_n: u32,
    ) -> Result<Option<Message>> {
        let messages = self.list_messages(conversation_id)?;
        let Some(mut matched) = messages
            .into_iter()
            .find(|m| m.sender_is_local && !m.delivered && m.send_n == Some(acked_n))
        else {
            return Ok(None);
        };
        matched.delivered = true;
        self.save_message(conversation_id, &matched)?;
        Ok(Some(matched))
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
        sample_message_with_sequence(timestamp, 0, content)
    }

    fn sample_message_with_sequence(timestamp: u64, sequence: u64, content: &str) -> Message {
        Message {
            id: random_id(),
            sender_is_local: true,
            content: content.as_bytes().to_vec(),
            timestamp,
            sequence,
            send_n: None,
            delivered: false,
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

    /// Real, previously-undiscovered bug, found by a two-real-client
    /// 100-message conversation test (`app/tests/full_conversation_100_messages.rs`):
    /// `now_unix()` is only 1-second resolution, so any real burst of
    /// messages (25 in a row, the way that test's phase 1 does) lands on
    /// the *same* timestamp — and without a second sort key, `list_messages`
    /// fell back to `keys_with_prefix`'s redb key order, keyed by a
    /// *random* message id, which came back essentially shuffled, not
    /// chronological. `Message::sequence` fixes it: same timestamp, still
    /// sorts by insertion order.
    #[test]
    fn messages_sharing_the_same_timestamp_still_sort_by_insertion_order() {
        let db = temp_db();
        let conv = [1u8; 16];

        // All 5 share one timestamp — exactly the real burst scenario.
        for (i, text) in ["a", "b", "c", "d", "e"].iter().enumerate() {
            db.save_message(conv, &sample_message_with_sequence(500, i as u64, text))
                .unwrap();
        }

        let messages = db.list_messages(conv).unwrap();
        let contents: Vec<String> = messages
            .iter()
            .map(|m| String::from_utf8(m.content.clone()).unwrap())
            .collect();
        assert_eq!(
            contents,
            vec!["a", "b", "c", "d", "e"],
            "same-timestamp messages must still come back in the order they were \
             actually saved, not redb's key order"
        );
    }

    /// The real production path (`save_message_now`, not the lower-level
    /// `save_message` the tests above use directly) assigns `sequence`
    /// itself, from `Db::message_sequence` — proving the *real* call sites
    /// this fix actually matters for, not just the primitive.
    #[test]
    fn save_message_now_assigns_increasing_sequence_numbers() {
        let db = temp_db();
        let conv = [1u8; 16];

        let texts = ["alpha", "beta", "gamma", "delta"];
        for text in texts {
            db.save_message_now(conv, text.as_bytes().to_vec(), true, None)
                .unwrap();
        }

        let messages = db.list_messages(conv).unwrap();
        let contents: Vec<String> = messages
            .iter()
            .map(|m| String::from_utf8(m.content.clone()).unwrap())
            .collect();
        assert_eq!(
            contents, texts,
            "save_message_now's real, in-order calls must list back in that same order, \
             whether or not they land in the same timestamp second"
        );
        // Strictly increasing, not just distinct.
        for pair in messages.windows(2) {
            assert!(pair[0].sequence < pair[1].sequence);
        }
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

    #[test]
    fn mark_message_delivered_flips_the_matching_sent_message() {
        let db = temp_db();
        let conv = [1u8; 16];

        let sent = db
            .save_message_now(conv, b"hi".to_vec(), true, Some(7))
            .unwrap();
        assert!(!sent.delivered);

        let updated = db.mark_message_delivered(conv, 7).unwrap().unwrap();
        assert_eq!(updated.id, sent.id);
        assert!(updated.delivered);

        let reloaded = db.list_messages(conv).unwrap();
        assert_eq!(reloaded.len(), 1);
        assert!(reloaded[0].delivered);
    }

    #[test]
    fn mark_message_delivered_ignores_received_messages_and_wrong_n() {
        let db = temp_db();
        let conv = [1u8; 16];

        // A received message with the same send_n-shaped value would never
        // actually have send_n set, but prove it explicitly: sender_is_local
        // must be true to match at all.
        db.save_message_now(conv, b"incoming".to_vec(), false, None)
            .unwrap();
        db.save_message_now(conv, b"outgoing".to_vec(), true, Some(3))
            .unwrap();

        assert!(db.mark_message_delivered(conv, 3).unwrap().is_some());
        // Already delivered — a duplicate/stale ack for the same n finds nothing left.
        assert!(db.mark_message_delivered(conv, 3).unwrap().is_none());
        // Never sent at all.
        assert!(db.mark_message_delivered(conv, 99).unwrap().is_none());
    }

    #[test]
    fn mark_message_delivered_picks_the_oldest_matching_undelivered_message() {
        // Documents the known cross-chain-collision limitation: two
        // messages from *different* sending chains can share the same
        // send_n (every DH ratchet step resets n back to 0). This proves
        // the deliberate tie-break — oldest (lowest sequence) first —
        // rather than leaving the choice unspecified.
        let db = temp_db();
        let conv = [1u8; 16];

        let first = db
            .save_message_now(conv, b"first chain, n=0".to_vec(), true, Some(0))
            .unwrap();
        let _second = db
            .save_message_now(conv, b"second chain, also n=0".to_vec(), true, Some(0))
            .unwrap();

        let updated = db.mark_message_delivered(conv, 0).unwrap().unwrap();
        assert_eq!(
            updated.id, first.id,
            "the oldest undelivered match must be the one flipped"
        );
    }
}
