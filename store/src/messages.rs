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
    /// `save_message_now` call. Starts at `0` on a brand-new `create`,
    /// but `open` recovers it from whatever's already on disk
    /// (`recover_message_sequence`) rather than naively resetting to
    /// `0` — a restart landing in the same wall-clock second as
    /// existing messages must not risk handing out a `sequence` value
    /// that collides with, or sorts before, ones already saved (a real
    /// bug this once was, closed after it broke the `wipe_conversation_since`
    /// boundary comparison — `docs/DELIVERY_FAILURE_FINDINGS.md`).
    pub sequence: u64,
    /// Only meaningful when `sender_is_local` — the ratchet header `n`
    /// (`docs/MESSAGE_SCHEMA.md` §2) this message was sent with, i.e. its
    /// position within whatever sending chain was active at the time.
    /// `None` for a received message (nothing sends *us* a `DeliveryAck`
    /// to attach an `n` to) and for any locally-sent message predating
    /// this field. Paired with `send_dh_pub` to match an incoming
    /// `DeliveryAck` (`dratchet_core::payload::DeliveryAck`) back to the
    /// message it acknowledges — see `Db::mark_message_delivered`'s doc.
    pub send_n: Option<u32>,
    /// Only meaningful when `sender_is_local` — the ratchet header
    /// `dh_pub` (`docs/MESSAGE_SCHEMA.md` §2) this message was sent with,
    /// i.e. which sending chain `send_n` is a position within. `None`
    /// under the same conditions as `send_n`. `(send_dh_pub, send_n)`
    /// together are a genuinely unique identifier for one specific
    /// message — the same pair a `DeliveryAck` now carries
    /// (`core::payload::DeliveryAck`'s doc) and the same pair
    /// `RatchetState`'s own skipped-message-key cache already keys by.
    /// Without this, `send_n` alone collides across sending chains, since
    /// every Double Ratchet DH step resets a fresh chain's `n` back to 0
    /// — the real gap `docs/DELIVERY_FAILURE_FINDINGS.md` finding #28
    /// documents and this field closes.
    #[serde(with = "serde_bytes")]
    pub send_dh_pub: Option<Vec<u8>>,
    /// Only meaningful when `sender_is_local` — whether a `DeliveryAck`
    /// or a cumulative `PiggybackAck` for this message has been received
    /// (`ARCHITECTURE.md` §4.6). Always `false` for a received message;
    /// not itself a signal of anything there (a received message is
    /// definitionally already delivered to us).
    pub delivered: bool,
    /// Only meaningful when `sender_is_local && !delivered` — set when
    /// this client detected a connection interruption after sending this
    /// message and before either acknowledgment path confirmed it, so
    /// there's genuine reason to doubt whether it ever reached the relay
    /// at all (as opposed to simply "sent, ack not back yet," the normal
    /// transient state every message passes through). Cleared back to
    /// `false` the moment `delivered` flips `true`, by either
    /// `mark_message_delivered` or `mark_messages_delivered_up_to`.
    /// `#[serde(default)]` so a message record written before this field
    /// existed decodes as `false` (never uncertain) rather than failing
    /// to decode at all.
    #[serde(default)]
    pub uncertain: bool,
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
            .field("send_dh_pub", &self.send_dh_pub.as_deref().map(hex))
            .field("delivered", &self.delivered)
            .field("uncertain", &self.uncertain)
            .finish()
    }
}

pub(crate) fn message_key(conversation_id: [u8; 16], message_id: &[u8]) -> String {
    format!("message:{}:{}", hex(&conversation_id), hex(message_id))
}

pub(crate) fn message_key_prefix(conversation_id: [u8; 16]) -> String {
    format!("message:{}:", hex(&conversation_id))
}

/// The correct starting value for `Db::message_sequence` when *opening*
/// an existing database: `1 +` the highest `sequence` any already-stored
/// message, across every conversation, currently has — or `0` if there
/// are none. `Db::create` correctly starts at `0` (nothing is stored
/// yet); `Db::open` must not, or this counter's own documented tie-break
/// contract quietly breaks across a restart.
///
/// `Message::sequence`'s doc says a fresh-every-run counter "only ever
/// needs to disambiguate messages saved within the same wall-clock
/// second, and that can only happen within one continuous run" — true
/// for the counter's *original* purpose (`list_messages`' own sort), but
/// false the moment something *else* durably stores a "sequence value
/// as of this saved instant" and compares it later, across a restart, to
/// a **new** counter that has since restarted at `0` —
/// `Contact::peer_wipe_boundary_sequence`
/// (`store::wipe_policy::record_peer_wipe_policy`) does exactly that. A
/// restart landing in the same wall-clock second as both the boundary
/// being stamped and a subsequent message being saved can then hand that
/// message `sequence = 0`, which can compare as *before* a boundary
/// whose own sequence component was stamped pre-restart at a higher
/// value — silently protecting a message from a scoped wipe that should
/// have removed it (`docs/DELIVERY_FAILURE_FINDINGS.md`). Recovering the
/// counter's true prior value on every `open` closes this at the root,
/// rather than patching each downstream consumer that happens to compare
/// across a restart.
pub(crate) fn recover_message_sequence(db: &Db) -> Result<u64> {
    let mut next = 0u64;
    for key in db.keys_with_prefix("message:")? {
        let bytes = db
            .get_encrypted(Scope::Content, &key)?
            .ok_or(Error::MalformedRecord("message key listed but not found"))?;
        let message = decode_message(&bytes)?;
        next = next.max(message.sequence + 1);
    }
    Ok(next)
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
    /// `send_n`/`send_dh_pub` are the ratchet header `n`/`dh_pub` this
    /// message was actually sent with (`Some`, for a locally-sent chat
    /// message — see `Message::send_n`/`send_dh_pub`'s docs) or `None`
    /// for a received message.
    pub fn save_message_now(
        &self,
        conversation_id: [u8; 16],
        content: Vec<u8>,
        sender_is_local: bool,
        send_n: Option<u32>,
        send_dh_pub: Option<Vec<u8>>,
    ) -> Result<Message> {
        let message = Message {
            id: random_message_id(),
            sender_is_local,
            content,
            timestamp: now_unix(),
            sequence: self.message_sequence.fetch_add(1, Ordering::Relaxed),
            send_n,
            send_dh_pub,
            delivered: false,
            uncertain: false,
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

    /// Handle an incoming `DeliveryAck` (`dratchet_core::payload::DeliveryAck`,
    /// `ARCHITECTURE.md` §4.6): find the locally-sent, not-yet-delivered
    /// message in `conversation_id` this ack refers to, mark it delivered,
    /// and return it — or `Ok(None)` if nothing matches (a stale/duplicate
    /// ack for an already-delivered message, or one naming a
    /// `(dh_pub, n)` this side never actually sent).
    ///
    /// **Exact match, not a heuristic**: `(dh_pub, n)` together uniquely
    /// identify one specific sent message — `dh_pub` names which sending
    /// chain, `n` the position within it — the same pair
    /// `RatchetState`'s own skipped-message-key cache already keys by.
    /// This closes a real gap the first `DeliveryAck` implementation had:
    /// matching on `n` alone collided across chains that happened to
    /// share one (every fresh chain starts at `n = 0`, so this was the
    /// common case) — see `docs/DELIVERY_FAILURE_FINDINGS.md` finding #28
    /// for the original limitation and its resolution.
    pub fn mark_message_delivered(
        &self,
        conversation_id: [u8; 16],
        dh_pub: &[u8],
        acked_n: u32,
    ) -> Result<Option<Message>> {
        let messages = self.list_messages(conversation_id)?;
        let Some(mut matched) = messages.into_iter().find(|m| {
            m.sender_is_local
                && !m.delivered
                && m.send_n == Some(acked_n)
                && m.send_dh_pub.as_deref() == Some(dh_pub)
        }) else {
            return Ok(None);
        };
        matched.delivered = true;
        matched.uncertain = false;
        self.save_message(conversation_id, &matched)?;
        Ok(Some(matched))
    }

    /// Handle an incoming `PiggybackAck` (`dratchet_core::payload::
    /// PiggybackAck`, carried on an ordinary chat message's
    /// `ChatContent::piggyback_ack`): mark every locally-sent,
    /// not-yet-delivered message on chain `dh_pub` with `send_n <=
    /// highest_n` as delivered — cumulative, not a single exact match
    /// like `mark_message_delivered`, the same "everything up through
    /// this point" semantics as a TCP cumulative ack. This is what lets
    /// an ordinary follow-up chat message resolve a message this client
    /// had marked `uncertain` (`Message::uncertain`'s doc) even though no
    /// dedicated `DeliveryAck` for it ever arrived — the peer's next
    /// message re-asserts coverage for everything it has actually
    /// received on this chain so far, so one lost dedicated ack doesn't
    /// leave the sender guessing forever as long as the conversation
    /// continues.
    ///
    /// Returns every message this call newly marked delivered, oldest
    /// first, for a caller to react to (e.g. UI checkmarks) — mirrors
    /// `mark_message_delivered`'s single-`Message` return, just
    /// potentially more than one at a time.
    pub fn mark_messages_delivered_up_to(
        &self,
        conversation_id: [u8; 16],
        dh_pub: &[u8],
        highest_n: u32,
    ) -> Result<Vec<Message>> {
        let messages = self.list_messages(conversation_id)?;
        let mut newly_delivered = Vec::new();
        for mut m in messages.into_iter().filter(|m| {
            m.sender_is_local
                && !m.delivered
                && m.send_dh_pub.as_deref() == Some(dh_pub)
                && m.send_n.is_some_and(|n| n <= highest_n)
        }) {
            m.delivered = true;
            m.uncertain = false;
            self.save_message(conversation_id, &m)?;
            newly_delivered.push(m);
        }
        newly_delivered.sort_by_key(|m| (m.timestamp, m.sequence));
        Ok(newly_delivered)
    }

    /// Mark every currently undelivered, locally-sent message in
    /// `conversation_id` as `uncertain` (`Message::uncertain`'s doc) —
    /// called once per conversation right after this client detects and
    /// recovers from a connection interruption, since any of those sends
    /// might have never actually reached the relay. Returns how many
    /// messages were newly marked (already-uncertain or already-delivered
    /// messages are left untouched, so calling this repeatedly across
    /// several short reconnects in a row is harmless).
    pub fn mark_undelivered_uncertain(&self, conversation_id: [u8; 16]) -> Result<usize> {
        let messages = self.list_messages(conversation_id)?;
        let mut count = 0;
        for mut m in messages
            .into_iter()
            .filter(|m| m.sender_is_local && !m.delivered && !m.uncertain)
        {
            m.uncertain = true;
            self.save_message(conversation_id, &m)?;
            count += 1;
        }
        Ok(count)
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

    fn temp_db_path() -> std::path::PathBuf {
        let dir = tempfile::tempdir().unwrap().keep();
        dir.join("test.redb")
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
            send_dh_pub: None,
            delivered: false,
            uncertain: false,
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
            db.save_message_now(conv, text.as_bytes().to_vec(), true, None, None)
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

    /// Regression test for the restart/tie-break bug `recover_message_sequence`
    /// exists to close: naively resetting `message_sequence` to `0` on
    /// `open` let a message saved shortly after a restart get a
    /// `sequence` that collides with (or sorts *before*) one already
    /// saved in the same wall-clock second, before the restart —
    /// breaking `list_messages`' own ordering guarantee, the exact
    /// invariant `sequence` exists for.
    #[test]
    fn sequence_survives_a_real_restart_within_the_same_wall_clock_second() {
        let path = temp_db_path();
        let conv = [9u8; 16];

        {
            let db = Db::create(&path, "pw").unwrap();
            for text in ["one", "two", "three"] {
                db.save_message_now(conv, text.as_bytes().to_vec(), true, None, None)
                    .unwrap();
            }
        }

        // A real close + reopen, exactly like `boundary_persists_across_a_real_db_restart`
        // in `app/tests/scoped_wipe_edge_cases.rs` — not just continuity
        // of one in-memory `Db` handle.
        let db = Db::open(&path, "pw").unwrap();
        db.save_message_now(conv, b"four".to_vec(), true, None, None)
            .unwrap();

        let messages = db.list_messages(conv).unwrap();
        let contents: Vec<String> = messages
            .iter()
            .map(|m| String::from_utf8(m.content.clone()).unwrap())
            .collect();
        assert_eq!(
            contents,
            vec!["one", "two", "three", "four"],
            "ACTUAL: the post-restart message sorts strictly after every pre-restart one, \
             even when both land in the same wall-clock second — its sequence continued \
             from where the pre-restart counter left off instead of restarting at 0"
        );
        for pair in messages.windows(2) {
            assert!(
                pair[0].sequence < pair[1].sequence,
                "strictly increasing across the restart, not just distinct: {:?} then {:?}",
                pair[0].sequence,
                pair[1].sequence
            );
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
        let dh_pub = vec![1u8; 32];

        let sent = db
            .save_message_now(conv, b"hi".to_vec(), true, Some(7), Some(dh_pub.clone()))
            .unwrap();
        assert!(!sent.delivered);

        let updated = db
            .mark_message_delivered(conv, &dh_pub, 7)
            .unwrap()
            .unwrap();
        assert_eq!(updated.id, sent.id);
        assert!(updated.delivered);

        let reloaded = db.list_messages(conv).unwrap();
        assert_eq!(reloaded.len(), 1);
        assert!(reloaded[0].delivered);
    }

    #[test]
    fn mark_message_delivered_ignores_received_messages_and_wrong_n_or_dh_pub() {
        let db = temp_db();
        let conv = [1u8; 16];
        let dh_pub = vec![2u8; 32];
        let other_dh_pub = vec![9u8; 32];

        // A received message with the same send_n-shaped value would never
        // actually have send_n set, but prove it explicitly: sender_is_local
        // must be true to match at all.
        db.save_message_now(conv, b"incoming".to_vec(), false, None, None)
            .unwrap();
        db.save_message_now(
            conv,
            b"outgoing".to_vec(),
            true,
            Some(3),
            Some(dh_pub.clone()),
        )
        .unwrap();

        // Right n, wrong dh_pub — no match.
        assert!(db
            .mark_message_delivered(conv, &other_dh_pub, 3)
            .unwrap()
            .is_none());
        // Right dh_pub, wrong n — no match.
        assert!(db
            .mark_message_delivered(conv, &dh_pub, 99)
            .unwrap()
            .is_none());
        // Both right — matches.
        assert!(db
            .mark_message_delivered(conv, &dh_pub, 3)
            .unwrap()
            .is_some());
        // Already delivered — a duplicate/stale ack for the same (dh_pub, n) finds nothing left.
        assert!(db
            .mark_message_delivered(conv, &dh_pub, 3)
            .unwrap()
            .is_none());
    }

    /// The real fix for finding #28's collision: two messages from
    /// *different* sending chains sharing the same `n` (every DH ratchet
    /// step resets a fresh chain's `n` back to 0 — `n = 0` colliding is
    /// the common case, not a rare one) are now disambiguated exactly by
    /// `dh_pub`, not by an "oldest wins" heuristic — each ack correctly
    /// flips the message from *its own* chain, never the other one.
    #[test]
    fn mark_message_delivered_disambiguates_same_n_across_different_chains() {
        let db = temp_db();
        let conv = [1u8; 16];
        let chain_a = vec![0xAAu8; 32];
        let chain_b = vec![0xBBu8; 32];

        let first = db
            .save_message_now(
                conv,
                b"first chain, n=0".to_vec(),
                true,
                Some(0),
                Some(chain_a.clone()),
            )
            .unwrap();
        let second = db
            .save_message_now(
                conv,
                b"second chain, also n=0".to_vec(),
                true,
                Some(0),
                Some(chain_b.clone()),
            )
            .unwrap();

        // Acking chain B's n=0 must flip *second*, not the older *first*.
        let updated = db
            .mark_message_delivered(conv, &chain_b, 0)
            .unwrap()
            .unwrap();
        assert_eq!(
            updated.id, second.id,
            "must match the message from the acked chain, not merely the oldest n=0"
        );

        let after_one_ack = db.list_messages(conv).unwrap();
        let first_reloaded = after_one_ack.iter().find(|m| m.id == first.id).unwrap();
        assert!(
            !first_reloaded.delivered,
            "the other chain's still-unacked message must not be touched"
        );

        // Acking chain A's n=0 now correctly flips *first*.
        let updated = db
            .mark_message_delivered(conv, &chain_a, 0)
            .unwrap()
            .unwrap();
        assert_eq!(updated.id, first.id);
    }
}
