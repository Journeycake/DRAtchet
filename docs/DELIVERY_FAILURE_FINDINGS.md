# Delivery-failure findings — 25 scenarios

A systematic pass over "how does DRAtchet actually behave when a
one-time prekey or a message gets dropped" (`ARCHITECTURE.md` §3.4/§4.5's
open questions), run against the real, current (pre-`DeliveryAck`)
system. Every scenario below is either:

- **Tested** — a real, no-mocks test exists and passes right now (file
  and test name given), or
- **Analyzed** — verified by direct code inspection with exact file:line
  citations, where a live test wasn't practical to construct.

Three genuine, previously-undocumented findings came out of this pass
(#12, #14, #23 below) — two turned out more benign than the code
structure first suggested (#12, #14), one is a real, currently-unaddressed
gap worth fixing (#23). Everything else confirms existing behavior, good
or bad, precisely.

Companion test files: `server/tests/delivery_failures.rs` (mailbox
layer), `core/src/ratchet.rs`'s `tests` module (ratchet layer, new cases
added alongside the many that already existed), `app/tests/delivery_failures.rs`
(app layer).

## Summary

| # | Scenario | Method | Verdict |
|---|---|---|---|
| 1 | Unfetched message expires past TTL | Tested | Confirmed gap — silent loss, no signal |
| 2 | Fetch without a follow-up delete | Tested | At-least-once — safe, but see #3 |
| 3 | Redelivering an already-decrypted envelope | Tested (existing) | Safe — rejected |
| 4 | Concurrent writers, same mailbox | Tested | Safe |
| 5 | No per-mailbox entry-count cap | Tested | Confirmed gap |
| 6 | No envelope size cap | Tested | Confirmed gap |
| 7 | Corrupted/tampered envelope | Tested (existing) | Safe |
| 8 | Prekey pool at zero | Tested (existing) | Safe — graceful degradation |
| 9 | Server restart, in-memory mailbox | Analyzed | Confirmed gap (by design, documented) |
| 10 | Duplicate delivery via naive retry | Tested | Safe |
| 11 | Burst exceeding `max_skip` | Tested (existing) | Safe — rejected cleanly |
| 12 | Recovery after a `MaxSkipExceeded` rejection | Tested (new) | Safe, with a real nuance (see below) |
| 13 | Skipped-key cache eviction bound | Tested (existing) | Safe |
| 14 | Crash between per-entry delete and batch-final `save_ratchet` | Tested (new) | Safe — corrected from initial hypothesis |
| 15 | Concurrent `FetchBundle` races for one OTP | Tested (existing, sequential) | Safe, not independently proven concurrent |
| 16 | Missing/consumed OTP secret named by a handshake | Analyzed | Safe |
| 17 | `Account` mutation ordering | Analyzed | Safe |
| 18 | `FirstContactWire` vs. `Envelope` disambiguation | Analyzed + existing test | Safe |
| 19 | Dropped `FirstContactWire` (compound of #1 + #20) | Analyzed | Confirmed gap (same root as #1/#20) |
| 20 | Alice's contact is Verified regardless of Bob's code check | Tested (new) | Confirmed asymmetry (by design) |
| 21 | Network error surfaces immediately, no partial commit | Tested | Safe |
| 22 | Retry from unsaved ratchet state reuses chain position | Tested (new) | Real crypto-hygiene finding, practically masked |
| 23 | `poll_loop` never reconnects after a connection failure | Analyzed | **Confirmed gap — high severity** |
| 24 | Pairing-code / mailbox TTL clock-skew exposure | Analyzed | Not a gap — corrected initial suspicion |
| 25 | Rapid replenish cycles and the signed prekey | Tested + analyzed | Safe |

---

## Mailbox / server layer

### 1. Unfetched message expires past TTL — silent loss
**Tested**: `server/tests/delivery_failures.rs::scenario_01_unfetched_message_expires_silently_with_no_signal_to_the_sender`.
A message sits for its full 14-day TTL, gets pruned by the real periodic
sweep (`server/src/pruning.rs`), and the sender's connection never
receives so much as a push frame about it.
**Options**: (a) ship `DeliveryAck` (already the plan for 5PM) so the
sender at least knows delivery *did* happen, which bounds how long a
silent failure can hide; (b) a `MailboxWrite` response could carry an
`expires_at` echo so a client-side outbox can proactively warn "this has
been sitting undelivered for N days."

### 2. Fetch without a follow-up delete
**Tested**: `scenario_02_a_fetch_without_a_follow_up_delete_is_redelivered_next_time`.
At-least-once, confirmed: a crash between fetch and delete leaves the
entry in place for the next fetch. Safe by itself — see #3 for why
redelivery doesn't cause double-processing.
**Options**: none needed; this is the correct behavior for the model.

### 3. Redelivering an already-decrypted envelope
**Tested (existing)**: `core/src/ratchet.rs::tests::each_message_key_is_single_use_replay_is_rejected`.
The message key is deleted the instant it's used; a second decrypt of the
identical envelope fails. This is what makes #2's at-least-once mailbox
semantics safe.

### 4. Concurrent writers to the same mailbox
**Tested**: `scenario_04_concurrent_writers_to_the_same_mailbox_both_survive`,
using real `tokio::spawn` tasks, not a sequential simulation. Both writes
survive; no last-write-wins clobbering.

### 5 & 6. No entry-count or envelope-size cap
**Tested**: `scenario_05_06_no_entry_count_or_size_cap_is_enforced` — 2,000
writes and a 1 MiB envelope all succeed with `ok: true`. Confirmed by
reading `server/src/ws.rs`'s `MailboxWrite` handler directly: it pushes to
an unbounded `Vec` with no check.
**Severity**: real — the mailbox is in-memory (#9), so this is an
unauthenticated-cost-free (any client can authenticate for free; proof-of-
work only gates *new username* registration) resource-exhaustion vector
against any mailbox_id an attacker can compute (trivial for
`bootstrap_mailbox_id(target_fp)` given just the target's fingerprint).
**Options**: (a) cap envelope size (a real chat message padded per §11.3
is small and bounded; reject anything wildly larger at the frame level);
(b) cap entries per mailbox (evict oldest or reject new writes past a
threshold); (c) extend `FetchRateLimiter`'s pattern to `MailboxWrite`
per-`(connection, target_mailbox)`.

### 7. Corrupted/tampered envelope
**Tested (existing)**: `garbage_envelope_does_not_desync_the_ratchet`,
`tampered_ciphertext_is_rejected`, `tampered_header_is_rejected_even_though_ciphertext_is_untouched`,
`garbage_envelope_with_inflated_pn_is_rejected_without_side_effects`. All
in `core/src/ratchet.rs`. Rejected cleanly, no ratchet-state corruption —
the "transactional by construction" design (`decrypt_raw`'s own doc
comment) holds.

### 8. Prekey pool at zero
**Tested (existing)**: `core/tests/x3dh_and_ratchet.rs::handshake_degrades_gracefully_without_a_one_time_prekey`.
The bundle just omits the OTP; the handshake still completes, with one
fewer DH term (documented, accepted forward-secrecy tradeoff — this is
exactly what `replenish_prekeys_if_low` exists to make rare).

### 9. Server restart — in-memory mailbox
**Analyzed**: `server/src/state.rs`'s `AppState.inner.mailboxes` is a
plain `HashMap`, never written to the persisted `redb` the way the
`directory` is (`server/src/pruning.rs`'s own doc comment: "state that
grows purely from implementation bookkeeping... `directory` is a
directory; unbounded-but-intentional, not a pruning target" — implicitly
confirming mailbox/presence/rendezvous are the ephemeral counterpart).
This matches the architecture diagram's caption from earlier this session
and is a known, accepted v1 tradeoff, not a surprise — restated here as
one concrete numbered delivery-failure mode: **a server restart drops
every undelivered message for every conversation, all at once, with the
same "no signal to anyone" property as #1.**
**Options**: (a) persist the mailbox to `redb` the same way the directory
was persisted (Task from earlier this session); (b) accept it as a v1
tradeoff and prioritize #1's `DeliveryAck` so the *client* can detect and
recover from an unusually large gap in delivery confirmations, rather
than making the server durable.

---

## Ratchet / crypto layer

### 11. Burst exceeding `max_skip`
**Tested (existing)**: `skipping_beyond_max_skip_is_rejected_not_silently_unbounded`.

### 12. Recovery after a `MaxSkipExceeded` rejection
**Tested (new)**: `core/src/ratchet.rs::tests::a_maxskipexceeded_rejection_does_not_wedge_the_conversation_for_reachable_messages`.
Two real findings, one on each side of an initial (wrong) hypothesis:
- The rejection is genuinely side-effect-free (matches the `decrypt_raw`
  doc comment's promise) — a *different*, in-range message from the same
  burst decrypts fine afterward, proving the conversation isn't wedged.
- **Correction caught by the test itself**: reachability is relative to
  the *current* position, not fixed at arrival time. An early draft of
  this test used too narrow a burst and found that decrypting the
  in-range message moved the receiver's position close enough that the
  *original* "unreachable" message became reachable on a second try. The
  final test widens the gap enough to show genuine, permanent
  unreachability once nothing will ever close it — but the corrected
  finding itself (a message once rejected can become decryptable again
  later, depending on what else gets processed first) is worth keeping in
  mind: "rejected" is not always "gone forever."

### 13. Skipped-key cache eviction bound
**Tested (existing)**: `skipped_cache_is_bounded_across_many_dh_ratchet_steps`,
`eviction_does_not_break_a_legitimate_late_arrival_within_the_cap`.

---

## App layer

### 14. Crash between per-entry delete and the batch-final `save_ratchet`
**Tested (new)**: `app/tests/delivery_failures.rs::scenario_14_a_crash_before_save_ratchet_does_not_lose_already_processed_messages`.
`receive_pending` (`app/src/lib.rs`) deletes each mailbox entry from the
server as it's processed, inside the loop, but calls `db.save_ratchet`
only once, after the loop finishes. Read cold, that looks like a real
data-loss bug: a crash partway through a batch would leave the on-disk
ratchet behind where the (already-deleted-server-side) messages actually
left it.

**This test disproves that** — reproducing the exact sequence by hand
(real fetch, real decrypt, real `save_message_now`, real delete+ack for
2 of 3 entries, then deliberately *not* calling `save_ratchet`) shows:
- Message content is safe: `save_message_now` runs per-entry, inside the
  loop — not deferred like `save_ratchet` is. The already-processed
  messages are durably saved before the simulated crash.
- The stale on-disk ratchet self-heals on the very next real
  `receive_pending` call: it skip-and-derives past the (now-phantom)
  positions of the deleted-but-unsaved entries to reach whatever's next,
  at the cost of some wasted, self-limiting skipped-key cache growth —
  not lost data.
- The only entry *not* recovered in the test is the one never deleted in
  the simulated crash (at-least-once, #2) — and even that recovers fully
  once a subsequent `receive_pending` call fetches it alongside whatever
  arrived after.

**Bottom line**: this is not a bug. No option needed — noted here because
the code structure alone would mislead a reviewer into flagging it as one
without running the test.

### 16. Missing/already-consumed OTP secret named by a handshake
**Analyzed**: `app/src/lib.rs`'s `try_accept_first_contact` —
`otp_secret.is_none()` (when `used_one_time_prekey_id` names an id this
device doesn't have) returns `Ok(None)` cleanly. The caller
(`receive_first_contact_attempts`) still deletes the mailbox entry and
moves on — no panic, no corrupted state, matches the same "reject
silently, never abort the batch" posture proven for malformed entries in
`app/tests/receive_pending_resilience.rs`.

### 17. `Account` mutation ordering
**Analyzed**: every real caller reaches `Account` through one
`Arc<Mutex<Account>>` (`ui/src-tauri/src/lib.rs`'s `AppState`), and
`replenish_prekeys_if_low`/`receive_first_contact_attempts` both run
sequentially on the same `poll_loop` tick — never concurrently. No race
between generating a new prekey batch and consuming one from the current
batch.

### 18. `FirstContactWire` vs. `Envelope` disambiguation
**Analyzed + existing test**: `receive_first_contact_attempts` tries
`Envelope::decode` first and only falls back to `FirstContactWire` on
failure — relies on the same "one bad entry doesn't wedge the batch"
property `app/tests/receive_pending_resilience.rs`'s
`a_corrupted_entry_between_two_real_messages_is_skipped_not_a_wedge`
already proves for the general case.

### 19. Dropped `FirstContactWire`
**Analyzed**: compound of #1 (silent TTL loss) and #20 (the asymmetry) —
if Alice's `FirstContactWire` never reaches Bob at all (pruned before his
next poll), the outcome is identical to a wrong code: Bob never attempts
anything, Alice's contact stays `Verified` regardless, and nothing ever
reconciles the two. No new mechanism, just the composition of two
already-documented behaviors.

### 20. Alice's contact is Verified regardless of Bob's code check
**Tested (new)**: `scenario_20_alices_contact_is_verified_regardless_of_whether_bobs_code_matched`,
extending `app/tests/first_contact.rs`'s existing wrong-code test (which
only ever checked Bob's side) to assert Alice's own contact list too.
Confirms exactly what `add_contact_by_username`'s doc comment claims, now
backed by an executable regression test. This is a documented, deliberate
design tradeoff (§6.4), not treated as a bug — flagged here because it's
central to "how are delivery failures handled" and easy to state
precisely now that it's pinned down.
**Options** (if ever revisited): a delayed local "still pending
confirmation" UI state that only flips to a plain Verified indicator once
the first real chat message round-trips successfully — costs a small UX
delay, buys an honest signal.

---

## Client / connection layer

### 21 & 22. Network failure mid-send, and what a retry reuses
**Tested**: `scenario_22_retrying_from_unsaved_ratchet_state_reuses_the_same_chain_position`.
`send_message` only calls `db.save_ratchet` after a successful `Ack`
(`app/src/lib.rs`); a network failure before that leaves the advanced
in-memory ratchet un-persisted and the caller sees an immediate `Err` —
safe, no partial commit (#21).

The sharper finding (#22): because message-key derivation is
deterministic from chain position, two independent loads of the same
un-saved disk state — the original attempt and a retry, even with
*different* plaintext — land on the identical `(dh_pub, n)` and reuse the
same derived message key. This is a genuine key/nonce reuse at the crypto
layer. In practice it's masked at the application level: the recipient's
single-use message-key consumption (#3) means whichever envelope arrives
first decrypts, and a second one at the same position is rejected, not
silently accepted as different content — so no user-visible corruption or
duplication results. It remains worth knowing about precisely because the
masking is a side effect of an unrelated protection, not a guarantee
this path was designed around.
**Options**: (a) treat this as informational (the masking is real and
sufficient today); (b) if `send_message` retry logic is ever added
explicitly (right now there is none — a caller has to notice the `Err`
and call it again itself), make the retry re-derive from a freshly
persisted state each time rather than reusing an unsaved in-memory
ratchet across two calls, which the current code already does by
construction (each call reloads from `Db`) — so this is really just a
note that the *safety* here is emergent, not to be relied on if the
persistence strategy ever changes.

### 23. `poll_loop` never reconnects after a connection failure
**Analyzed**: `ui/src-tauri/src/lib.rs`. `Connection::connect` is called
exactly once, synchronously, in `run()` before `poll_loop` is spawned
(line ~564). `poll_loop` (line 459 on) holds that same `Connection`
behind `state.conn: Arc<Mutex<Connection>>` for its entire lifetime.
Every error path in the loop (`receive_first_contact_attempts`,
`replenish_prekeys_if_low`, `receive_pending`, per contact) does nothing
but `eprintln!` and move on to the next contact/tick — there is no
`Connection::connect` call anywhere inside `poll_loop`, and nothing
else in the file re-establishes the connection either.

**This is the one real, unambiguous, high-severity gap this pass found.**
Any transient disconnect — laptop sleep/wake, a wifi network switch, a
server restart, a brief network blip — leaves every subsequent
`conn.send`/`conn.recv` call failing against a permanently-dead socket.
The app keeps running, keeps ticking every 2 seconds, keeps silently
logging errors to a console the user never sees, and never sends or
receives another message again until the user manually quits and
restarts the app. This is a much more common real-world trigger than any
of #1/#9/#19's TTL-driven scenarios — it doesn't need 14 days or a server
crash, just a laptop lid closing.

**Options**:
1. Detect a `conn.send`/`conn.recv` `Err` in `poll_loop`, and on that
   signal, drop the dead `Connection` and call `Connection::connect` +
   `.authenticate()` again before continuing — the natural, minimal fix,
   mirroring what `reconcile_own_profile` already does for a *different*
   kind of "state went stale" recovery at startup.
2. Add exponential backoff around the reconnect attempt itself (a
   `Connection::connect` failure — server genuinely down — shouldn't
   retry every 2 seconds forever).
3. Surface a connection-state indicator in the UI (a small "reconnecting…"
   badge) so a user isn't left wondering why messages stopped arriving —
   currently there is no signal of any kind, even a healthy one, about
   connection state.

---

## Prekey layer (extends the orphaned-secret fix from this session)

### 15. Concurrent `FetchBundle` races for one OTP
**Tested (existing, sequential)**: `server/tests/integration.rs::one_time_prekeys_are_consumed_exactly_once_across_repeated_fetches`.
This session's `scenario_04` (mailbox writes) independently proves the
same `AppState`-wide `RwLock` pattern is safe under *real* concurrent
access for a different handler — giving indirect confidence the same
holds for `FetchBundle`, but that exact race isn't proven under real
parallel load today. Worth a follow-up `tokio::spawn`-based test mirroring
`scenario_04` if this ever becomes a concern.

### 24. Pairing-code / mailbox TTL clock-skew exposure
**Analyzed — corrected an initial suspicion**: at first glance, both TTLs
looked like they might depend on comparing two different devices' clocks.
Checked precisely and neither does:
- Mailbox TTL: `expires_at` is computed **server-side**
  (`SystemTime::now() + ttl` in `server/src/ws.rs`), so it's immune to
  any client's clock being wrong.
- Pairing-code TTL: both `generate_pairing_code` (client) and its
  eventual `.verify(code, &[], now)` check inside
  `try_accept_first_contact` run on **the same device** (Bob's) — there's
  no cross-device comparison at all, just Bob's own clock against itself
  over a ~10-minute window.

Not a gap. Included to correct the record rather than let an untested
assumption stand.

### 25. Rapid replenish cycles and the signed prekey
**Tested + analyzed**: `core/src/account.rs::tests::many_replenish_cycles_never_grow_storage_past_one_batch`
(this session's orphaned-prekey fix) proves the one-time-prekey batch
stays bounded across repeated cycles. Separately confirmed by reading
`Account`: `signed_prekey` is set once in `Account::generate()` and never
reassigned by `generate_one_time_prekeys`/`publish_bundle`/anything in
`publish_under_candidates`'s replenish path — only one-time prekeys
rotate on replenish, the signed prekey does not. No in-flight handshake
can ever have its signed-prekey reference invalidated by a replenish
race.
