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
structure first suggested (#12, #14); the third (#23) was a real gap and
has since been fixed and tested (`ui/src-tauri/src/lib.rs`'s `poll_loop`
now reconnects with backoff instead of silently dying forever). Everything
else confirms existing behavior, good or bad, precisely.

A fourth genuine gap (#26) turned up later, outside this 25-scenario
pass — from the real two-client 100-message functionality test — and is
documented in its own section below alongside the other findings, since
it's the same class of "found a real bug, fixed it, tested the fix"
result.

Two more (#27, #28) turned up while building and testing `DeliveryAck`
(`ARCHITECTURE.md` §4.6): #27 is a real, high-severity, previously-latent
gap in the mailbox model itself; #28 is a real limitation in `DeliveryAck`'s
own matching scheme. Both were fixed and tested — #28 was initially
documented with remediation options rather than fixed outright, then
closed in a follow-up pass (see its section for the fix and why it was
worth doing).

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
| 23 | `poll_loop` never reconnects after a connection failure | Analyzed, then fixed + tested | **Fixed** — was a confirmed high-severity gap |
| 24 | Pairing-code / mailbox TTL clock-skew exposure | Analyzed | Not a gap — corrected initial suspicion |
| 25 | Rapid replenish cycles and the signed prekey | Tested + analyzed | Safe |
| 26 | Same-second messages sort by random key order, not send order | Tested (new) | **Fixed** — was a confirmed gap |
| 27 | A writer's own not-yet-collected mailbox entry is fetchable by the writer itself | Tested (new) | **Fixed** — was a confirmed high-severity gap |
| 28 | `DeliveryAck.acked_n` collides across sending chains | Analyzed + tested | **Fixed** — was a confirmed, open limitation |

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

### 23. `poll_loop` never reconnects after a connection failure — **fixed**
**Originally analyzed, now fixed and tested.** `ui/src-tauri/src/lib.rs`:
`Connection::connect` used to be called exactly once, synchronously, in
`run()` before `poll_loop` was spawned, and every error path in the loop
(`receive_first_contact_attempts`, `replenish_prekeys_if_low`,
`receive_pending` per contact) did nothing but `eprintln!` and move on —
reusing the same dead `Connection` behind `state.conn: Arc<Mutex<Connection>>`
forever.

**This was the one real, unambiguous, high-severity gap this pass
found.** Any transient disconnect — laptop sleep/wake, a wifi network
switch, a server restart, a brief network blip — left every subsequent
`conn.send`/`conn.recv` call failing against a permanently-dead socket,
silently, with no user-visible signal, until the app was manually
restarted. A much more common real-world trigger than any of #1/#9/#19's
TTL-driven scenarios — no 14 days or server crash needed, just a laptop
lid closing.

**Fix applied** (options 1 and 2 below; option 3 deliberately deferred):
- `connect_authenticate_and_reconcile(url, db, account)` — the
  connect+authenticate+reconcile sequence `run()`'s startup used to
  perform inline is now a shared helper, reused by both startup and
  `poll_loop`'s reconnect path, so a re-established connection is never
  any less complete than the original one (crucially, it still reclaims
  a squatted handle via `reconcile_own_profile` if the directory forgot
  this device — the same server-restart scenario a dropped socket often
  coincides with).
- `poll_loop` now classifies each tick's errors with `is_connection_error`
  (matching only `dratchet_app::Error::Connection`, never an
  application-level error like `NotAcknowledged`) and, on a real
  transport failure, skips the rest of that tick's work and schedules a
  reconnect attempt for the next tick.
- Reconnect attempts back off exponentially on repeated failure
  (`RECONNECT_INITIAL_BACKOFF` = one poll tick, doubling up to
  `RECONNECT_MAX_BACKOFF` = 60s) — the first attempt is prompt, but a
  genuinely down server doesn't get hammered every 2 seconds forever.
- Real tests (`ui/src-tauri/src/lib.rs`'s `tests` module, against a real
  spawned `dratchet_server::app()`): the helper produces a live, usable
  connection; it fails cleanly against an unreachable address; and,
  directly proving the reconnect scenario end to end, a second call after
  the first connection is dropped produces a working replacement.

**Option 3, also done**: a small "Reconnecting…" badge in the sidebar
header (`ui/src/routes/+page.svelte`), driven by a new
`get_connection_status` command plus a `CONNECTION_STATUS_EVENT` the
backend emits only on an actual state change. Live-verified under Xvfb
against a real `dratchetd`: no badge in normal operation, the badge
appears the moment the server is killed, the log shows the real 2s → 4s
backoff from `RECONNECT_INITIAL_BACKOFF` doubling, and the badge clears
the instant the reconnect succeeds after the server comes back. All
three remediation options for scenario 23 are now shipped.

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

## App / display layer (found by the 100-message functionality test)

### 26. Same-second messages sort by random key order, not send order
**Tested (new)**: found by `app/tests/full_conversation_100_messages.rs`,
the real two-client 100-message functionality test requested outside
this 25-scenario pass but documented here since it's the same class of
finding. Not one of the original 25 — a genuinely new, previously-
undiscovered gap.

`store::messages::now_unix()` has 1-second resolution
(`SystemTime::now().duration_since(UNIX_EPOCH).as_secs()`), and
`Db::list_messages` sorted purely by that `timestamp`. Rust's
`sort_by_key` is stable, so ties fell back to iteration order from
`keys_with_prefix`, which walks redb's B-tree key order — keys are
`message:{conv_id}:{message_id}` where `message_id` is 16 random bytes
(`random_message_id()`). Any real burst of messages landing in the same
wall-clock second (phase 1 of the 100-message test sends 25 in a tight
loop) therefore came back in **effectively random order**, not the order
they were actually sent — confirmed empirically: the failing test's
panic output showed content like "alice burst 10", "bob reply 22", "bob
reply 6", "alice turn 6" interleaved with no relation to send order.

This is a real, user-visible bug: a chat history rendered straight from
`list_messages` (exactly what `ui/src-tauri/src/lib.rs`'s `list_messages`
command does — no re-sorting on the frontend) could show messages out of
order whenever more than one landed in the same second, which ordinary
fast typing or a burst of replies makes common, not rare.

**Fix implemented and tested**: added `Db::message_sequence`, an
in-memory `AtomicU64` (reset on every `create`/`open` — sufficient
because it only needs to disambiguate messages saved within the same
wall-clock second, which can only happen within one continuous process
run) and a `sequence: u64` field on `Message`, assigned by
`save_message_now` via `fetch_add`. `list_messages` now sorts by
`(timestamp, sequence)`. Regression tests:
`store/src/messages.rs::tests::messages_sharing_the_same_timestamp_still_sort_by_insertion_order`
(5 messages, one shared timestamp, asserts insertion order is preserved)
and `save_message_now_assigns_increasing_sequence_numbers` (asserts the
real production call path assigns strictly increasing sequence numbers).
Confirmed fixed end-to-end by re-running
`app/tests/full_conversation_100_messages.rs` after the fix — passes,
all 100 messages come back on both sides in the exact order they were
sent.

Checked whether the frontend needs a matching change: `ui/src-tauri/src/lib.rs`'s
`MessageDto`/`to_message_dto` carry no ordering field, and
`ui/src/routes/+page.svelte` never re-sorts the array `list_messages`
returns — it renders it as-is. No frontend change needed; the backend
fix alone corrects what the UI displays.

**Options considered** (for completeness — the option actually taken is
listed first):
1. **(Taken) In-memory monotonic sequence counter, compound sort key.**
   Minimal, no cross-restart persistence complexity, and no migration
   concern since there are no deployed databases predating this fix.
2. Switch `now_unix()` to millisecond or microsecond resolution. Narrows
   the window but doesn't close it — two messages in the same
   millisecond is still possible under real load (e.g. two devices on a
   fast LAN, or `receive_pending` decrypting a stored batch faster than
   the clock ticks), and doesn't fix already-affected historical data
   any better than option 1. Rejected as a partial fix to the same
   problem option 1 solves completely.
3. Persist a per-conversation sequence counter across restarts (e.g. a
   dedicated redb counter key, incremented transactionally with each
   save). Strictly stronger (survives process restarts, not just
   same-run bursts) but adds real complexity — a persisted counter needs
   its own crash-consistency story — for a property that in practice
   never matters across a restart (wall-clock time has moved on by then,
   so `timestamp` alone already disambiguates). Rejected as
   unnecessary complexity for no practical benefit over option 1.

## `DeliveryAck` (found building and testing `ARCHITECTURE.md` §4.6)

### 27. A writer's own not-yet-collected mailbox entry is fetchable by the writer itself
**Tested (new)**: found while building `DeliveryAck`, then reproduced and
fixed at the layer it actually lives in — the server's mailbox, not the
app. `ARCHITECTURE.md` §11.1's final adopted fix makes a conversation's
`mailbox_id` **bidirectional**: both sides write to and fetch from the
exact identical address (`store::routing::compute_mailbox_id` is a
symmetric, order-independent hash). The server (`server/src/ws.rs`,
before this fix) returned *every* entry in a mailbox to *whoever* fetched
it, with no notion of "entries I wrote" vs. "entries my peer wrote."

Consequence: if a device ever calls `receive_pending` on a conversation
after writing to that same mailbox but before its peer has fetched-and-
deleted that entry, it fetches its own envelope back. Decrypting it with
the *receiving* side of the ratchet fails the AEAD check every time (it
was encrypted with the sender's own *sending* chain key, not a key the
receiving side has), gets classified as a per-entry content error, and —
this is the actually damaging part — **`receive_pending` still deletes it
as "processed" afterward**, exactly like any other consumed entry. The
message is gone from the mailbox forever, and the real recipient never
gets it. No error surfaces to the user; it just silently vanishes.

This was a real, latent risk for *ordinary chat* from the moment §11.1's
bidirectional mailbox was adopted, not something `DeliveryAck` introduced
— but every existing test's choreography happened to avoid it (the sender
never called `receive_pending` between sending and the recipient's
fetch). `DeliveryAck` turns this from a rare, avoidable-by-convention edge
case into the *common* case: it writes an ack back to the shared mailbox
on every single received chat message, and a normal polling client (this
project's `poll_loop`) has no reason not to poll again almost immediately
after. Confirmed via `app/tests/receive_pending_resilience.rs`'s existing
regression test failing outright once `DeliveryAck` started writing acks
(it expected a second `receive_pending` call to see nothing new, and
instead saw the client's own just-sent acks come back and get skipped).

**Fixed**: `server/src/state.rs`'s `MailboxEntry` gained a `written_by`
field (the authenticated identity that wrote it); `MailboxFetch`
(`server/src/ws.rs`) now excludes entries the fetcher itself wrote. New
tests: `server/tests/integration.rs::a_writer_never_sees_its_own_not_yet_collected_entry`
(a bare write-then-immediately-fetch-with-the-same-identity proves the
entry no longer comes back) and
`app/tests/delivery_ack.rs::polling_immediately_after_sending_does_not_self_consume_the_message`
(the real, at-the-application-layer version of the exact scenario that
broke). `server/tests/integration.rs::mailbox_write_fetch_delete_round_trips`
(a pre-existing test that happened to write and fetch with the same
identity) was updated to use two identities, matching how the mailbox is
actually used; `server/tests/stress.rs`'s concurrency test similarly
switched its per-iteration mailbox fetch to a second, throwaway-identity
connection.

**Options considered** (the option taken is listed first):
1. **(Taken) Server-side `written_by` filtering.** Minimal, symmetric with
   how the server already authenticates every connection, and closes the
   gap for every message type through this mailbox (chat, acks,
   `RoutingIdAnnounce`, wipe messages), not just `DeliveryAck`. No wire
   format change visible to a well-behaved client — `MailboxFetch`'s
   request/response shapes are unchanged, it just returns fewer, correct
   entries.
2. Client-side heuristic: before attempting to decrypt an entry, check
   whether its `dh_pub` matches the client's own current *sending* chain's
   public key, and skip (without deleting) anything that does. Rejected:
   fragile across DH ratchet steps (a client's own dh_pub changes over
   time, and reconstructing "was this ever one of my own sending keys"
   client-side means keeping a growing history around just to answer this
   one question), and every client would need this logic independently —
   the server already has the authoritative answer for free from the
   authenticated connection it's already checking.
3. Split the bidirectional mailbox into two unidirectional ones (a
   per-direction `mailbox_id` instead of one symmetric one). Closes the
   gap by construction — a device only ever fetches from the mailbox its
   peer writes to — but is a real wire-protocol change (both sides would
   need to derive and track two ids per conversation instead of one,
   coordinate which is "theirs," and this is exactly the design §11.1's
   own "second gap" section already explored and rejected for unrelated
   reasons: a rotating-with-the-ratchet id can't be computed by both sides
   at a mutually-known moment). Rejected as disproportionate to the
   problem when option 1 closes it completely at the layer that already
   has the right information.

### 28. `DeliveryAck.acked_n` collides across sending chains
**Analyzed + tested, then fixed**: a real, previously-open limitation in
`DeliveryAck` itself (`core::payload::DeliveryAck`, `docs/MESSAGE_SCHEMA.md`
§7), closed in a follow-up pass after being recorded here.

`acked_n` is the ratchet header `n` of the message being acknowledged —
but `n` only disambiguates messages *within one sending chain*. Every
Double Ratchet DH step (which, per `docs/DELIVERY_FAILURE_FINDINGS.md`'s
own module doc and `ARCHITECTURE.md` §3.3, happens on nearly every message
in ordinary back-and-forth chat) resets the new chain's `n` back to 0. The
wire schema originally carried no `dh_pub` alongside `acked_n` to say
which chain produced it, so a receiver of an ack could only match it back
against its own sent messages by `acked_n`'s bare value.

The original implementation (`Db::mark_message_delivered`) resolved this
by picking the **oldest undelivered** locally-sent message with a
matching `send_n` — correct as long as a chain's messages got acked
before the next chain's `n` values started repeating, which held for the
ordinary turn-taking `app/tests/delivery_ack.rs::acks_flow_correctly_in_both_directions`
and the 100-round exchange exercise, but wasn't a hard guarantee: two
messages sent in genuinely different, still-unacked-at-the-time chains
that happened to share an `n` (e.g. both `n=0`, the single most common
case since every fresh chain starts there) would have been
indistinguishable to the receiver of their acks, with the wrong one
possibly marked delivered.

**Fixed**: `DeliveryAck` now carries the acknowledged envelope's `dh_pub`
alongside `acked_n` (`MESSAGE_SCHEMA.md` §7's updated schema) — the same
`(dh_pub, n)` pair `RatchetState`'s own skipped-message-key cache already
keys by (`core/src/ratchet.rs`'s `SkippedEntry`), a real,
already-proven-unique identifier for one specific message.
`Message::send_dh_pub` (`store/src/messages.rs`) records it alongside
`send_n` at send time, and `Db::mark_message_delivered` now matches
`(dh_pub, n)` exactly instead of picking the oldest same-`n` candidate —
this was option 1 below, taken as originally described. New test:
`store/src/messages.rs::mark_message_delivered_disambiguates_same_n_across_different_chains`
constructs two locally-sent messages from different chains that both
have `n = 0` and proves each incoming ack now flips the *correct* one,
never the other — the exact ambiguity this finding originally described,
now provably closed rather than merely narrowed. The existing turn-taking
tests (`acks_flow_correctly_in_both_directions`, the 100-round exchange)
continued passing unchanged after the field was added, confirming the fix
is transparent to the ordinary, non-colliding case.

**Options considered** (the option taken is listed first):
1. **(Taken) Extend `DeliveryAck` with the acknowledged envelope's `dh_pub`.**
   Fully disambiguates — `(dh_pub, n)` together are exactly
   `RatchetState`'s own skipped-message-key cache key, a real,
   already-proven-unique identifier for one specific message. Required a
   `MESSAGE_SCHEMA.md` §7 schema change (one more `bytes(32)` field) — a
   real but small wire change, backward-incompatible with any
   already-deployed client, but none exist yet, so no migration cost.
2. **Track a locally-unique, monotonic per-conversation send counter**
   (distinct from the ratchet's own `n`) and echo *that* back in the ack
   instead of the ratchet header's `n`. Would have fully disambiguated
   without needing `dh_pub` at all, reusing the same "in-memory monotonic
   counter" pattern finding #26 already established for `Message::sequence`.
   Rejected in favor of option 1: it would have made the ack no longer
   literally acknowledge "ratchet position `n`" (the originally-specified
   semantic) but "the `k`-th message I ever sent in this conversation" — a
   deliberate schema *meaning* change, not just an added field, for no
   benefit over option 1 once option 1 was confirmed small enough to ship
   directly.
3. **Leave it as documented behavior, narrow the risk window instead.**
   E.g., have a sender refuse to start a new chain (hold outgoing sends)
   until all of the previous chain's messages are acked or a timeout
   elapses. Rejected as the worst option: trades a rare, low-severity
   ambiguity for real send-latency/backpressure complexity, and Double
   Ratchet's whole design point is *not* forcing turn-taking to be
   strictly synchronous.

## Piggyback ack (found building and testing the TCP-style cumulative ack, `ARCHITECTURE.md` §4.6a)

### 29. `PiggybackAck.highest_n` could claim a permanently-skipped message as delivered — **fixed**

**Severity: high** — a false *positive* delivery confirmation, not a false
negative. Every other finding in this document is some form of "a genuinely
delivered message reads as undelivered" (annoying, but the sender still
knows to be skeptical). This one is the opposite and worse for an E2E
messenger: the sender sees `delivered: true` — full confidence — for a
message the recipient never actually received and never will.

Found live, not by code review: a two-real-instance Xvfb UI test built to
demonstrate `4.6a`'s "uncertain" indicator and its piggyback resolution
(this session's own verification of that feature) killed the relay server
between a recipient's genuine decrypt of one message and their dedicated
`DeliveryAck` reaching the sender — deliberately reproducing the exact
race `4.6a` exists to cover. A *second*, unrelated message from the same
sender had been silently lost before the recipient ever saw its envelope
at all (the same in-memory-mailbox loss finding #27's neighbors already
established). Once the recipient's next real reply resolved the *first*
message via its `PiggybackAck`, the *second, genuinely never-received*
message also flipped to `delivered: true` on the sender's screen —
confirmed at the local-database level, not just the UI. See the session
transcript's three screenshots: the recipient's own window proves it never
received that message's content, while the sender's window shows it
double-checkmarked anyway.

**Root cause**: `RatchetState::receiving_progress()` reported `recv_n - 1`
as `highest_n` — the receive chain's raw cryptographic position, which
advances past a *skipped* message (out-of-order arrival, or permanent
loss) exactly the same way it advances past one whose content was
genuinely decrypted. `MESSAGE_SCHEMA.md` §7a's own contract for
`highest_n` ("I have successfully decrypted every message from `n = 0`
through `highest_n`, inclusive") was correct as written; the code just
didn't live up to it, since `recv_n` alone can't distinguish "decrypted"
from "skipped over."

**Fixed**: `RatchetState` now tracks `content_delivered_contiguous`
(`core/src/ratchet.rs`) separately from `recv_n` — advanced only by a
message whose content was actually decrypted, and only contiguously from
`0`; an out-of-order arrival ahead of a still-missing message is held in
`content_delivered_out_of_order` until the gap closes, never reported
early. `receiving_progress()` now reports this instead of `recv_n - 1`,
and resets to "nothing yet" on every DH ratchet step, same as `recv_n`
conceptually always should have for this purpose. Five new unit tests in
`core/src/ratchet.rs` (`receiving_progress_never_claims_a_permanently_skipped_message_as_delivered`
chief among them) lock in the corrected contract; the existing
`app/tests/uncertain_delivery_piggyback.rs` continued passing unchanged,
confirming the fix is transparent to the ordinary, non-skipped case it
already covered.

**A real consequence of the fix, not a limitation to work around**: a
permanently-skipped message now correctly blocks *every* later message on
that chain from being piggyback-resolvable too, not just the skipped one
— matching genuine TCP cumulative-ack semantics, where a gap in the byte
stream can't be acked around either. `DeliveryAck` (§7, unaffected by this
fix) still resolves each of those later messages individually and
immediately in the ordinary case; only the piggyback backstop is scoped
this strictly, and only for the remainder of that one chain's lifetime
(a fresh DH ratchet step starts the tracking over).

## Per-conversation wipe (found and fixed testing a genuinely single-sided `request_conversation_wipe`, `ARCHITECTURE.md` §11.9a)

### 30. An un-announced `include_session` preference desynced the two sides' ratchets — **fixed**

**Severity: high** — a real, silent, *unrecoverable* session desync, not
a delivery-status cosmetic. `store::wipe_policy`'s own doc states
`effective_wipe_include_session` is "most-restrictive-wins": either side
wanting the fuller (ratchet-destroying) wipe should mean *both* get it.
That only actually held when the preference had been separately announced
(`ConversationWipePolicyAnnounce`, `payload_type = 4`) and landed on the
peer's side *before* the wipe request arrived — `PAYLOAD_CONVERSATION_WIPE_REQUEST`
itself carried no policy data at all (empty content), so the merge had
nothing to work with on the recipient's side beyond their own,
possibly-stale local preference.

Found via a real, no-mocks test (`app/tests/single_sided_wipe_request.rs`)
built to verify a genuinely single-sided wipe (only one party ever calls
`request_conversation_wipe`, matching this session's fault-injection
testing pattern) against the design's own documented merge semantics: a
requester who sets `include_session = true` only in their own local
`Contact` record — the same state a UI bug, or simply racing the "announce
first" step, would produce — computes their *own* effective decision as
`true` (their own local flag alone is sufficient) and destroys their own
ratchet. The peer, having received no announcement, still computes
`false` and only wipes messages. The two sides now permanently disagree
about whether a session exists. The requester's own follow-up test
assertion confirmed the real, user-visible consequence: the peer, unaware
anything is wrong, sends an ordinary reply on their still-live ratchet,
and the requester — who has none — gets a hard `NoSession` error with no
automatic recovery path, not a graceful re-pairing prompt.

**Fixed**: `request_conversation_wipe` now carries the requester's own
`include_session` preference directly in the request content
(`core::payload::ConversationWipeRequestContent`, `MESSAGE_SCHEMA.md`
§10's updated schema) — the recipient's `apply_entry` now computes
`own_preference OR requester's_preference` for *this* wipe specifically,
correctly implementing most-restrictive-wins without depending on any
prior announcement having landed. Four tests in
`app/tests/single_sided_wipe_request.rs` lock this in: the default-policy
(messages-only) case leaves the session usable afterward; an `uncertain`
message gets wiped cleanly rather than orphaned; the exact
previously-desyncing scenario now closes both ratchets together
(`include_session_no_longer_desyncs_the_peer_even_when_never_announced`);
and a positive control confirms the properly-announced-first path still
works as it always did, proving the fix addresses the announce-ordering
gap specifically rather than being a coincidental pass.

**A known, smaller residual gap, left as-is rather than expanding this
fix's scope**: the "ask before delete" gated path
(`effective_wipe_ask_before_delete()` — unanimous, both sides must have
opted in) doesn't persist the request's carried preference between
`receive_pending` setting `Contact::wipe_request_pending` and
`confirm_pending_wipe` actually running the wipe later, so the same class
of gap could in principle still occur there. Judged lower priority: it
requires *both* sides to have already unanimously opted into
ask-before-delete in the first place, a much smaller population than the
default (auto-comply) path finding #30 covers, and the human confirming
the wipe sees a UI moment where a mismatch could plausibly be caught
before real harm, unlike the fully automatic auto-comply path.

## Boundary-scoped wipe edge cases (found and fixed auditing `wipe_conversation_since`, `ARCHITECTURE.md` §11.9a's boundary-scoped follow-up to finding #30)

### 31. A policy announcement and the wipe request it gates, landing in the same poll, silently downgraded to the old unscoped behavior — **fixed**

**Severity: high.** The boundary-scoped wipe (protecting messages a peer
already had before they learned of a policy change) and the older
ask-before-delete gate both depend on `Contact` fields a
`ConversationWipePolicyAnnounce` sets. `receive_pending`
(`app/src/lib.rs`) fetches a batch of mailbox entries and processes each
one against a single `Contact` snapshot captured *once, before the loop
starts* — correct for verification state (which genuinely can't change
mid-batch) but not for wipe policy, since an announcement can itself
arrive earlier in that same batch and update the persisted record while
the snapshot the wipe-request arm reads never picks it up. The realistic
trigger isn't adversarial: a peer who was simply offline for a while and
catches up in one poll gets an announce, some new messages, and a wipe
request delivered together — completely ordinary, not a race someone
has to engineer.

Two concrete consequences, found via real, no-mocks tests
(`app/tests/scoped_wipe_edge_cases.rs`) built specifically to reproduce
this same-batch condition rather than reasoning about it from the
source:

- **Boundary bypass**: a peer with genuine pre-boundary history already
  stored, who then receives the announce *and* the wipe request in one
  batch, had that history wiped anyway — the exact protection this
  feature exists to provide, silently lost the moment the peer happened
  to be offline when the policy changed.
- **Ask-before-delete bypass**: with both sides configured to require
  confirmation, a wipe request arriving in the same batch as the
  confirming announce auto-applied instead of setting
  `wipe_request_pending` — deleting content without the confirmation
  both sides had explicitly opted into. (Pre-existing — this shares
  `receive_pending`'s stale-snapshot design, not something the boundary
  feature introduced — but it sits on the same code path this audit was
  already exercising, and finding #30's own "known, smaller residual
  gap" note anticipated this exact failure mode without yet having a
  reproduction.)

**Fixed**: `apply_entry`'s `PAYLOAD_CONVERSATION_WIPE_REQUEST` arm now
reloads the `Contact` fresh from disk (`db.load_contact`) immediately
before making its ask-before-delete or boundary decision, instead of
trusting the batch-stale snapshot — a `ConversationWipePolicyAnnounce`
processed earlier in the same batch is now visible to the wipe-request
arm processed later in it. `receive_pending`'s own doc comment, which
previously (incorrectly) claimed wipe-policy decisions shared
verification state's "safe to use the stale snapshot" property, is
corrected to explain why they don't. Both
`same_batch_announce_and_wipe_request_when_peer_is_offline_the_whole_time`
and `same_batch_ask_before_delete_announce_and_wipe_request`
(`app/tests/scoped_wipe_edge_cases.rs`) flip from failing to passing
under this fix, with no changes to the tests themselves — they were
written expectation-first, stating the documented behavior before the
fix existed.

### 32. A crash mid-wipe left conversations genuinely half-wiped, with no signal anything was wrong — **fixed**

**Severity: high.** `wipe_conversation`/`wipe_conversation_since`
(`store/src/wipe_policy.rs`) looped and called `delete_message` once per
message. `Db::delete` opens and commits its own `write_txn` per call
(`store/src/db.rs`), so each individual deletion was genuinely durable —
but the loop as a whole had no wrapping transaction, so nothing stopped
a real process death between two iterations.

Confirmed empirically, not just reasoned about, with a self-forking
experiment: a worker process reproducing the loop's exact logic was
`SIGKILL`ed at a deterministic point (synchronized on the worker's own
progress output, not a timing guess). Reproduced across every run: the
on-disk `Db` always reopened cleanly afterward (`redb`'s per-transaction
durability held — no corruption), every pre-boundary message always
survived, but the wipe itself was left genuinely partially applied —
roughly half the post-boundary messages that should have been removed
were still there, with nothing stored to distinguish "not yet processed"
from "correctly protected."

**Fixed**: `Db` gained `delete_many` (`store/src/db.rs`) — every key
removed in **one** `write_txn` instead of one per key.
`wipe_conversation`/`wipe_conversation_since` now collect every in-scope
key (messages, and the ratchet if `include_session`) first, then remove
them all in a single `delete_many` call. A crash can now only land
before that transaction commits (conversation untouched, exactly its
pre-wipe state) or after (conversation fully wiped) — never a partial
result. Re-run against the fixed function: 30+ real `SIGKILL` trials
across two message-count scales, sweeping a range of kill delays,
produced zero partial outcomes — every trial landed on exactly one of
the two valid states. Landed as a permanent, `#[ignore]`d regression test
— `app/tests/crash_mid_wipe_atomicity.rs`,
`cargo test -p dratchet-app --test crash_mid_wipe_atomicity -- --ignored
--nocapture` — rather than a one-off manual experiment: it re-execs the
compiled test binary itself as a real subprocess (libtest's own
`--exact --ignored` selecting just the worker test, parameters passed
via environment variables, since `#[test]` functions take none) so a
future regression here would need someone to notice it wasn't run, not
rediscover the bug from scratch.

### 33. `Db::message_sequence` resetting to 0 on `open` broke its own tie-break guarantee across a same-second restart — **fixed**

**Severity: medium**, but a real, reproducible flake, not hypothetical —
first surfaced as an intermittent failure in
`boundary_persists_across_a_real_db_restart_when_processed_in_separate_polls`
(`app/tests/scoped_wipe_edge_cases.rs`), which passed reliably in
isolation but failed when run alongside other tests in the same process
(timing-dependent, not test-order-dependent). `Message::sequence`'s own
doc comment asserted a fresh-every-run counter was fine because "that
[a same-second collision] can only happen within one continuous run" —
an assumption `Db::open` resetting the in-memory counter to `0` (same as
`Db::create`) makes false the moment a real restart lands in the same
wall-clock second as messages saved just before it, which a fast
app-relaunch (or, in the failing test, back-to-back operations with no
real delay) can absolutely do.

Concrete consequence: `Contact::peer_wipe_boundary_sequence`
(`record_peer_wipe_policy`) persists a sequence value stamped by the
*pre-restart* counter. A message saved shortly after a same-second
restart gets a sequence number from the *post-restart* counter,
restarted at `0` — which can be numerically lower than the persisted
boundary's sequence component, so `wipe_conversation_since`'s
`(timestamp, sequence) >= boundary` comparison ties on `timestamp` and
then wrongly reads the tie-break as "before the boundary," protecting a
message that should have been in scope for the wipe.

**Fixed**: `Db::open` now recovers the counter's correct starting value
from what's already on disk (`messages::recover_message_sequence`: `1 +`
the highest `sequence` any stored message, across every conversation,
currently has, or `0` if there are none) instead of naively resetting to
`0` — `Db::create` is untouched, since starting at `0` is correct there
(nothing stored yet). A new regression test,
`sequence_survives_a_real_restart_within_the_same_wall_clock_second`
(`store/src/messages.rs`), saves messages, does a real `Db` close +
reopen, saves one more, and asserts strict ordering holds across the
restart. `boundary_persists_across_a_real_db_restart_when_processed_in_separate_polls`
has since passed cleanly across 5+ consecutive runs, both isolated and
alongside the rest of its file.

### Verification (findings #31–33)

All three fixes landed together on `explore/wipe-crash-consistency`
(forked from the tip of the boundary-scoped-wipe work) before folding
back: full workspace `cargo fmt`/`clippy -D warnings`/`cargo test`
green, including `ui/src-tauri`'s own clippy pass; the two same-batch
tests in `scoped_wipe_edge_cases.rs` confirmed flipping from failing to
passing under the fix; the restart test confirmed stable across repeated
runs, both isolated and in its full file; and the crash-mid-wipe
experiment re-run against the fixed, atomic `wipe_conversation_since`
produced zero partial outcomes across every trial.

## Duress-wipe atomicity (found probing `Db::quick_wipe`/`full_wipe` for the same class of gap findings #31–33 fixed in the boundary-scoped wipe)

### 34. `quick_wipe`/`full_wipe` rotated or destroyed their keys *last*, so a crash mid-call could leave content still recoverable under the still-live original key — **fixed**

**Severity: high.** Both duress-wipe entry points (`store/src/db.rs`) did
their bulk deletion first and their actual security-establishing step
last, "belt-and-suspenders" style:

- `quick_wipe` looped, deleting every message/ratchet record
  individually, *then* rotated the content DEK.
- `full_wipe` scan-deleted every key in the database, *then* — as part
  of that same loop, no earlier — removed the salt and wrapped DEK
  records that make the file unopenable at all.

Neither loop was wrapped in a single transaction (same shape as finding
#32), so a real crash partway through either one left exactly the
opposite of what a duress wipe is for: some content still fully
decryptable under a key that was never destroyed, because the delete
loop hadn't reached it yet when the process died — while anything the
loop *had* already reached was gone. Whether a device seized or killed
mid-wipe ends up "safe" or "still holds live plaintext" came down to
which records the loop happened to have reached yet, not anything the
caller could rely on.

**Fixed**, mirroring #32's "security action first, cleanup second"
pattern exactly:

- `quick_wipe` now rotates the content DEK — one atomic write — as its
  very first step. The instant that commits, every message/ratchet
  record already on disk is permanently unrecoverable, regardless of
  whether the delete loop that follows ever completes. That loop (now
  itself batched into one `delete_many` call rather than one
  transaction per record) is reclaiming space, not establishing the
  guarantee.
- `full_wipe` now destroys the salt and all three wrapped DEKs (identity,
  contacts, content) together in one `delete_many` transaction as its
  very first step — `Db::open` needs the salt to derive a master key at
  all, so the instant that commits the file is permanently unopenable by
  any passphrase. The full-table scan-delete that follows is likewise
  now just best-effort space reclamation.

All 14 pre-existing wipe-related tests (`cargo test -p dratchet-store
wipe`) and the full 66-test store suite passed unmodified against the
reordering — this is a pure ordering fix, not a behavior change any
existing test observes from the outside.

### A separate, environment-level finding surfaced while proving #34, out of scope for this fix

Building a real-`SIGKILL` regression test for #34
(`store/tests/duress_wipe_crash_consistency.rs`, same self-re-exec
technique as `crash_mid_wipe_atomicity.rs`) surfaced something #34's own
code changes can't address: on this environment, a `SIGKILL` landing
during an *active* `redb` transaction commit can occasionally leave the
file unable to reopen at all — a decrypt failure on a record the wipe
in progress hadn't even touched, not the expected "content now
unreadable" outcome. Diagnostic isolation (a zero-messages trial
exercising only the rotation write, with no delete loop at all) confirmed
this reproduces even for a single, lone record write with no relation to
`quick_wipe`'s own logic — ruling out its ordering or its delete loop as
the cause. Batching the delete loop into one `delete_many` transaction
(applied as part of #34's own fix, independent of this) narrowed the
window considerably — reproducible at up to ~200ms of kill delay before
batching, only a much narrower window afterward — but did not eliminate
it.

This points at a write-barrier/durability question in how this specific
container's filesystem (or `redb` on it) handles a real `SIGKILL` landing
exactly mid-commit, not a dratchet code defect — plausibly absent on real
target hardware, and orthogonal to every wipe-atomicity fix in this
document, all of which are about crashes landing *between* transactions,
not *during* one. `duress_wipe_crash_consistency.rs` reports it as its
own honest outcome category (`TrialOutcome::ReopenFailed`, distinct from
`RotatedAndSecure`/`NotRotatedYet`) rather than asserting it can't
happen or hiding it inside a broader pass/fail. A confirmation run (10
trials, 20–200ms delay sweep) landed 9/10 `RotatedAndSecure`, 1/10
`ReopenFailed`, 0/10 insecure/partial — consistent with a narrow,
low-probability window rather than a systemic one. Worth its own
investigation at the `redb`/filesystem level if it recurs; not blocking
for #34, which only claims (and only needs to claim) that *whenever* the
file does reopen after a kill, the security ordering held.

### Verification (finding #34)

`cargo build -p dratchet-store` / `cargo fmt --check` / `cargo clippy -p
dratchet-store --all-targets -- -D warnings` / full `cargo test -p
dratchet-store` (66 passed) all clean on the reordered `quick_wipe`/
`full_wipe`. New regression test `store/tests/duress_wipe_crash_consistency.rs`
(`#[ignore]`d — real subprocesses, real `SIGKILL`s; run with `cargo test
-p dratchet-store --test duress_wipe_crash_consistency -- --ignored
--nocapture`) confirmed: across 10 real-kill trials, every trial where
the file reopened and the rotation had committed showed content
permanently unrecoverable — never once a message surviving readable next
to a rotated key.
