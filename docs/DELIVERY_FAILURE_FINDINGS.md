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

## Directory persistence atomicity (item 2 of the same edge-case sweep — confirmed already sound, no fix needed)

Probed for the same class of bug findings #32/#34 fixed — a multi-step
durable write with no wrapping transaction, so a crash partway through
leaves an inconsistent on-disk state — against `server/src/persistence.rs`'s
`Persistence::save`, the directory's own durable-write path
(`docs/ARCHITECTURE.md` §6.1). Reading the code first rather than
assuming: `try_save` already does its entire write — CBOR-encode, then
one `begin_write`/`insert`/`commit` — as a single `redb` transaction per
call, and every call site in `ws.rs` (a publish/rename, or a one-time-
prekey consumed by `FetchBundle`) mutates exactly one fingerprint's
record per logical operation. There's no second record that write ever
needs to stay in sync with: `Inner::username_index` is never itself
persisted — `AppState::with_persistence` rebuilds it at startup purely
from each loaded `StoredBundle`'s own `username`/`discriminator` fields
— so it structurally can't drift out of sync with the one table that is
persisted. Unlike `quick_wipe`/`full_wipe`, there was never a "which
step runs first" ordering question here to get wrong.

Not left as an unverified reading of the code, though — this session's
standing rule has been to prove atomicity claims against a real
`SIGKILL`, not reason about them from source, so a new test,
`server/tests/persistence_crash_consistency.rs` (`#[ignore]`d, same
self-re-exec-subprocess technique as `duress_wipe_crash_consistency.rs`;
run with `cargo test -p dratchet-server --test
persistence_crash_consistency -- --ignored --nocapture`), seeds a
"before" record, overwrites it from a real worker subprocess carrying a
distinctly-marked "after" record (padded to 20,000 one-time prekeys so
the encode-plus-commit takes long enough, real wall-clock time, for a
kill to land inside it), and `SIGKILL`s the worker across a swept range
of delays. Confirmed over 10 trials (4 landed before the commit, 6
after): the reloaded record was always *exactly* one of the seeded
"before" state or the fully-written "after" state — the same two-valid-
outcomes shape as finding #32's fix — never a record with fields mixed
between the two writes, and never a record silently lost. No code change
was needed; this is a confirmation, not a fix.

## DRA-0012: Concurrent `receive_pending` calls (item 3 of the same edge-case sweep — confirmed real, now fixed in two layers)

Probed the type-level question directly: does anything about
`app::receive_pending`'s own signature rule out two overlapping calls for
the same conversation, the way `&mut Db` would if that were the
signature? It didn't — `db: &Db` is a shared reference (`Db`'s methods
rely on `redb`'s own transaction isolation, not exclusive access), and
`conn: &mut Connection` only rules out reusing *one* `Connection` value
twice at once, not a second, independently-authenticated `Connection`
for the same account calling concurrently.

Proven, not just reasoned about, with a real end-to-end test,
`app/tests/concurrent_receive_pending_race.rs`: two separate
connections for the same account, racing `receive_pending` for the same
contact via `tokio::join!` against two real queued messages. Confirmed
outcome (pre-fix): genuine content duplication — both calls each
independently loaded the ratchet at the same starting state, each
fetched and processed the same mailbox entries, and each stored its own
copy, so 2 real messages sent produced 4 stored on the receiving side.
The ratchet itself, however, was left self-consistent in every trial —
whichever call's `db.save_ratchet` landed last fully determined the
persisted state, and a message sent afterward still decrypted normally;
the race duplicated content, it did not permanently desync the
conversation.

**Fixed, in two independent layers, rather than left as a documented
caller invariant:**

1. **`Db::receive_lock(conversation_id)`** (`store/src/db.rs`) — a
   per-conversation `tokio::sync::Mutex`, created on first use and never
   removed, backed by a `HashMap` guarded by a plain `std::sync::Mutex`
   (held only for the instant it takes to look up/clone the `Arc`, never
   across an `.await`). `receive_pending` (`app/src/lib.rs`) now acquires
   this lock for its entire body, immediately after computing `conv_id`.
   A second overlapping call for the *same* conversation now blocks on
   `.lock().await` until the first call finishes — including its own
   `MailboxDelete`/ack round trips — rather than racing it. A call for a
   *different* conversation is unaffected (a distinct `Arc<Mutex<()>>`
   per `conv_id`), so this doesn't serialize unrelated traffic. This
   turns the invariant `receive_pending`'s doc comment used to just
   *state* into one the function actually enforces, regardless of
   caller — closing exactly the gap this finding's "Not fixed inside
   `receive_pending` itself" note used to describe.
2. **`Db::save_received_message_idempotent`** (`store/src/messages.rs`)
   — a second, independent backstop behind the lock. Received chat
   messages now record the ratchet header they arrived with
   (`Message::recv_dh_pub`/`recv_n`, mirroring the existing
   `send_dh_pub`/`send_n` pair already used for sent messages). Before
   inserting a new message, this checks whether one already exists for
   the same `(conversation_id, recv_dh_pub, recv_n)` — a ratchet header
   is never legitimately reused for different content, the same property
   `send_dh_pub`/`send_n` already relied on — and returns the existing
   record instead of storing a duplicate if so. This guards against any
   future caller that bypasses the in-process lock entirely (e.g. a
   second OS process against the same on-disk `Db` file, which a
   `tokio::sync::Mutex` can't reach), and incidentally also closes the
   already-accepted crash-recovery duplicate case (an undeleted mailbox
   entry reprocessed on the next `receive_pending` call after a crash
   mid-batch) for free.

Re-run of `app/tests/concurrent_receive_pending_race.rs` against the fix
confirms the exact outcome the lock predicts: call A (whichever wins the
race) delivers both real messages, call B's own `MailboxFetch` — which
now runs only after call A's `MailboxFetch`/decrypt/`MailboxDelete` cycle
has already completed — sees an empty mailbox and delivers 0. Exactly 2
messages stored, never 4, and a message sent afterward still decrypts
normally. Full workspace `cargo fmt --check` / `cargo clippy --workspace
--all-targets -- -D warnings` / `cargo test --workspace` all pass with
this change.

## UI double-fire on the "Confirm clear" wipe button (item 4 of the same edge-case sweep — confirmed narrow, fixed)

`clearConversation` (`ui/src/routes/+page.svelte`)'s second click — the
one that actually calls `request_conversation_wipe` — guarded against a
double-fire with `disabled={clearBusy}`, a reactive `$state` binding set
synchronously at the top of that branch. Reasoning alone couldn't settle
whether that's actually enough: Svelte's reactive DOM updates flush on a
microtask, not necessarily before a second, already-dispatched click
event is processed, so the real question was purely empirical.

Tested live in a real Chromium instance (not jsdom, not a mock DOM)
against the actual, unmodified `+page.svelte` served by a real Vite dev
server — only the Tauri native IPC bridge was stubbed
(`window.__TAURI_INTERNALS__.invoke`), the standard way to exercise
Tauri frontend code outside the native shell. Two click scenarios:

- **Playwright's native `dblclick`** (real mousedown/mouseup pairs at a
  realistic OS double-click interval — the actual mechanism a human
  double-clicking a mouse produces): the guard held. Exactly one
  `request_conversation_wipe` call, every run.
- **Two raw `click` events dispatched back-to-back with zero delay
  between dispatch calls** — tighter than any real mouse or OS input
  queue can produce, but not provably unreachable (a macro mouse,
  scripted input, or a future automated-test harness could do this):
  **confirmed real** — two `request_conversation_wipe` calls, both
  landing before `clearBusy`'s reactive update had painted.

**Fixed**: added `clearInFlight`, a plain (deliberately non-`$state`)
module-scope boolean checked and set synchronously as the very first
statement of the confirm branch, before the reactive `clearBusy`
assignment. A plain variable has no reactive-flush lag to race — closes
the zero-delay gap outright, with no dependency on Svelte's render
timing. Re-ran both scenarios against the fixed code: both now show
exactly one call. `npm run check` clean.

Not escalated further than this: even before the fix, a double-fire's
worst-case consequence was contained on both ends — `db.wipe_conversation`/
`_since` are proven atomic (finding #34's neighbors) so a second local
wipe is a harmless no-op, and a duplicate `ConversationWipeRequest`
reaching the peer is likewise a no-op on their side (`apply_entry`'s
wipe-request arm re-scopes from the same boundary either time). The fix
here closes the gap because it was cheap and fully proven, not because
the alternative was unsafe.

## DRA-0014: Any registered identity could read and delete another identity's pending first-contact mail (penetration test, priority 1: access; confirmed real, fixed)

Penetration-test pass, priority 1 ("gaining access to individual messages
or entire conversations"). Audited `server/src/ws.rs`'s `MailboxWrite`/
`MailboxFetch`/`MailboxDelete` handlers directly for an ownership check —
found none. All three require only `authenticated.ok_or(Error::AuthRequired)?`:
*some* identity must have completed the connection-level auth handshake,
but nothing ties the caller to the specific `mailbox_id` they name. The
implicit security model is that `mailbox_id` itself is an unguessable
capability — true for the post-transition, routing-id-derived id
(`store::routing::compute_mailbox_id`, an HKDF output over private
material only the two participants ever learn), **not** true for
`bootstrap_mailbox_id` (`core::x3dh`): deliberately
`SHA256("dratchet-x3dh-bootstrap-v1" || recipient_fingerprint)`, so the
*intended* recipient's own client can compute it before any relationship
exists — but a recipient's fingerprint is public (needed for X3DH,
discoverable via `FetchBundle`/the username directory), so *anyone* can
compute the same id for *any* registered user.

`bootstrap_mailbox_id`'s own doc already named a narrower version of this
as a bounded, intentional trade-off: "a relay can observe someone wrote
to this recipient." What it didn't cover — and what a new real,
no-mocks test (`server/tests/mailbox_ownership_gap.rs`) proved against
the pre-fix server — is that the exposure wasn't limited to the server
operator observing linkability metadata. With no ownership check on the
handlers themselves, **any other registered account** got full read
*and delete* access to a third party's queued first-contact attempts:

1. Attacker looks up the victim's username via the ordinary, intended
   `FetchBundle` directory lookup — gets their public fingerprint.
2. Attacker computes `bootstrap_mailbox_id(victim_fingerprint)` locally —
   the exact same value any real sender's client would compute — and
   calls `MailboxFetch` on it directly. No pairing, no prior contact,
   no special privilege: confirmed receiving a real sender's genuine
   pending first-contact envelope, verbatim ciphertext.
3. Attacker calls `MailboxDelete` on that entry. Confirmed: the real
   sender's pairing attempt is now permanently gone. There is no
   delivery-ack at the pre-pairing stage, so neither the sender nor the
   victim is ever notified — a silent, targeted denial-of-service against
   any specific relationship trying to form, repeatable at will by any
   registered account against any other, with zero prior relationship
   required.

Message *content* was never at risk — everything read was still AEAD
ciphertext, consistent with the server-breach guarantee `breach.rs`
already proves — so this doesn't break end-to-end confidentiality. The
real impact is unauthorized read access to routing/existence metadata
(who is attempting to contact whom) plus a genuine, low-effort,
repeatable denial-of-service primitive against the pairing flow
specifically, exercisable by anyone with an account on the server.

**Fixed**: `mailbox_id_belongs_to_someone_else` (`server/src/ws.rs`)
rejects `MailboxFetch`/`MailboxDelete` with a new `Error::NotMailboxOwner`
whenever the requested `mailbox_id` matches a *different* registered
identity's `bootstrap_mailbox_id` — scanning the in-memory directory
(`O(directory size)` per call, accepted as a small self-hosted service's
reasonable tradeoff over adding a separate reverse-index cache; worth
revisiting if the directory ever grows large). `MailboxWrite` is
deliberately left unrestricted (first-contact delivery must still work
for anyone), and a genuine post-transition `mailbox_id` is unaffected —
it's an HKDF output over private routing-id material, astronomically
unlikely to collide with any registered identity's `bootstrap_mailbox_id`.

Re-ran `mailbox_ownership_gap.rs` against the fix in the same test: the
attacker's `FetchBundle`-based discovery still works (expected — that's
the intended directory feature), but the follow-on `MailboxFetch`/
`MailboxDelete` against the victim's bootstrap mailbox are now both
rejected with `NotMailboxOwner`, while the real sender's write and the
real victim's own fetch/delete continue to work exactly as before. Full
workspace `cargo fmt --check` / `cargo clippy --workspace --all-targets
-- -D warnings` / `cargo test --workspace` all pass.

**Known residual scope, stated explicitly rather than left implicit**:
this fix only protects identities that are in the in-memory directory at
check time (i.e., have called `PublishBundle`) — the same population an
attacker would need the directory lookup for in the first place. An
identity whose fingerprint leaked through some other out-of-band channel
without ever publishing a bundle is not covered by this specific check;
that residual case was judged out of scope for this fix since it
requires a fingerprint leak this protocol doesn't otherwise cause.

## DRA-0015: No per-mailbox entry-count or envelope-size cap (penetration test, priority 2: denial of service; already documented as scenario 5/6, now fixed)

Penetration-test pass, priority 2 (denial of service). This gap was
already characterized earlier this session as scenario 5/6 (item 5&6
above): `ws.rs`'s `MailboxWrite` handler pushed to an unbounded `Vec`
with no check on either the number of entries a mailbox could hold or
the size of any one envelope — confirmed at the time with a real test
writing 2,000 entries and a 1 MiB envelope, all accepted. That earlier
pass stopped at documenting the gap ("worth an explicit cap... not
implemented here"); this penetration-test pass closes it.

Impact, concretely: since `Inner::mailboxes` is a plain in-memory
`HashMap<MailboxId, Vec<MailboxEntry>>` with no eviction beyond
TTL-based pruning on fetch, any authenticated identity (or, combined
with DRA-0014's now-fixed gap, previously even an uninvolved one against
someone *else's* bootstrap mailbox) could force the server to hold an
arbitrarily large amount of memory: an unbounded number of entries in a
single mailbox, each of unbounded size, with no TTL expiry helping until
someone actually fetches that mailbox to trigger `prune_expired`. A
single connection, over a few seconds, could queue gigabytes into one
mailbox with a target TTL long enough to persist until a real client
happened to poll it — real resource exhaustion, not just a theoretical
gap.

**Fixed**: two new constants in `server/src/state.rs`:
`MAX_ENVELOPE_LEN` (64 KiB — 4x `core::payload::MAX_PADDED_LEN`'s own 16
KiB ceiling on any real client's padded plaintext, so no legitimate
envelope is anywhere close) and `MAX_MAILBOX_ENTRIES` (256 — generous for
real offline-queueing, while bounding one mailbox's worst case to 16
MiB instead of unbounded). `MailboxWrite` now rejects an oversized
envelope with `Error::EnvelopeTooLarge` before touching any state, and
rejects a write to an already-full mailbox with `Error::MailboxFull`
(checked *after* `prune_expired`, so a mailbox isn't punished for
entries that would be dropped on the next fetch anyway).

`server/tests/delivery_failures.rs`'s `scenario_05_06` test was rewritten
from "confirms no cap exists" to "confirms the cap is enforced at exactly
the right boundary": fills a mailbox to precisely `MAX_MAILBOX_ENTRIES`
(every one of those writes must still succeed — the cap must not be
off-by-one in the restrictive direction), confirms the next write is
rejected, then separately confirms an envelope exactly at
`MAX_ENVELOPE_LEN` succeeds while one byte over is rejected. Full
workspace `cargo fmt --check` / `cargo clippy --workspace --all-targets
-- -D warnings` / `cargo test --workspace` all pass.

**Known residual scope, stated explicitly**: this bounds *one mailbox's*
worst case, not the server's total memory — nothing yet caps how many
*distinct* mailbox ids a single identity (or many colluding identities)
can create, so `Inner::mailboxes`' `HashMap` itself can still grow
without bound across many different mailbox ids, each individually
under the new per-mailbox cap. Closing that fully would need either a
global entry-count budget across the whole server or a per-writer rate
limit on distinct mailboxes created (mirroring `crate::abuse`'s existing
per-target/per-requester `FetchRateLimiter` pattern) — named here as a
follow-up, not implemented in this pass since it's a materially larger
change (a new abuse-resistance primitive, not a bounds check) and the
per-mailbox cap already closes the specific, demonstrated worst case
(one flooded mailbox) at a fraction of the risk.

## DRA-0016: A contact could spoof another known contact's exact displayed handle (penetration test, priority 3: poisoning/corrupting a conversation's identity; confirmed real, fixed)

Penetration-test pass, priority 3 (poisoning/corrupting messages or
conversations) — this time not the ciphertext itself (every AEAD/replay
path checked this session was already solid: `untag_and_unpad` bounds-
checks its length prefix, `is_per_entry_content_error` correctly
classifies every per-entry decode failure as skippable rather than
batch-aborting, `ChatContent::decode`'s errors round-trip through
`Error::Core` exactly as needed) but the *identity label* a conversation
displays under.

`store::profile::record_peer_profile` handles an incoming
`PAYLOAD_PROFILE_ANNOUNCE` — a rename, per `docs/MESSAGE_SCHEMA.md`.
Unlike `PAYLOAD_CHAT`, this payload type is never gated by
`store::gate` (`apply_entry`'s `PAYLOAD_PROFILE_ANNOUNCE` arm calls it
directly, no verification-state check — correct for its purpose,
`ARCHITECTURE.md` calls this out as protocol metadata, not chat
content) — so *any* contact can send one, verified or still Pending.
`record_peer_profile` itself, though, applied whatever
`username`/`discriminator` the announce carried to *that one contact's*
own record with no check against every *other* contact already known
locally. Confirmed with a real store-level test
(`store::profile::tests::record_peer_profile_refuses_to_impersonate_an_already_known_contacts_handle`,
run against the pre-fix code first): a second, entirely distinct,
never-verified contact announcing the exact same `username#NNNN` an
already-known, unrelated contact uses succeeded silently — both
fingerprints then displayed identically in the sidebar
(`ui/src/routes/+page.svelte` renders `contact.handle` with no
fingerprint or other disambiguator visible to the user).

Impact: messages are still addressed and encrypted by fingerprint
internally, never by the displayed handle, so this can't redirect or
decrypt anyone else's actual conversation. The real risk is social —
identical labels in the sidebar invite a user to open the *impostor's*
thread believing it's their real, already-trusted contact, and type
something sensitive into it. A conversation's *identity*, not its
content, is what gets poisoned.

**Fixed**: `record_peer_profile` now checks the announced
`(username, discriminator)` against every other locally-known contact
(`Db::list_contacts`) before applying it. A collision with a *different*
fingerprint's current handle is declined exactly like an announce that
changes nothing — `Ok((contact, false))`, no error, so this needed no
change to `apply_entry`'s error handling and can't newly wedge a batch
the way an `Err` here would have. A genuine, non-colliding rename (the
overwhelmingly common case — someone actually changing their own
handle) is completely unaffected, proven by a second new test,
`record_peer_profile_still_allows_a_genuine_non_colliding_rename`.

Full workspace `cargo fmt --check` / `cargo clippy --workspace --all-targets
-- -D warnings` / `cargo test --workspace` all pass (store crate:
67 → 69 tests).

**Known residual scope, stated explicitly**: this closes the collision
at the moment a *new* announce arrives — it does not retroactively
audit already-stored contacts for a collision that predates this fix
(not a live threat model change on this branch: this session's own test
databases are always fresh), and a truly simultaneous pair of
`ProfileAnnounce`s for the same handle arriving in the same
`receive_pending` batch is resolved by ordinary first-write-wins (the
first one processed claims it; the second is then correctly seen as a
collision) rather than any more elaborate arbitration — judged
sufficient since the attacker in this scenario is choosing the
colliding handle deliberately, not racing a legitimate rename.

## DRA-0017: One side of a shared mailbox could exhaust the whole entry cap, blocking the other side's own writes (penetration test round 2, priority 3: denial of service for a single conversation; confirmed real, fixed)

Penetration-test round 2, re-examining DRA-0015's own fix rather than a
fresh area: `MAX_MAILBOX_ENTRIES` closed unbounded growth of one
mailbox, but the cap is enforced on the mailbox *as a whole*, and a
mailbox is bidirectional (`ARCHITECTURE.md` §11.1 — both participants in
a conversation write to and fetch from the identical `mailbox_id`).
Nothing stopped one side from filling the *entire* cap with their own
entries, at which point the *other* side's own legitimate `MailboxWrite`
into that same shared mailbox was rejected too, with the exact same
`Error::MailboxFull` as if they were the flooder.

Confirmed with a real test (`server/tests/single_conversation_mailbox_starvation.rs`,
run against the pre-fix code first): Bob, an ordinary already-paired
contact — not a stranger, not exploiting any other gap — fills the
shared mailbox to `MAX_MAILBOX_ENTRIES` with his own entries. Alice, who
has done nothing wrong and has no way to detect the mailbox is already
full until she tries, then attempts to send Bob one real message. Her
write is rejected. Bob has unilaterally, silently denied Alice's
outgoing communication in *this one conversation* — a targeted,
single-conversation DoS, exactly the "denial of service for a...
conversation" scenario this round's penetration test was scoped to look
for. (Not a regression DRA-0015 introduced — before that fix existed at
all, the equivalent attack was strictly easier, an unbounded flood — but
a related gap DRA-0015's own fix didn't close.)

**Fixed**: a new `state::MAX_ENTRIES_PER_WRITER_PER_MAILBOX` (half of
`MAX_MAILBOX_ENTRIES`) caps each *writer's own share* within a mailbox,
enforced in `MailboxWrite` alongside the existing total cap. Neither of
the two normal participants in a conversation can ever be locked out of
writing by the other's volume alone, whatever the other side does with
their own half. A new, distinct `Error::WriterQuotaExceeded` (rather
than reusing `MailboxFull`) lets a client eventually tell "I'm the one
over my own quota" apart from "the mailbox itself is generically full,"
useful groundwork for a future UI signal.

Since a single writer can no longer reach the *total* cap alone,
`scenario_05_06`'s count-cap assertion (`server/tests/delivery_failures.rs`,
DRA-0015) needed updating to use two distinct writers each filling
exactly their own share — rewritten and re-verified rather than left
subtly wrong. Full workspace `cargo fmt --check` / `cargo clippy
--workspace --all-targets -- -D warnings` / `cargo test --workspace`
all pass.

**Known residual scope, stated explicitly**: this assumes the normal
two-party mailbox model DRA-0015 was built around. If more than two
distinct identities ever write to the same `mailbox_id` (only possible
today via the bootstrap mailbox — and DRA-0014 already restricts who
can *fetch*/*delete* there, though writes remain intentionally open to
anyone attempting first contact), a third writer still gets their own
full `MAX_ENTRIES_PER_WRITER_PER_MAILBOX` share on top of the other
two's, so the *total* cap (not per-writer) is what ultimately bounds
that case — already covered by DRA-0015's existing total-cap check.

## DRA-0018: Unbounded distinct mailbox creation — server-wide denial of service (penetration test round 2, priority 3: denial of service against all clients; confirmed real, fixed)

Penetration-test round 2, closing the residual scope DRA-0015 already
named but didn't fix: `MAX_MAILBOX_ENTRIES`/`MAX_ENTRIES_PER_WRITER_PER_MAILBOX`
(DRA-0015/DRA-0017) bound how much one *existing* mailbox can hold, but
nothing bounded how many *distinct* mailbox ids `Inner::mailboxes`
could ever grow to at once. `MailboxWrite` requires no pre-existing
relationship with its target — any authenticated identity can write to
any 16-byte `mailbox_id`, and a not-yet-seen id was inserted via
`.entry(mailbox_id).or_default()` with no check on the total number of
keys already tracked.

Confirmed with a real test (`server/tests/unbounded_mailbox_creation.rs`,
run against the pre-fix code first): a single connection, looping
`MailboxWrite` with a fresh random `mailbox_id` each time, made the
server accept 500 entirely distinct mailboxes in one unthrottled burst
with zero resistance — no rate limit, no per-identity cap, nothing.
Unlike DRA-0015/DRA-0017 (bounded to one conversation), this is a real
"all clients" denial of service: scaled up, a single attacker forces
unbounded server memory allocation, degrading or crashing the service
for every other client, not just one conversation. Exactly the
"denial of service... for all clients" scenario this round's
penetration test was scoped to look for.

**Fixed**: a new `abuse::NewMailboxRateLimiter`, mirroring the existing
`FetchRateLimiter` token-bucket pattern exactly (Phase 1.2's directory
abuse resistance, `ARCHITECTURE.md` §11.8) rather than inventing a new
mechanism. Keyed by the caller's real authenticated `Fingerprint`
(`MailboxWrite` already requires authentication, unlike `FetchBundle`,
so there's a stable identity to key by directly). Burst capacity 20,
refill one every 30 seconds — deliberately much slower than the fetch
limiter's, since this gates *creating* new server-side state, not
reading already-bounded directory data. Consumed only when the target
`mailbox_id` doesn't already exist in `Inner::mailboxes`, checked in
`ws.rs`'s `MailboxWrite` handler before the `.entry(...).or_default()`
call that would otherwise unconditionally create the key — ordinary
traffic within an already-established conversation (the overwhelming
majority of real usage) never touches this budget at all. A new,
distinct `Error::NewMailboxRateLimited` lets a client tell this apart
from `MailboxFull`/`WriterQuotaExceeded`. Stale buckets are swept
alongside the existing `FetchRateLimiter` ones in
`pruning::sweep_once`.

Re-ran `unbounded_mailbox_creation.rs` against the fix: a burst up to
the limiter's own capacity still succeeds immediately (so adding
several new contacts at once is never throttled), the next brand-new
mailbox is rejected, and — the important negative case — a write into
an *already-existing* mailbox still succeeds even after the new-mailbox
budget is fully exhausted, proving ordinary conversation traffic is
unaffected. New unit tests in `abuse.rs` cover the limiter directly
(burst-then-reject, independent per-writer budgets, stale-bucket
sweeping), mirroring `FetchRateLimiter`'s own test coverage. Full
workspace `cargo fmt --check` / `cargo clippy --workspace --all-targets
-- -D warnings` / `cargo test --workspace` all pass.

**Known residual scope, stated explicitly**, matching `FetchRateLimiter`'s
own accepted limitation (`abuse.rs`'s module doc): this is a per-identity
budget, not a global one — many distinct registered identities (or one
attacker registering many identities, itself gated by the existing
registration proof-of-work) could still collectively create a large
number of mailboxes, each within their own individual rate limit. A
global ceiling on `Inner::mailboxes.len()` would close that fully but
risks rejecting legitimate growth once a real server has many genuine
users; the per-identity throttle was judged the right first line of
defense, raising the cost of a burst substantially (500 mailboxes that
previously cost nothing now costs roughly four hours of sustained
activity from one identity) without capping the service's honest
long-term capacity.

## DRA-0019: Unbounded PublishBundle size — permanent, never-pruned server-wide denial of service (penetration test round 2, priority 3: denial of service against all clients; confirmed real, fixed)

Penetration-test round 2, a second, distinct route to the same class of
harm as DRA-0018 — this time through the directory rather than
mailboxes, and arguably worse: `pruning.rs`'s own module doc states
`directory` is "unbounded-but-intentional, not a pruning target" —
unlike a flooded mailbox (DRA-0015/0017/0018, which self-heals via TTL
expiry and periodic sweeping), **nothing ever removes a directory
entry**. A single oversized `PublishBundle` is a permanent resource cost
for as long as the server runs, not a transient one.

Audited `ws.rs`'s `publish_bundle`/`to_core_bundle` for size or count
validation on `PublishBundle`'s fields and found none on `username` (an
arbitrary-length `String`) or `one_time_prekeys` (an arbitrary-length
`Vec`, each entry's `key` itself an arbitrary-length `Vec<u8>` never
checked against the 32 bytes a real X25519 public key actually is —
only checked, lazily, whichever individual key a later `FetchBundle`
happened to consume). `PublishBundle` deliberately requires no
authentication at all (self-verified by the bundle's own signature
chain — `ws.rs`'s own module doc explains why), so this is reachable by
literally anyone, not even a registered account.

Confirmed with a real test (`server/tests/unbounded_bundle_size.rs`, run
against the pre-fix code first): a single `PublishBundle` carrying
10,000 one-time prekeys — 1,000x `app::ONE_TIME_PREKEY_BATCH` (10), the
real batch size any legitimate client ever publishes at once — was
accepted and stored in full, permanently, in the directory.

**Fixed**: two new constants in `server/src/state.rs` —
`MAX_ONE_TIME_PREKEYS_PER_PUBLISH` (100, 10x the real batch size) and
`MAX_USERNAME_LEN` (64) — checked in `publish_bundle` before any
signature verification or directory work, so a bloated publish is
rejected as cheaply as possible. A second, narrower gap closed in the
same pass: each individual one-time-prekey's byte length is now checked
against the fixed 32 bytes a real X25519 public key always is — before
this, an oversized *individual* key could still sit in the directory
even within a small enough batch, since nothing validated a key's
length until some later `FetchBundle` happened to consume that exact
one.

Re-ran `unbounded_bundle_size.rs` against the fix: the 10,000-prekey
publish is now rejected outright (and, confirmed separately, creates no
directory entry at all — not even a truncated one), while a batch
exactly at the new cap still succeeds normally, proving the fix isn't
overly strict. Full workspace `cargo fmt --check` / `cargo clippy
--workspace --all-targets -- -D warnings` / `cargo test --workspace`
all pass, including every existing test that legitimately publishes
real (small) bundles.

**Known residual scope, stated explicitly**: `identity_key`,
`identity_dh_signature`, and `signed_prekey_sig` remain unbounded at
this specific check site — `identity_dh_public` and `signed_prekey`
already had fixed-size validation before this fix (`to_core_bundle`'s
existing `try_into::<[u8; 32]>()`), and the three remaining fields are
validated downstream by `PrekeyBundle::verify()`'s actual signature
checks, which reject non-conforming lengths as part of normal signature
verification — but that verification runs *after* deserialization, so
an attacker could still force the server to deserialize (though not
permanently store) a single oversized field before rejection. Lower
severity than the two fixed here (bounded to one request's transient
processing cost, not permanent directory growth) and left as a
follow-up rather than expanding this fix's scope further under time
pressure.

## DRA-0020: confirm_pending_wipe performed a destructive wipe with no check that a request was actually pending (penetration test round 3, priority 2: message poisoning/compromise — unauthorized destructive data loss; confirmed real, fixed)

Penetration-test round 3, priority 2 (poisoning/compromise) — after the
crypto/protocol core came back clean across two full rounds
(`untag_and_unpad` bounds-checked, per-entry error classification
correct, `FirstContactWire`'s identity binding verified before use,
`server/src/persistence.rs`'s crash-consistency already sound), this
pass moved to the app layer's own destructive operations and found a
real gap: `confirm_pending_wipe` (`app/src/lib.rs`) — the sole entry
point for §11.9a's "ask before deleting" wipe path, exposed directly as
a Tauri command callable from the webview's JavaScript — performed the
wipe *unconditionally*. Nothing checked that
`Contact::wipe_request_pending` was actually set before deleting real
message history and clearing the flag.

The Svelte UI (`ui/src/routes/+page.svelte`) happens to gate the
"Allow" button's *visibility* on this same flag
(`{#if selected.wipe_request_pending}`), but that's a rendering
decision, not a guard the async handler (`allowPendingWipe`) itself
re-checks before calling `invoke("confirm_pending_wipe", ...)` — and
nothing stops any other caller of the same Tauri command (a stale click
landing after the flag already cleared via another path, a future code
path that forgets the precondition, or any other script able to reach
the webview's `invoke` bridge) from destroying a conversation's history
that was never actually up for deletion. Confirmed with a real,
local-only test (`app/tests/confirm_pending_wipe_requires_pending.rs`,
run against the pre-fix code first): calling `confirm_pending_wipe` on
a contact with `wipe_request_pending: false` deleted two real messages
that were never requested to be wiped.

**Fixed**: `confirm_pending_wipe` now reloads `contact` fresh from `db`
by fingerprint (the same "don't trust the caller's possibly-stale
snapshot" pattern `apply_entry`'s wipe-request arm already established
for a different reason) and refuses with the new
`Error::NoPendingWipeRequest` unless `wipe_request_pending` is actually
set on that fresh record. This is the sole entry point for the
destructive path, so the fix belongs here — not only in the UI that
happens to gate the button on the same flag — closing the gap for
every current and future caller of the Tauri command, not just the one
button that exists today.

Re-ran the test against the fix: the unwarranted call is now rejected
and both real messages survive; a second test confirms a genuinely
pending wipe still succeeds exactly as before and still clears the
flag. Full workspace `cargo fmt --check` / `cargo clippy --workspace
--all-targets -- -D warnings` / `cargo test --workspace` all pass,
including every existing wipe test (which all correctly set
`wipe_request_pending` before calling this, so none needed changes).

## DRA-0021: a conversation-wipe request from a contact who isn't Verified — including one already flagged Mismatch — was processed anyway (penetration test round 3, priority 2: message poisoning/corruption; confirmed real, fixed)

Penetration-test round 3, priority 2 (poisoning/corruption), continuing
past DRA-0020. Two investigative dead ends worth recording first, so
they aren't re-investigated later: (1) `poll_loop`'s reconnect
backoff (`ui/src-tauri/src/lib.rs`) resets to its initial value on every
successful reconnect, which looked at first like a server could force a
tight reconnect loop by accepting-then-dropping — but this is already
an accepted characteristic of the design, not a new gap. (2)
`FetchRateLimiter`'s budget is keyed by `(ConnectionId, target)`, and
`ConnectionId` is a fresh random value per WebSocket connection — so
reconnecting resets a target's fetch budget, which looked like a
bypass of the one-time-prekey exhaustion defense — but `abuse.rs`'s own
module doc already names this exact tradeoff explicitly ("a known,
accepted limitation: reconnecting resets the budget"), so it isn't a
new finding either. (3) The signed prekey is never actually rotated —
`signed_prekey_expires_at` is always published as a literal `0`
(`app/src/lib.rs`) and nothing anywhere checks it — but
`core/src/prekey.rs`'s own doc comment says outright: "Rotated
periodically in the full design; v0 just models the keypair +
signature, not the rotation schedule." An explicitly-scoped-out v0
limitation, not an undiscovered bug.

The real finding: `apply_entry`'s `PAYLOAD_CONVERSATION_WIPE_REQUEST`
arm (`app/src/lib.rs`) never checked `contact.verification_state`
before acting on it. `store::gate`'s mandatory-verification gate
(§6.5) only ever withholds `PAYLOAD_CHAT` content from a non-`Verified`
contact, on the documented theory that everything else is inert
"protocol machinery" safe to let through underneath the gate (the
routing-id exchange has to work before verification completes, for
instance). A wipe request isn't inert, though — unlike routing-id
announces or profile announces, processing it has a real, destructive
local effect: the auto-comply branch calls `wipe_conversation_scoped`
outright, and even the ask-before-delete branch arms a confirmation
prompt the user could be talked into approving. Nothing about either
branch depended on the sender actually being trusted.

The realistic impact is worse than "an unverified first-contact wipes
an empty conversation": `Contact::mark_mismatch` (§6.2/6.3) is a hard
stop specifically for a *detected* identity change — deliberately not
reversible except by a fresh, successful re-verification — and this
gap meant a session already flagged `Mismatch` could still reach in and
delete real, previously-`Verified` message history. Confirmed with a
real, no-mocks test in `app/tests/conversation_wipe.rs`
(`a_wipe_request_from_a_mismatched_contact_is_ignored`), run against
the pre-fix code first: a genuine `Verified` pair (real X3DH via the
directory, real routing-id exchange) exchanges one real message, Bob
then calls the same `record_verification_result(..., false)` path the
app uses on a detected mismatch, and Alice's still-live session sends a
real, validly-encrypted wipe request — proving this is an authorization
gap, not an AEAD/forgery one. Pre-fix, Bob's one real message was
deleted and `outcome.wipe_activity` was `true`.

**Fixed**: the wipe-request arm now reloads the fresh, just-persisted
`Contact` record (the same reload it already needed for the wipe
boundary) and returns `EntryEffect::None` immediately — before touching
either the auto-comply or ask-before-delete branch — unless
`verification_state == VerificationState::Verified`, mirroring exactly
what `decrypt_gated` already does for chat content from the same kind
of untrusted session. Not just the destructive auto-comply path but
also the ask-before-delete path is gated, since arming a confirmation
prompt from a `Mismatch` contact is still a live social-engineering
surface even though it isn't itself destructive.

Re-ran the test against the fix: the real message survives, no
`wipe_activity` is reported, and `wipe_request_pending` isn't even
armed. Re-ran the rest of `conversation_wipe.rs` (all pre-existing
auto-comply, ask-before-delete, decline, and asymmetric-preference
scenarios, all of which use `Verified` contacts throughout) unchanged
and still green — this fix only removes behavior for a strictly
narrower, previously-unintended case. Full workspace `cargo fmt
--check` / `cargo clippy --workspace --all-targets -- -D warnings` /
`cargo test --workspace` all pass.

## DRA-0022: `PairingResponse`'s DH material wasn't bound to its claimed identity, letting an on-path relay MITM the whole session while the later fingerprint check still passed (penetration test round 3, priority 1: gaining access to individual conversations via an active MITM; confirmed real, fixed)

Penetration-test round 3, priority 1 (access), continuing past DRA-0021.
Audited `client/src/handshake.rs` — Option B's direct, out-of-band
pairing flow (`ARCHITECTURE.md` §6.3a): two blobs, copy-pasted between
peers (a QR code in the eventual Tauri UI; this reference CLI just
base64s a CBOR blob), run X3DH with no server or directory involved.
`PairingBundle`, the first blob, correctly binds its `identity_dh_public`
to `identity_key` with a real signature (`identity_dh_signature`,
checked by `PrekeyBundle::verify` inside `handshake::initiate`) —
exactly what `ARCHITECTURE.md` §3.2 requires. But `PairingResponse`, the
blob flowing the *other* direction, carried `identity_dh_public` and
`ephemeral_public` with no such binding at all, even though
`x3dh::respond` uses both as real Diffie-Hellman inputs.

The consequence is a complete session compromise, not just a data-
integrity nit. This round's new `client/tests/pairing_response_mitm.rs`
proves it two ways. First, at the
pure DH-math level, independent of any wire format: given only the
public prekeys `PairingBundle` already exchanges in the open (Bob's
`identity_dh_public` and `signed_prekey`), a party holding no secret
belonging to either Alice or Bob can pick two arbitrary secrets of its
own, substitute the corresponding public keys for Alice's real
`identity_dh_public`/`ephemeral_public`, and derive the *exact same
root key* `x3dh::respond` (called as Bob) lands on —
`a_mitm_can_derive_bobs_root_key_from_only_public_material_without_response_binding`
proves this by deriving both sides independently and asserting they're
identical. Second, end to end: an on-path relay of the pairing blobs
could make exactly this substitution while leaving `identity_key`
untouched — so the fingerprint Bob later verifies out of band against
Alice's real identity would still match, even though the session keys
underneath it were silently forged. This is meaningfully worse than the
already-accepted directory-TOFU-MITM limitation (where an impersonator
would show up as a *different*, mismatching fingerprint, exactly the
case the verification step exists to catch): here the system's own
designed final defense never fires, because the field it never checks
is the one actually being forged.

**Fixed**: `PairingResponse` gained a new `response_signature` field.
`handshake::initiate` now signs `identity_dh_public ‖ ephemeral_public ‖
routing_id` (length-prefixed, tagged `dratchet-pairing-response-v1`) with
the initiator's identity key — `handshake::signing_payload` is the one
function both the signer and the verifier call, so they can't drift
apart on what's actually covered. `handshake::respond` now verifies this
signature against the response's own `identity_key` *before* either DH
field is used, rejecting the response outright if it doesn't verify.
`routing_id` is bound too, not just the two DH values, so a signature
can't be spliced from one pairing exchange onto a different one.

Verified with three tests in `client/tests/pairing_response_mitm.rs`:
the MITM-math proof above (unaffected by the fix, since it demonstrates
the underlying weakness independent of the wire format — the reason the
fix is necessary in the first place); `respond_accepts_a_genuine_untampered_pairing_response`
(the fix must not be overly strict); and
`respond_rejects_a_pairing_response_whose_dh_material_was_tampered_with_after_signing`,
which substitutes a fresh `ephemeral_public` into an otherwise-real,
already-signed response and confirms `respond` now returns `Err` instead
of silently deriving a session key from it. The existing end-to-end
`client/tests/integration.rs` golden path (real pairing, real message
exchange over a real spawned server) still passes unmodified. Full
workspace `cargo fmt --check` / `cargo clippy --workspace --all-targets
-- -D warnings` / `cargo test --workspace` all pass.

**Scope note**: `client/`'s Option B pairing flow is explicitly
documented as this project's reference CLI, not yet wired into the
production Tauri app (`ui/src-tauri/`), which currently only implements
Option A's mandatory-verification, directory-based flow. This fix closes
a real, severe protocol flaw in code that exists and is tested in the
repository today, ahead of whatever UI eventually calls it.
