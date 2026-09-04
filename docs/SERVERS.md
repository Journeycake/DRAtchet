# DRAtchet — Server Components

Status: **design draft, no code yet**. Companion to
[`ARCHITECTURE.md`](ARCHITECTURE.md) (see §4 for how these fit into the
tiered delivery model) and [`MESSAGE_SCHEMA.md`](MESSAGE_SCHEMA.md) (wire
formats referenced below).

DRAtchet's 1:1 model has exactly two *optional* server-side components,
neither a single always-on backend the way "server" usually implies:

1. **Signaling & Presence Service** — small, mostly-ephemeral, needed for
   Tier 0/Tier 1 delivery (rendezvous, prekey bundle discovery) and for
   online-status.
2. **Recovery Store** — only exists at all if a conversation has opted into
   Tier 2 recovery, and then it's owned by one participant, not shared.

Group chat (v2, `ARCHITECTURE.md` §13) adds a third component that is
**not optional**:

3. **Group Coordination Service** (§2 below) — required for any group to
   function at all, since group membership changes need a single agreed-
   upon ordering that direct peer-to-peer coordination can't provide on its
   own (`ARCHITECTURE.md` §13.2). Still never sees message content.

## 1. Signaling & Presence Service

### 1.1 Responsibilities

One small service, four related jobs — kept as one piece of infrastructure
for v1 rather than four, per the open decision in `ARCHITECTURE.md` §10:

1. Prekey bundle directory: publish/fetch by `username#NNNN` (§1 of
   `MESSAGE_SCHEMA.md`) — extended in v2 to a per-account **device list**
   rather than one bundle per account (`ARCHITECTURE.md` §14.2).
2. WebRTC rendezvous: relay SDP offer/answer and ICE candidates so two
   clients can establish a direct Tier 0 connection.
3. Tier 1 mailbox: hold ratchet message envelopes transiently (TTL'd) when
   the recipient isn't reachable for direct delivery (`ARCHITECTURE.md`
   §4.2), addressed by the per-conversation-direction `mailbox_id`
   described there — not a per-device inbox (see `ARCHITECTURE.md` §11.1
   for why) — extended in v2 to an optional two-hop private-routing mode
   so no single relay operator sees both ends of a conversation
   (`ARCHITECTURE.md` §11.2).
4. **Presence**: track and broadcast online/offline status to verified
   contacts — the new piece this section specifies.

None of these require the service to see plaintext, ratchet state, or
long-term private key material.

**Abuse resistance is part of this job list, not an afterthought:**
one-time prekeys (job 1) are consumed per session-establishment attempt, so
the service should rate-limit prekey fetches per requesting identity —
otherwise a malicious actor can repeatedly initiate handshakes against a
victim to exhaust their published one-time prekeys, forcing later real
handshakes to silently degrade to X3DH-without-a-one-time-prekey (weaker
forward secrecy on that session's setup, per the optional field in §3 of
`MESSAGE_SCHEMA.md`). See `ARCHITECTURE.md` §11.8 for the fuller treatment,
including account-registration abuse (username squatting).

### 1.2 Connection & authentication

- Each device holds a persistent WebSocket connection to the service
  whenever the app can maintain one (foreground always; background subject
  to OS/user permission).
- Auth handshake, no separate account system needed:
  1. Server sends a random nonce on connect.
  2. Client responds with `{identity_key_fingerprint, signature}`, where
     `signature` is over the nonce using the device's identity key (or a
     dedicated per-device signing subkey — see §4 below).
  3. Server verifies the signature against the already-public identity key
     it has on file from that account's prekey bundle (§1 of
     `MESSAGE_SCHEMA.md`). No password, no separate login credential.
- This reuses the identity-key trust model everywhere else in the project
  instead of inventing a second one just for the signaling connection.

### 1.3 Presence model

- **State held is in-memory and ephemeral only**: `device_id → {state:
  online | away, last_seen: timestamp}`. No durable log, no database row
  per status change — consistent with the project's serverless/ephemeral
  posture elsewhere. A service restart simply means every connected client
  reconnects and re-announces; nothing is lost that matters.
- **Transitions**: `online` on WebSocket connect plus periodic heartbeat;
  `away` after an idle timeout (open question, §4 below, on whether this
  ships in v1 at all vs. a simpler online/offline-only signal); `offline`
  on disconnect, at which point only `last_seen` is retained — in memory,
  not persisted to disk.
- **Visibility — scoped, not public**:
  - Default: presence is visible only to **Verified** contacts
    (`ARCHITECTURE.md` §6.2). A device can subscribe to presence updates
    only for accounts it has an established or attempted session with —
    there is no arbitrary "look up this username's presence" query. This
    prevents presence from becoming a contact-enumeration or stalking
    oracle.
  - User-configurable: extend visibility to Pending contacts too (useful
    while a verification exchange, `ARCHITECTURE.md` §6.3/§6.4, is still in
    progress), or disable presence broadcasting entirely (an "appear
    offline" toggle). Default stays the more private option.
- **Delivery-tier integration**: before sending, the client checks its
  locally cached presence for the recipient. Online → attempt Tier 0
  rendezvous first. Offline, unreachable, or the Tier 0 attempt times out →
  fall back to the Tier 1 mailbox (if the conversation uses it) or the
  local outbox retry loop (Tier-0-only mode, `ARCHITECTURE.md` §4.1).
- **What this deliberately does not do**: presence is not logged anywhere
  for analytics, not exposed to anyone but verified contacts, and not
  retained past the current connection — see `ARCHITECTURE.md` §8 for the
  one caveat this doesn't fully close (the service operator can observe
  global presence transitions across the whole user base, even though
  individual users can't query beyond their own contacts).

### 1.4 Minimal deployment shape

- No database migrations, no durable message storage. A single-process
  in-memory presence table plus prekey-bundle store is sufficient for
  small/self-hosted deployments; a Redis-backed table is a reasonable
  upgrade path if horizontal scaling matters later. Either way, restarting
  the service loses only current-connection state, not anything users would
  consider data loss.
- The Tier 1 mailbox (job 3 above) does need slightly more durability than
  presence — entries must survive a brief service restart to honor their
  TTL — but stays far short of a database: a KV store with per-key TTL
  (e.g. the Cloudflare Durable Objects/KV option from `ARCHITECTURE.md`
  §4.2, or Redis with `EXPIRE`) covers it without a schema or migrations.

### 1.5 Deployment posture: ephemeral-fallback vs. always-on primary

Everything in §1.1–§1.4 describes the *protocol* this service speaks; how
it's hosted is a separate, orthogonal choice — the same distinction
`ARCHITECTURE.md` §12 draws between the tiered model's default and the
server-based deployment model:

- **Ephemeral-fallback posture (v1 default)**: hosted as short-lived
  serverless functions (Cloudflare Durable Objects/KV or equivalent),
  attempted only after Tier 0 fails or times out (`ARCHITECTURE.md` §4.5).
  Uptime expectations are modest — a brief gap just means more messages sit
  in the sender's local outbox a little longer.
- **Always-on primary posture (the "server-based model," `ARCHITECTURE.md`
  §12.1)**: the identical protocol, hosted on durable, monitored
  infrastructure and treated as the primary path — Tier 0 attempted only as
  a latency optimization, or not at all. This posture is what makes sense
  to pair with the always-relay privacy toggle (`ARCHITECTURE.md` §11.2)
  and with extending the Tier 1 TTL well past the 14-day ephemeral default,
  since a properly operated server can responsibly hold ciphertext for
  longer without it turning into an accidental durable archive.

No protocol or schema difference between the two — same message formats
(§4 below, and `MESSAGE_SCHEMA.md` §6–7), same "never sees plaintext"
guarantee. The difference is entirely operational: uptime SLA, TTL policy,
and whether Tier 0 is attempted at all.

## 2. Group Coordination Service

Required for group chat (v2, `ARCHITECTURE.md` §13) — not optional the way
§1 and §3 are. Section §13.2 of `ARCHITECTURE.md` explains *why* a group
needs this at all: without a single agreed-upon ordering for membership
changes, two participants proposing conflicting adds/removes at the same
time can fork the group into two views of its own membership, and pure
peer-to-peer coordination has no way to resolve that on its own. This
service is that single ordering point — nothing more.

### 2.1 Responsibilities

1. **KeyPackage directory**: publish/fetch MLS `KeyPackage`s (RFC 9420) by
   `username#NNNN`, the group-chat analog of §1.1 job 1's prekey bundle
   directory. A `KeyPackage` is what lets an existing group member add a new
   one without an interactive round-trip with that new member first.
2. **Commit ordering**: for each group (identified by its MLS group ID),
   maintain a single authoritative, strictly increasing epoch sequence.
   Exactly one `Commit` is accepted per epoch; the service's only real job
   here is rejecting a second `Commit` racing against one it already
   accepted for that epoch, so every member converges on the same next
   state instead of forking. The service does not construct, approve, or
   understand the content of a `Commit` — it only decides which one, of
   possibly several submitted concurrently, wins the race for a given
   epoch.
3. **Welcome/Proposal relay**: deliver `Welcome` messages to newly-added
   members and relay `Proposal` messages among current members, the same
   way §1.1 job 3's Tier 1 mailbox relays ordinary ratchet envelopes.
4. **Group roster**: hold the minimal membership list (which identities are
   in which group) needed to know who to relay `Welcome`/`Proposal`/`Commit`
   traffic to. This is new metadata exposure relative to the 1:1 model,
   where a conversation is an opaque `conversation_id` to any server that
   handles it (`ARCHITECTURE.md` §13.4 names this trade-off explicitly
   rather than letting it inherit §8's 1:1 threat model silently).

None of these require the service to see plaintext message content, group
message keys, or the MLS group secret — same guarantee as §1.

### 2.2 Authentication & authorization

- Connection and identity authentication reuse the same nonce-signature
  handshake as §1.2 — no separate account system for groups either.
- **Authorization is not this service's job.** Whether a given member is
  allowed to propose an add/remove, and whether a `Commit` is validly
  signed by a current member, is enforced cryptographically by MLS itself
  (`ARCHITECTURE.md` §13.1/§13.4) — every `Commit` and `Proposal` is signed
  by its sender's identity key, and every client verifies that signature
  independently on receipt. The service orders and relays; it does not
  decide who may change group membership. This keeps the service's own
  compromise or misbehavior from being able to forge a membership change —
  at worst it can reorder, delay, or refuse to relay, not fabricate.

### 2.3 Abuse resistance

- Rate-limit `Commit` and `Proposal` submission per group per identity —
  the group-chat analog of §1.1's one-time-prekey exhaustion protection and
  `ARCHITECTURE.md` §11.8's fuller treatment. Otherwise a single malicious
  or compromised member could spam `Commit`s to churn every other member's
  group state or deny the group forward progress.
- KeyPackage directory abuse resistance mirrors §1.1 job 1 directly (rate
  limits per requesting identity), since it's the same kind of resource.

### 2.4 Minimal deployment shape

Less purely stateless than §1's presence table: Commit ordering needs at
least one durable, monotonically-advancing counter per group epoch — a
race between two concurrently-submitted `Commit`s for the same epoch has to
resolve the same way even if the service restarts mid-decision. In
practice this is still small (one counter/log per active group, not a full
message store): a KV store with compare-and-swap semantics (e.g. the same
Cloudflare Durable Objects tier §1.4 already uses, or a small
Postgres/SQLite table keyed by `(group_id, epoch)`) is enough — no general
message durability requirement beyond the brief relay window for
`Welcome`/`Proposal`/`Commit` traffic itself.

### 2.5 What this deliberately does not do

- Never sees plaintext group message content — those are encrypted under
  MLS application keys the service never holds, exactly like §1 and §3.
- Never decides group membership — only orders and relays already-signed,
  independently-verifiable protocol messages (§2.2).
- Does not retroactively grant a newly-added member access to messages from
  before they joined — `ARCHITECTURE.md` §13.3 covers why (an MLS `Welcome`
  only conveys the current epoch's state, consistent with forward secrecy).
- Roster visibility (§2.1 job 4) is the one new thing this component sees
  that §1 and §3 don't — accepted and named explicitly rather than treated
  as equivalent to the 1:1 model's opacity.

## 3. Recovery Store (Tier 2)

### 3.1 Per-participant, not shared — and why

Each user who opts into recovery for a conversation configures their
**own** recovery destination. Mutual consent (`ARCHITECTURE.md` §7) still
gates whether backup happens *at all* — both sides must explicitly agree
before either side starts writing — but once it's agreed, the storage
itself is single-owner, not a shared resource the two participants jointly
depend on. Three reasons this beats a shared store:

1. **Blast radius.** Compromising one person's store exposes only that
   person's own opted-in conversations — not a multi-tenant target holding
   every DRAtchet user's backups.
2. **Clean deletion semantics.** "Delete my backups" (`ARCHITECTURE.md` §7)
   is unambiguous against your own store. A shared store makes one party's
   unilateral deletion remove the other party's recovery option too, which
   is confusing and sits awkwardly against a decision meant to be mutual
   and considered.
3. **Simpler auth.** Single-owner storage needs only a normal API
   key/bucket credential the owner issues themselves — no cross-party
   capability scheme, no shared secret the server has to arbitrate access
   around.

Because each participant's own client sees both sent and received
plaintext for a conversation, their own store ends up holding a full copy
of that conversation regardless — mutual consent governs whether that
happens at all, not how many independent copies exist once it does.

**Naming note:** the two storage options below are labeled 1/2, deliberately
*not* "profile A/B" — `ARCHITECTURE.md` §7.1 already uses Profile A/B/C for
a different axis entirely (how much conversation *content* gets stored:
full, sent-only, or none). These two options are only about *where and how*
whatever content the effective content-profile allows gets hosted; the two
are independent choices and reusing the same letters for both would make
every cross-reference ambiguous.

### 3.2 Storage option 1 — minimal purpose-built server (recommended for v1)

Small, self-hostable HTTP service (e.g. Rust + `axum`). Single-tenant (one
user's own instance) or lightly multi-tenant (e.g. a household or small
team running one instance with a per-user API key each) — either way, one
operator, not a cross-party trust relationship.

| Endpoint | Purpose |
|---|---|
| `PUT /v1/recovery/{conversation_id}/{seq}` | Upload one entry — body is the CBOR `RecoveryBackupEntry` (§5 of `MESSAGE_SCHEMA.md`); `Authorization: Bearer <owner's API key>` |
| `GET /v1/recovery/{conversation_id}?since_seq=N` | Fetch entries after `N`, paginated |
| `DELETE /v1/recovery/{conversation_id}` | Purge **all** stored entries for one conversation (used when the effective content-profile reaches Profile C, `ARCHITECTURE.md` §7.3) |
| `DELETE /v1/recovery/{conversation_id}?written_by=peer` | Purge only peer-authored entries (used on an A→B content-profile tightening, `ARCHITECTURE.md` §7.3 — leaves this account's own authored entries in place) |
| `DELETE /v1/recovery` | Purge everything under this API key (full account wipe) |

- Auth is a plain bearer API key the store's owner generates for their own
  client(s) — no cross-party handshake, since the store isn't shared.
- Storage backend is pluggable and treats every entry as opaque
  already-encrypted bytes: flat files, SQLite, or any KV store all work
  equally well server-side.

### 3.3 Storage option 2 — zero-custom-code (direct object storage)

- Client writes directly to an S3-compatible bucket the user already
  controls, using credentials scoped to a `recovery/{conversation_id}/*`
  prefix (bucket policy or short-lived STS-issued credentials).
- No server binary to run at all — for users who want self-hosted recovery
  without operating a service.
- The filtered-delete behavior above (peer-authored-only purge) has to be
  done client-side here — list objects under the conversation's prefix,
  inspect each entry's `written_by` field, delete the matching ones — since
  a plain bucket has no server-side filter to call. Client complexity is
  the trade for zero server code.
- Trade-off vs. option 1: rate limiting, precise delete-everything
  semantics, and audit logging are whatever the cloud provider's bucket
  tooling gives you, not purpose-built. Recommend option 1 once a user
  wants more control than "store and fetch blobs."

### 3.4 Cross-party hosting caveat

If one participant offers to host the recovery store the *other*
participant uses — rather than each hosting their own — the trust model
changes: the hosting participant's operator role gives them metadata
visibility (cadence, sizes, timing) into the other participant's *other*
conversations too, if that store is reused across multiple contacts.
Recommend the app default to "each participant configures their own store"
and treat "use my contact's store" as an explicit, clearly-labeled advanced
option — never a default flow, since it quietly weakens exactly the
isolation §3.1 exists to provide.

## 4. Message schemas

Presence protocol messages (`PresenceAnnounce`, `PresenceUpdate`) referenced
in §1.3 above are specified in [`MESSAGE_SCHEMA.md`](MESSAGE_SCHEMA.md) §6.
Rendezvous and mailbox control messages (`RendezvousOffer`/`Answer`,
`MailboxWrite`/`Fetch`/`Delete`) referenced in §1.1's job list, and the
`DeliveryAck` payload they eventually carry, are in `MESSAGE_SCHEMA.md` §7.
Recovery Store request/response bodies reuse the `RecoveryBackupEntry`
schema from `MESSAGE_SCHEMA.md` §5 directly — the HTTP layer in §3.2 above
adds only routing (`conversation_id`/`seq` in the URL, plus the
`written_by` filter on delete) and auth, no new payload shape.
`RecoveryProfileAnnounce` (`MESSAGE_SCHEMA.md` §8) is exchanged directly
between the two conversation participants, not with this service — it
never touches the Recovery Store or the Signaling & Presence Service.
Group Coordination Service traffic (§2 above) — `KeyPackage` publication,
`Welcome`/`Proposal`/`Commit` relay — adopts RFC 9420's own wire encoding
directly rather than a DRAtchet-specific schema, per the decision recorded
in `ARCHITECTURE.md` §13.1; `MESSAGE_SCHEMA.md` does not duplicate that
format, only notes where it's carried.

## 5. Open questions

These are also tracked in `ARCHITECTURE.md` §10 alongside the rest of the
project's open decisions; kept here too since they're specific to these
services.

- ~~**Signing key for the presence handshake (§1.2)**~~ — **resolved** by
  the multi-device roadmap (`ARCHITECTURE.md` §14.3): each device already
  gets its own identity DH key and signed prekey under the per-device
  model (§14.1), so reusing that same per-device key for the presence
  handshake is the natural answer rather than a separate mechanism — a
  revoked device loses signaling access the same way it loses
  message-session access, in one step. No longer open; kept here as a
  record of the question, not a decision still pending.
- **Presence "away" state:** ship the idle-timeout `away` state in v1, or
  keep it to a simpler online/offline-only signal until there's a concrete
  UX reason for the extra state? Low-stakes, doesn't block other work.
- **Recovery Store hosting default:** ship storage option 1, the
  purpose-built server (§3.2), only for v1, or also document option 2,
  direct object storage (§3.3), as a supported path from day one?
  Recommend option 1 first since it gives cleaner delete/rate-limit
  behavior; option 2 is a natural v2 addition once there's a reason to
  support it.
- **Commit-ordering durability tier for the Group Coordination Service
  (§2.4):** is a KV store with compare-and-swap enough at real scale, or
  does per-group Commit ordering need a dedicated small database once
  groups are common? Deferred until there's usage data; not a blocker for
  the v2.0 MVP phasing in `ARCHITECTURE.md` §13.5.
