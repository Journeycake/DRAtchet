# DRAtchet — Server Components

Status: **design draft, no code yet**. Companion to
[`ARCHITECTURE.md`](ARCHITECTURE.md) (see §4 for how these fit into the
tiered delivery model) and [`MESSAGE_SCHEMA.md`](MESSAGE_SCHEMA.md) (wire
formats referenced below).

DRAtchet has exactly two optional server-side components, and neither is a
single always-on backend the way "server" usually implies:

1. **Signaling & Presence Service** — small, mostly-ephemeral, needed for
   Tier 0/Tier 1 delivery (rendezvous, prekey bundle discovery) and for
   online-status.
2. **Recovery Store** — only exists at all if a conversation has opted into
   Tier 2 recovery, and then it's owned by one participant, not shared.

## 1. Signaling & Presence Service

### 1.1 Responsibilities

One small service, four related jobs — kept as one piece of infrastructure
for v1 rather than four, per the open decision in `ARCHITECTURE.md` §10:

1. Prekey bundle directory: publish/fetch by `username#NNNN` (§1 of
   `MESSAGE_SCHEMA.md`).
2. WebRTC rendezvous: relay SDP offer/answer and ICE candidates so two
   clients can establish a direct Tier 0 connection.
3. Tier 1 mailbox: hold ratchet message envelopes transiently (TTL'd) when
   the recipient isn't reachable for direct delivery (`ARCHITECTURE.md`
   §4.2).
4. **Presence**: track and broadcast online/offline status to verified
   contacts — the new piece this section specifies.

None of these require the service to see plaintext, ratchet state, or
long-term private key material.

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
  - User-configurable: extend visibility to Unverified contacts too, or
    disable presence broadcasting entirely (an "appear offline" toggle).
    Default stays the more private option.
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

## 2. Recovery Store (Tier 2)

### 2.1 Per-participant, not shared — and why

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

### 2.2 Deployment profile A — minimal purpose-built server (recommended for v1)

Small, self-hostable HTTP service (e.g. Rust + `axum`). Single-tenant (one
user's own instance) or lightly multi-tenant (e.g. a household or small
team running one instance with a per-user API key each) — either way, one
operator, not a cross-party trust relationship.

| Endpoint | Purpose |
|---|---|
| `PUT /v1/recovery/{conversation_id}/{seq}` | Upload one entry — body is the CBOR `RecoveryBackupEntry` (§5 of `MESSAGE_SCHEMA.md`); `Authorization: Bearer <owner's API key>` |
| `GET /v1/recovery/{conversation_id}?since_seq=N` | Fetch entries after `N`, paginated |
| `DELETE /v1/recovery/{conversation_id}` | Purge all stored entries for one conversation (used on revoke, `ARCHITECTURE.md` §7) |
| `DELETE /v1/recovery` | Purge everything under this API key (full account wipe) |

- Auth is a plain bearer API key the store's owner generates for their own
  client(s) — no cross-party handshake, since the store isn't shared.
- Storage backend is pluggable and treats every entry as opaque
  already-encrypted bytes: flat files, SQLite, or any KV store all work
  equally well server-side.

### 2.3 Deployment profile B — zero-custom-code (direct object storage)

- Client writes directly to an S3-compatible bucket the user already
  controls, using credentials scoped to a `recovery/{conversation_id}/*`
  prefix (bucket policy or short-lived STS-issued credentials).
- No server binary to run at all — for users who want self-hosted recovery
  without operating a service.
- Trade-off vs. profile A: rate limiting, precise delete-everything
  semantics, and audit logging are whatever the cloud provider's bucket
  tooling gives you, not purpose-built. Recommend profile A once a user
  wants more control than "store and fetch blobs."

### 2.4 Cross-party hosting caveat

If one participant offers to host the recovery store the *other*
participant uses — rather than each hosting their own — the trust model
changes: the hosting participant's operator role gives them metadata
visibility (cadence, sizes, timing) into the other participant's *other*
conversations too, if that store is reused across multiple contacts.
Recommend the app default to "each participant configures their own store"
and treat "use my contact's store" as an explicit, clearly-labeled advanced
option — never a default flow, since it quietly weakens exactly the
isolation §2.1 exists to provide.

## 3. Message schemas

Presence protocol messages (`PresenceAnnounce`, `PresenceUpdate`) referenced
in §1.3 above are specified in [`MESSAGE_SCHEMA.md`](MESSAGE_SCHEMA.md) §6.
Recovery Store request/response bodies reuse the `RecoveryBackupEntry`
schema from `MESSAGE_SCHEMA.md` §5 directly — the HTTP layer in §2.2 above
adds only routing (`conversation_id`/`seq` in the URL) and auth, no new
payload shape.

## 4. Open questions

These are also tracked in `ARCHITECTURE.md` §10 alongside the rest of the
project's open decisions; kept here too since they're specific to these two
services.

- **Signing key for the presence handshake (§1.2):** reuse the long-term
  identity key directly, or mint a dedicated per-device signing subkey for
  it? A per-device subkey would let a lost/revoked device be cut off from
  presence and signaling independently of the identity key it was derived
  from, without a full identity rotation — worth doing once multi-device
  (`ARCHITECTURE.md` §9 v2) is in scope, probably unnecessary complexity
  before then.
- **Presence "away" state:** ship the idle-timeout `away` state in v1, or
  keep it to a simpler online/offline-only signal until there's a concrete
  UX reason for the extra state? Low-stakes, doesn't block other work.
- **Recovery Store deployment profile default:** ship profile A (§2.2) only
  for v1, or also document profile B (§2.3) as a supported path from day
  one? Recommend A first since it gives cleaner delete/rate-limit behavior;
  B is a natural v2 addition once there's a reason to support it.
