# DRAtchet — Message Schemas

Status: **design draft, no code yet**. Companion to [`ARCHITECTURE.md`](ARCHITECTURE.md)
— read that first for the protocol rationale (Double Ratchet, X3DH,
§6 peer auth, §7 recovery) — and to [`SERVERS.md`](SERVERS.md) for the two
server components (Signaling & Presence Service, Recovery Store) that some
of the schemas below (§5, §6) are exchanged with. This document is the
concrete wire format for each message type the protocol produces.

## Encoding conventions

Two different encodings, chosen per message type by how hot the path is:

- **Ratchet message envelope** (§2 below) — the thing sent for *every* chat
  message — uses a **fixed binary layout**, not a general serialization
  format. It's on the hot path, sent at chat volume, and benefits from
  minimum overhead and zero-copy parsing. This is also where §3.5 of
  `ARCHITECTURE.md` (why a minimal custom format was chosen over a
  general-purpose one) pays off concretely — see the overhead comparison
  at the end of §2.
- **Everything else** (prekey bundles, the X3DH init message, pairing
  messages, recovery blobs) — sent rarely (session setup, verification,
  backup) — uses **CBOR** (RFC 8949): compact, binary, schema-evolvable via
  map keys (new optional fields don't break old parsers), good Rust support
  (`ciborium`). JSON was considered and rejected for these too: CBOR is
  smaller, has real binary support (no base64 tax for key material), and a
  stricter type model.

All multi-byte integers are big-endian (network byte order). All key
material is raw fixed-size bytes: Ed25519 public keys and X25519 public
keys are both 32 bytes, Ed25519 signatures are 64 bytes — nothing is an
OpenPGP or other certificate/packet object (`ARCHITECTURE.md` §3.1/§3.5).

## 1. Prekey bundle (CBOR)

Published by each client to wherever bundles are discoverable (see
`ARCHITECTURE.md` §4 for the serverless/relay discussion of *where* —
this schema is the same regardless of hosting model).

| Field | Type | Notes |
|---|---|---|
| `username` | text string | self-chosen, §6.1 |
| `discriminator` | uint16 | the `NNNN` in `username#NNNN` |
| `identity_key` | bytes (32) | raw Ed25519 public key, the account's long-term signing identity (`ARCHITECTURE.md` §3.1) |
| `identity_dh_public` | bytes (32) | raw X25519 public key, the long-term X3DH identity DH key `IK` — a separate keypair from `identity_key`, not derived from it (`ARCHITECTURE.md` §3.1) |
| `identity_dh_signature` | bytes (64) | raw Ed25519 signature over `identity_dh_public`, by `identity_key` — binds the DH key to this identity the same way a signed prekey is bound (§3.2) |
| `signed_prekey_id` | uint32 | monotonic per-account counter |
| `signed_prekey` | bytes (32) | raw X25519 public key |
| `signed_prekey_sig` | bytes (64) | raw Ed25519 signature, by `identity_key` |
| `signed_prekey_expires_at` | uint64 | unix seconds; rotated on schedule (§3.2) |
| `one_time_prekeys` | array of `{id: uint32, key: bytes (32)}` | each consumed once, then removed from the published bundle (§3.4) |
| `registration_pow` | optional uint64 | proof-of-work solution, required only when publishing a `username`/`discriminator` not already owned by this bundle's own identity — directory abuse resistance (§11.8), added in Phase 1.2 after the fields above; a rotation/republish of an already-owned username omits it |

## 2. Ratchet message envelope (fixed binary layout)

The payload for every ongoing chat message, once a session is established.

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 1 | `version` | protocol version tag, allows future format changes |
| 1 | 16 | `conversation_id` | `SHA-256(sorted(fingerprint_A, fingerprint_B))[:16]` — both sides compute this independently; no server needs to mint it (relevant for the serverless model in `ARCHITECTURE.md` §4) |
| 17 | 32 | `dh_pub` | sender's current ratchet public key (X25519) — the "next message's public key" from the original brief |
| 49 | 4 | `pn` | length of the sender's *previous* sending chain |
| 53 | 4 | `n` | message number within the current sending chain |
| 57 | 4 | `ciphertext_len` | only needed on transports without native message framing (see note below) |
| 61 | `ciphertext_len` | `ciphertext` | AEAD ciphertext; the 16-byte AEAD tag is appended by the AEAD API and counted inside this length |

**Header authentication:** bytes `0..61` (everything except the ciphertext)
are passed as AEAD associated data — authenticated (tamper-evident) but
sent in clear text. This is the standard Double Ratchet trade-off: `dh_pub`,
`pn`, `n`, and `conversation_id` are visible to anything that can see the
wire, including a relay if one is in the path. That's a metadata leak
(reveals turn-taking and rough message volume, though not content), tracked
as a known gap in `ARCHITECTURE.md` §8 and as an open decision (header
encryption) in `ARCHITECTURE.md` §10, rather than solved here.

**Payload type:** the plaintext (before padding, inside what becomes
`ciphertext`) starts with a 1-byte `payload_type` tag: `0 = chat message`,
`1 = DeliveryAck` (§7), `2 = RecoveryProfileAnnounce` (§8),
`3 = RoutingIdAnnounce` (§7), `4 = ConversationWipePolicyAnnounce` (§10),
`5 = ConversationWipeRequest` (§10), `6 = FirstContactContent` (§3 — the
one exception to "every payload here travels inside an ordinary envelope
already backed by a session": this one is the content of a
`FirstContactWire.envelope` specifically, encrypted under a root key just
derived, not an existing ratchet's chain key), `7 = ProfileAnnounce`
(§11), reserved values for future control payloads (e.g. a `ReadReceipt`,
`ARCHITECTURE.md` §4.6).
This is what lets a recipient tell a chat message apart from a control
message like `DeliveryAck` or `RecoveryProfileAnnounce` after decrypting —
all travel inside the same ratchet envelope and get the same
confidentiality/padding treatment; nothing about a control message is
distinguishable on the wire before decryption.

**Padding:** the tagged plaintext (`payload_type` + content) is padded to a
fixed bucket size before encryption — e.g. the next multiple of 160 bytes,
up to a cap, beyond which it pads to the next larger bucket — so
`ciphertext_len` doesn't directly reveal exact message length
(distinguishing a one-word reply from a longer message by size alone, or
fingerprinting content by its exact byte count — and, now, distinguishing a
`DeliveryAck` from a short chat message by size). Inspired by Signal's
message padding; see §11.3 of `ARCHITECTURE.md` for the full rationale.

**Implementation note (v0, `core/src/payload.rs`):** padding turned out to
need one more field than described above — a `content_len: u32 LE`
immediately after `payload_type`, before the content itself. Zero-byte
padding isn't self-delimiting: content that itself happens to end in `0x00`
bytes (realistic for binary CBOR payloads like `RecoveryProfileAnnounce`)
would otherwise be silently truncated on unpad, indistinguishable from
padding. The explicit length prefix removes the ambiguity; it's still
inside the padded, encrypted region, so it adds no observable-on-the-wire
size signal beyond what padding already introduces.

**Nonce:** not transmitted. The AEAD encryption key *and* the 12-byte nonce
are both derived from the per-message key via HKDF (`HKDF(message_key) →
{enc_key(32B), nonce(12B)}`) — since each message key is single-use by
construction (§3.3/§3.4 of `ARCHITECTURE.md`), a derived rather than
transmitted nonce is safe and saves 12 bytes on every message.

**Transport framing note:** on a message-oriented transport (WebRTC
DataChannel, QUIC datagram) the surrounding transport already delimits each
message, making `ciphertext_len` redundant — it's kept in the schema so the
same envelope also works unmodified over a byte-stream transport (raw
TCP, or a relay that concatenates queued envelopes in one fetch response).

**Overhead:** 61-byte header + 16-byte AEAD tag = **77 bytes of fixed
overhead per message**, regardless of payload size. That's the concrete
number behind the §3.5 decision in `ARCHITECTURE.md` — a full-OpenPGP-framed
equivalent (packet headers + MPI-encoded fields across a PKESK/SKESK +
SEIPD packet pair) typically runs several times that for a short chat
message.

## 3. First contact: `FirstContactWire` (CBOR) — **implemented**

The *first* message of a new session, and the actual, shipped shape of
what this section used to describe only speculatively (an
"X3DH session-establishment message" carrying just
`initiator_identity_fingerprint`, and a separate `PairingChallenge`/
`PairingResponse` exchange in what was §4). Both are superseded by this
single message, built around `docs/ARCHITECTURE.md` §6.4's now-atomic,
pairing-code-gated add-contact flow: a leaked or guessed `username#NNNN`
must never be enough by itself to make an attempt appear on someone's
device, so the code the recipient generated and shared out of band
*before* anything was sent travels inside this same message, checked
before any `Contact` record is ever created.

`core::first_contact::FirstContactWire`, sent via an ordinary
`MailboxWrite` to `bootstrap_mailbox_id(recipient_fingerprint)` — not
wrapped in a ratchet envelope itself, since the recipient has no ratchet
to decrypt anything with until they've derived one from this message's
own cleartext fields. Distinguishable on receipt from an ordinary §2
envelope because that's a fixed-layout binary format, not CBOR.

| Field | Type | Notes |
|---|---|---|
| `initiator_identity_key` | bytes (32) | the initiator's raw Ed25519 signing public key — self-certifying, same as `PublishBundle`'s `identity_key` (§1); the recipient derives the fingerprint from it directly |
| `initiator_identity_dh_public` | bytes (32) | `IK_A`, the X3DH identity DH key |
| `initiator_identity_dh_signature` | bytes | binds `initiator_identity_dh_public` to `initiator_identity_key` — verified before trusting anything derived from these fields, the same check `PublishBundle`'s bundle-signature verification does |
| `initiator_ephemeral_public` | bytes (32) | `EK_A`, fresh per session |
| `used_signed_prekey_id` | uint32 | which of the recipient's signed prekeys was used |
| `used_one_time_prekey_id` | uint32, optional | omitted if the recipient had none available (X3DH degrades gracefully but loses one DH term) |
| `envelope` | bytes | a §2 ratchet envelope, encrypted under the HKDF-derived root key, `payload_type = PAYLOAD_FIRST_CONTACT` (§2's payload-type list), content = the `FirstContactContent` below |

`FirstContactContent` (the `envelope` field's decrypted payload —
encrypted, unlike everything above, so a passive observer of the relay
never sees the pairing code, only the same public key material a
directory fetch already exposes):

| Field | Type | Notes |
|---|---|---|
| `pairing_code` | string (6 digits) | the code the recipient generated and read out over an already-trusted channel |
| `username` | string | the initiator's own registered username, so the recipient's client can label the new contact without a directory round-trip |
| `discriminator` | uint16 | the initiator's own registered discriminator |

**On receipt**: the recipient checks the enclosed `pairing_code` against
whatever it currently has stored for itself (single-use, short TTL,
rate-limited attempts — §6.4). A match creates an already-`Verified`
`Contact` and consumes the code; anything else — no code stored, wrong
code, expired, attempts exhausted, or a bad identity-binding signature —
deletes the mailbox entry and produces no other effect at all: no
contact, no error, no reply to the sender. There is no delivery receipt
either way, the same limitation every other ungated protocol message in
this document already has.

## 4. Superseded — see §3

This section used to describe a separate `PairingChallenge`/
`PairingResponse` exchange for §6.4's remote pairing, speculative and
never implemented. `FirstContactWire`'s `pairing_code` field (§3) folds
that exchange directly into first contact instead — do not implement the
shape this section used to describe.

## 5. Recovery backup entry (CBOR) — §7 opt-in recovery

Written to whichever recovery store an account has configured for itself
(§3.1 of `SERVERS.md` — per-participant, not shared). One entry per
message, independent of the ratchet's own `n`/`pn` counters so recovery
ordering never depends on live ratchet internals.

| Field | Type | Notes |
|---|---|---|
| `conversation_id` | bytes (16) | same derivation as §2 |
| `seq` | uint64 | monotonic per-conversation sequence number, assigned locally |
| `ciphertext` | bytes | `AEAD(plaintext)` under the conversation recovery key, independent key from any ratchet message key |
| `created_at` | uint64 | unix seconds |
| `written_by` | 1 byte enum: `0 = self`, `1 = peer` | who authored the underlying message, from the perspective of whichever account owns this store. This field now does double duty beyond its original dedup role: it's what a client checks against the conversation's *effective* recovery profile (`ARCHITECTURE.md` §7.2) to decide whether an entry may be written at all (effective Profile B skips `written_by = peer` entries entirely), and it's the selector the Recovery Store's filtered delete uses to purge only peer-authored entries on a tightening from effective Profile A to B (`SERVERS.md` §3.2, `ARCHITECTURE.md` §7.3) |

## 6. Presence protocol (CBOR, over the Signaling & Presence Service's WebSocket)

See [`SERVERS.md`](SERVERS.md) §1 for the service design these messages
belong to — auth handshake, visibility rules, and why presence state is
held in-memory only, never logged.

| Message | Field | Type | Notes |
|---|---|---|---|
| `AuthChallenge` (service → client, on connect) | `nonce` | bytes (32) | fresh per connection |
| `AuthResponse` (client → service) | `identity_fingerprint` | bytes (32) | identifies the connecting account |
| | `signature` | bytes | signature over `nonce` using the identity key (or per-device subkey — `SERVERS.md` §5) |
| `PresenceAnnounce` (client → service) | `state` | 1 byte enum | `0 = online`, `1 = away` |
| `PresenceUpdate` (service → subscribed contacts' clients) | `identity_fingerprint` | bytes (32) | whose presence changed |
| | `state` | 1 byte enum | `0 = online`, `1 = away`, `2 = offline` |
| | `last_seen` | uint64, present only when `state = offline` | unix seconds |
| `PresenceSubscribe` (client → service, implicit on session establishment) | `identity_fingerprint` | bytes (32) | a client only receives updates for accounts it has an established or attempted session with — the service enforces this, not the client (`SERVERS.md` §1.3) |

`PresenceUpdate` is push-only, sent to already-subscribed clients as state
changes happen — there is no `PresenceQuery` message, by design: presence
can't be polled for an arbitrary account, only received for existing
contacts, which is what keeps it from being an enumeration oracle
(`SERVERS.md` §1.3).

## 7. Rendezvous, mailbox, and delivery-acknowledgment messages (CBOR)

The control messages behind the sequence diagrams in `ARCHITECTURE.md` §4.1
(Tier 0 rendezvous), §4.2 (Tier 1 mailbox), and §4.6 (delivery
acknowledgment) — all over the same Signaling & Presence Service WebSocket
as §6.

| Message | Field | Type | Notes |
|---|---|---|---|
| `RendezvousOffer` (initiator → service → recipient) | `to_fingerprint` | bytes (32) | recipient's identity fingerprint |
| | `sdp_offer` | text | WebRTC SDP offer |
| | `ice_candidates` | array of text | trickled incrementally in practice; shown as one field here for brevity |
| `RendezvousAnswer` (recipient → service → initiator) | `sdp_answer` | text | WebRTC SDP answer |
| | `ice_candidates` | array of text | |
| `MailboxWrite` (sender → service) | `mailbox_id` | bytes (16) | derived per `ARCHITECTURE.md` §11.1, not a static device id |
| | `envelope` | bytes | the ratchet message envelope (§2), opaque to the service |
| | `ttl` | uint32 | seconds; 14 days default (`ARCHITECTURE.md` §4.5) |
| `MailboxFetch` (recipient → service, on reconnect) | `mailbox_id` | bytes (16) | computed locally from the two routing ids exchanged at pairing time (`ARCHITECTURE.md` §11.1) — or, before that exchange completes, `x3dh::bootstrap_mailbox_id` (§11.1) — never enumerated via the service |
| `MailboxDelete` (recipient → service, after successful decrypt) | `mailbox_id` | bytes (16) | |
| | `entry_id` | bytes (16) | service-assigned on write, echoed back on fetch |
| `DeliveryAck` (recipient → sender, routed like any other message) | `conversation_id` | bytes (16) | same derivation as §2 |
| | `acked_n` | uint32 | the ratchet header's `n` (§2) being acknowledged |
| `RoutingIdAnnounce` (either side → the other, routed like any other message) | `routing_id` | bytes (32) | this side's fresh, single-use routing id (`ARCHITECTURE.md` §11.1) — sent once, right after the session is established |

`DeliveryAck`'s two fields (`conversation_id`, `acked_n`) are CBOR-encoded
and become the *content* of a ratchet envelope's plaintext, tagged with
`payload_type = 1` (§2) — it's carried as an ordinary ratchet message, not
a separate wire format, and gets the same encryption, padding, and (for
Tier 1) mailbox routing as a chat message. `RoutingIdAnnounce` is the same
shape of thing, tagged `payload_type = 3` (§2) — sent over
`bootstrap_mailbox_id` before either side has a routing-id-derived mailbox
to use yet, and, like `DeliveryAck`, never gated by `ARCHITECTURE.md`
§6.5's mandatory-verification rule (it's protocol machinery, not chat
content). The rendezvous and mailbox control messages above these two in
this table (`RendezvousOffer` through `MailboxDelete`) are different in
kind: they're exchanged with the Signaling & Presence Service itself,
before or outside any given ratchet session, so they're plain CBOR over
the WebSocket with no ratchet encryption of their own — the service has to
be able to read routing metadata to do its job (§4.1/§4.2 of
`ARCHITECTURE.md`), unlike message content.

**Implementation note (`core::payload::DeliveryAck`, `dratchet_app`):**
`acked_n` alone only disambiguates messages *within one sending chain* —
every Double Ratchet DH step resets a new chain's `n` back to 0, and this
schema (matching the shape documented above) carries no `dh_pub` alongside
it to say which chain produced it. A receiver matches an incoming ack back
to its own sent messages by picking the oldest undelivered
locally-sent message with that `n` (`Db::mark_message_delivered`) — correct
for ordinary turn-taking, not a hard guarantee under sufficiently
out-of-order ack arrival. See `docs/DELIVERY_FAILURE_FINDINGS.md` finding
#28 for the analysis and remediation options (extending the schema with
`dh_pub`, among them).

## 8. Recovery profile negotiation (CBOR) — §7.2/§7.3/§7.5 of `ARCHITECTURE.md`

| Field | Type | Notes |
|---|---|---|
| `profile` | 1 byte enum: `0 = C (None)`, `1 = B (Sent-only)`, `2 = A (Full)` | the announcing account's *current* recovery profile for this conversation — either its global default or an active per-conversation override; the recipient doesn't need to know which |

Like `DeliveryAck`, `RecoveryProfileAnnounce` is CBOR-encoded content
carried inside a ratchet envelope, tagged `payload_type = 2` (§2) — sent at
session establishment and again any time the announcing account's profile
for that conversation changes. A recipient who has never received one for
a given conversation treats the counterpart as Profile C (fail-closed,
`ARCHITECTURE.md` §7.2) rather than assuming a default. The effective
policy — `min(own profile, last-announced peer profile)` — is computed
independently and identically by both clients; no response message is
needed, and there's no proposal to accept or reject. There's also no
`previous_profile` field: a receiving client diffs an incoming `profile`
against whatever it already has cached for that peer to decide whether to
surface a change notice, so the "old" side of that notice is always the
receiver's own last-known state, never something the sender asserts — see
`ARCHITECTURE.md` §7.5 for the full notification behavior, including why
the very first announcement for a conversation is establishing state
rather than changing it.

## 9. Group vouch attestation (CBOR) — `ARCHITECTURE.md` §13.6

| Field | Type | Notes |
|---|---|---|
| `prospect_fingerprint` | bytes (32) | the prospective member's identity fingerprint (`ARCHITECTURE.md` §3.1), confirmed by the voucher via §6.3 or §6.4 |
| `voucher_fingerprint` | bytes (32) | the current member issuing this attestation — redundant with the MLS sender identity, included so the attestation is independently verifiable outside the transport that carried it |
| `vouched_at` | uint64 | unix seconds |
| `signature` | bytes (64) | raw Ed25519 signature by the voucher's identity key, over `(prospect_fingerprint, voucher_fingerprint, vouched_at)` |

Carried as an MLS Application message (`ARCHITECTURE.md` §13.1) to the
group, not a DRAtchet-specific ratchet envelope — consistent with §13.1's
decision to adopt RFC 9420's own encoding for all group traffic. Every
current member's client independently collects vouch attestations for a
given `prospect_fingerprint`, sums the issuing members' configured vouch
weights, and only then does a member propose the `Commit` that actually
adds the prospect — the attestations are the auditable evidence for that
Commit, not a request routed through the Group Coordination Service for
it to act on.

## 10. Per-conversation wipe (CBOR) — `ARCHITECTURE.md` §11.9a

Two messages behind the per-conversation "clear this chat" feature — the
same shape as Signal/WhatsApp's "delete for everyone," scoped to a single
conversation both sides already have, never a general remote-wipe
primitive (`ARCHITECTURE.md` §11.9's device-seizure duress wipe is a
completely different, strictly local feature — see that section for why
a *general* remote-wipe capability was deliberately never built).

| Field | Type | Notes |
|---|---|---|
| `ask_before_delete` | bool | ask locally before complying with an incoming wipe request, rather than deleting immediately |
| `include_session` | bool | also destroy the conversation's ratchet/session state (not just message history) when complying |

`ConversationWipePolicyAnnounce`'s two fields are CBOR-encoded and become
the *content* of a ratchet envelope's plaintext, tagged with
`payload_type = 4` (§2) — sent at session establishment and again any
time the announcing side's preferences for that conversation change,
exactly like `RecoveryProfileAnnounce` (§8). `ConversationWipeRequest`
carries no fields at all — empty content, tagged `payload_type = 5` — the
conversation is already identified by which ratchet/mailbox it arrived
on. Both are ungated by `ARCHITECTURE.md` §6.5's mandatory-verification
rule, like `RoutingIdAnnounce`: protocol machinery, not chat content.

**Two merge functions, computed independently and identically by both
clients from (own preference, last-announced peer preference) — no
response message, no proposal to accept or reject, same shape §8 already
established.** An unset peer preference (never announced yet) defaults to
`false` on both axes — fail toward the calmer outcome:

- **Effective `ask_before_delete` = `own AND peer`** — the *opposite* of
  §7.2's min-merge ("most restrictive wins") for recovery profiles,
  deliberately: requiring *unanimous* consent for the safer "ask" outcome,
  rather than letting either side unilaterally impose it and block the
  other side's ability to actually clear a conversation both parties
  share. If either side (or an unannounced peer) prefers immediate
  deletion, the default is delete-on-receipt.
- **Effective `include_session` = `own OR peer`** — the conventional
  most-restrictive-wins shape: either side asking for the fuller wipe
  (messages *and* ratchet/session state, not messages alone) gets the
  fuller wipe.

**What "wipe" means here, and what it doesn't**: a plain deletion of the
matching `message:*` (and, if `include_session`, `ratchet:*`) records —
not the crypto-shred `ARCHITECTURE.md` §11.9's quick/full wipe perform.
That distinction exists on purpose: §11.9 defends against a device-seizure
threat model across the *entire* local store; this is ordinary per-
conversation housekeeping, the same plain-delete guarantee `delete_message`
and `delete_contact` already provide today.

**No delivery receipt.** The requesting side has no way to know whether
the peer complied, declined, or hasn't seen the request yet — the same
fire-and-forget limitation every mailbox message already has (no
`ReadReceipt` exists either, per `ARCHITECTURE.md` §10's open decisions).

## 11. Profile announce (CBOR) — `ARCHITECTURE.md` §6.1

A single message behind the restart/reclaim notification mechanism: when
`dratchet_app::reconcile_own_profile` finds its stored `username#NNNN`
was claimed by someone else while the directory forgot this device owned
it (a server restart, §6.1), and has to pick a new discriminator, it
broadcasts the new handle to every already-`Verified` contact so their
clients stay in sync rather than silently going stale.

| Field | Type | Notes |
|---|---|---|
| `username` | string | the sender's current registered username |
| `discriminator` | uint16 | the sender's current registered discriminator |

`ProfileAnnounce`'s two fields are CBOR-encoded and become the *content*
of a ratchet envelope's plaintext, tagged `payload_type = 7` (§2), sent
over the recipient's existing conversation exactly like
`RoutingIdAnnounce` (§7) or `ConversationWipePolicyAnnounce` (§10) — an
ordinary control message, not a new session or a new payload channel.
This is deliberate: `conversation_id` and all ratchet/session state are
derived from the long-term identity fingerprint (`ARCHITECTURE.md`
§3.1/§3.2), never from `username#NNNN`, so a handle change is purely a
display-label update and needs no key or ratchet change of any kind to
propagate.

**On receipt**, the recipient compares the announced handle against
whatever it already has stored for that contact (`Db::record_peer_profile`)
and updates it if different. Learning a handle for the first time (e.g.
immediately after §6.4 pairing, before any announce has arrived) is not
treated as a "change" worth surfacing — only a genuine reassignment *from*
an already-known handle triggers a UI notice. Like `RoutingIdAnnounce`,
this is ungated by `ARCHITECTURE.md` §6.5's mandatory-verification rule:
protocol machinery, not chat content, and it can only ever arrive over a
conversation that already exists.

**No delivery receipt**, the same fire-and-forget limitation as every
other control message in this document.

## 12. Own prekey count query (CBOR) — `ARCHITECTURE.md` §3.4

Not a ratchet-envelope payload — a plain request/response pair over the
authenticated connection, following the same shape as `MailboxFetch` (§7)
rather than anything routed through a mailbox.

`FetchOwnPrekeyCount` (client → server): no fields at all. The target is
always the caller's own authenticated identity; there is deliberately no
way to name a different one, so this can never become a new enumeration/
timing oracle for another account's prekey pool size (`ARCHITECTURE.md`
§11.8).

`OwnPrekeyCount` (server → client), in reply:

| Field | Type | Notes |
|---|---|---|
| `remaining` | uint32 | how many one-time prekeys the directory still has stored for the caller's currently-published bundle; `0` if the caller has never published one |

Used by `dratchet_app::replenish_prekeys_if_low`: once `remaining` has
drained to a small threshold, the client republishes a full fresh batch
under its existing `username#NNNN` — an ordinary `PublishBundle` (§1),
nothing new on the write side.
