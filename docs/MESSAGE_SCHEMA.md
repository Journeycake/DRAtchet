# DRAtchet — Message Schemas

Status: **design draft, no code yet**. Companion to [`ARCHITECTURE.md`](ARCHITECTURE.md)
— read that first for the protocol rationale (Double Ratchet, X3DH-over-OpenPGP,
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
  `ARCHITECTURE.md` (lightweight envelope vs. full OpenPGP framing) pays off
  concretely — see the overhead comparison at the end of §2.
- **Everything else** (prekey bundles, the X3DH init message, pairing
  messages, recovery blobs) — sent rarely (session setup, verification,
  backup) — uses **CBOR** (RFC 8949): compact, binary, schema-evolvable via
  map keys (new optional fields don't break old parsers), good Rust support
  (`ciborium`). JSON was considered and rejected for these too: CBOR is
  smaller, has real binary support (no base64 tax for key material), and a
  stricter type model.

All multi-byte integers are big-endian (network byte order). All key
material is raw fixed-size public-key bytes (X25519 = 32 bytes) unless
explicitly noted as an OpenPGP packet.

## 1. Prekey bundle (CBOR)

Published by each client to wherever bundles are discoverable (see
`ARCHITECTURE.md` §4 for the serverless/relay discussion of *where* —
this schema is the same regardless of hosting model).

| Field | Type | Notes |
|---|---|---|
| `username` | text string | self-chosen, §6.1 |
| `discriminator` | uint16 | the `NNNN` in `username#NNNN` |
| `identity_key` | bytes | OpenPGP public key packet (Ed25519 + Curve25519) |
| `signed_prekey_id` | uint32 | monotonic per-account counter |
| `signed_prekey` | bytes | OpenPGP ECDH subkey packet (Curve25519) |
| `signed_prekey_sig` | bytes | OpenPGP signature packet, by `identity_key` |
| `signed_prekey_expires_at` | uint64 | unix seconds; rotated on schedule (§3.2) |
| `one_time_prekeys` | array of `{id: uint32, key: bytes}` | each consumed once, then removed from the published bundle (§3.4) |

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
`1 = DeliveryAck` (§7), `2 = RecoveryProfileAnnounce` (§8), reserved values
for future control payloads (e.g. a `ReadReceipt`, `ARCHITECTURE.md` §4.6).
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
`DeliveryAck` from a short chat message by size). Padding is stripped after
decryption and never transmitted as a separate field. Inspired by Signal's
message padding; see §11.3 of `ARCHITECTURE.md` for the full rationale.

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

## 3. X3DH session-establishment message (CBOR)

The *first* message of a new session — carries the extra fields the
recipient needs to derive the shared root key, since they don't have
ratchet state yet. After this, all further messages use the fixed
ratchet envelope above.

| Field | Type | Notes |
|---|---|---|
| `initiator_identity_fingerprint` | bytes (32) | SHA-256 of initiator's identity key |
| `initiator_ephemeral_pub` | bytes (32) | `EK_A`, fresh per session |
| `used_signed_prekey_id` | uint32 | which of the recipient's signed prekeys was used |
| `used_one_time_prekey_id` | uint32, optional | omitted if the recipient had none available (X3DH degrades gracefully but loses one DH term — flagged in `ARCHITECTURE.md` open decisions if this needs hardening) |
| `initial_envelope` | bytes | the first ratchet message envelope (§2), encrypted under the HKDF-derived root/chain key |

## 4. Peer-pairing messages (CBOR) — §6.4 remote pairing

| Message | Field | Type | Notes |
|---|---|---|---|
| `PairingChallenge` (recipient → initiator, out-of-band) | `pairing_id` | bytes (16) | correlates challenge/response if relayed through an untrusted channel |
| | `expires_at` | uint64 | ~10 min TTL (§9 of `ARCHITECTURE.md`) |
| `PairingResponse` (initiator → recipient) | `pairing_id` | bytes (16) | echoes the challenge |
| | `code_proof` | bytes (32) | `HMAC(key = code, msg = session_transcript_hash)` — **not the raw code**, so a transport that isn't fully trusted (e.g. an ephemeral relay, §4 of `ARCHITECTURE.md`) never observes the code itself or gets a replayable value against a different session |

## 5. Recovery backup entry (CBOR) — §7 opt-in recovery

Written to whichever recovery store an account has configured for itself
(§2.1 of `SERVERS.md` — per-participant, not shared). One entry per
message, independent of the ratchet's own `n`/`pn` counters so recovery
ordering never depends on live ratchet internals.

| Field | Type | Notes |
|---|---|---|
| `conversation_id` | bytes (16) | same derivation as §2 |
| `seq` | uint64 | monotonic per-conversation sequence number, assigned locally |
| `ciphertext` | bytes | `AEAD(plaintext)` under the conversation recovery key, independent key from any ratchet message key |
| `created_at` | uint64 | unix seconds |
| `written_by` | 1 byte enum: `0 = self`, `1 = peer` | who authored the underlying message, from the perspective of whichever account owns this store. This field now does double duty beyond its original dedup role: it's what a client checks against the conversation's *effective* recovery profile (`ARCHITECTURE.md` §7.2) to decide whether an entry may be written at all (effective Profile B skips `written_by = peer` entries entirely), and it's the selector the Recovery Store's filtered delete uses to purge only peer-authored entries on a tightening from effective Profile A to B (`SERVERS.md` §2.2, `ARCHITECTURE.md` §7.3) |

## 6. Presence protocol (CBOR, over the Signaling & Presence Service's WebSocket)

See [`SERVERS.md`](SERVERS.md) §1 for the service design these messages
belong to — auth handshake, visibility rules, and why presence state is
held in-memory only, never logged.

| Message | Field | Type | Notes |
|---|---|---|---|
| `AuthChallenge` (service → client, on connect) | `nonce` | bytes (32) | fresh per connection |
| `AuthResponse` (client → service) | `identity_fingerprint` | bytes (32) | identifies the connecting account |
| | `signature` | bytes | signature over `nonce` using the identity key (or per-device subkey — `SERVERS.md` §4) |
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
| `MailboxFetch` (recipient → service, on reconnect) | `mailbox_id` | bytes (16) | computed locally from the recipient's own ratchet state, never enumerated via the service |
| `MailboxDelete` (recipient → service, after successful decrypt) | `mailbox_id` | bytes (16) | |
| | `entry_id` | bytes (16) | service-assigned on write, echoed back on fetch |
| `DeliveryAck` (recipient → sender, routed like any other message) | `conversation_id` | bytes (16) | same derivation as §2 |
| | `acked_n` | uint32 | the ratchet header's `n` (§2) being acknowledged |

`DeliveryAck`'s two fields (`conversation_id`, `acked_n`) are CBOR-encoded
and become the *content* of a ratchet envelope's plaintext, tagged with
`payload_type = 1` (§2) — it's carried as an ordinary ratchet message, not
a separate wire format, and gets the same encryption, padding, and (for
Tier 1) mailbox routing as a chat message. The rendezvous and mailbox
control messages above it in this table (`RendezvousOffer` through
`MailboxDelete`) are different in kind: they're exchanged with the
Signaling & Presence Service itself, before or outside any given ratchet
session, so they're plain CBOR over the WebSocket with no ratchet
encryption of their own — the service has to be able to read routing
metadata to do its job (§4.1/§4.2 of `ARCHITECTURE.md`), unlike message
content.

## 8. Recovery profile negotiation (CBOR) — §7.2/§7.3 of `ARCHITECTURE.md`

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
needed, and there's no proposal to accept or reject.
