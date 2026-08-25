# DRAtchet — Architecture & Design

Status: **design draft, no code yet**
Target platforms: Windows, macOS, Linux (desktop)

## 1. Recap: why "a fresh PGP keypair every message" doesn't work

The original idea was: encrypt every message with classic OpenPGP public-key
encryption, alternate which side's keypair is "active" every other message,
and throw away each private key the instant it's used.

That breaks under real messaging conditions:

- **Queue depth > 1.** If Alice sends two messages before Bob replies (common —
  offline recipient, slow reply, burst of messages), message #2 has no new
  public key to encrypt against, because in a strict alternating scheme the
  *next* key only exists once the recipient replies. The scheme is lock-step
  (ping-pong) and doesn't tolerate multiple in-flight messages, out-of-order
  delivery, or retries.
- **Cost.** Generating a new PGP keypair (especially RSA) and doing a full
  asymmetric encrypt/decrypt on *every single message* is orders of magnitude
  more expensive than symmetric crypto — noticeable latency and battery/CPU
  cost at chat volumes (this is exactly why nobody does this for real-time
  messaging).
- **Async delivery.** A store-and-forward server, multi-device, or a
  recipient who's offline for a while all need many messages to be encrypted
  and queued *before* any reply-driven key rotation could happen.

**This is a solved problem** — it's what the Signal Protocol's **Double
Ratchet** algorithm exists for. DRAtchet adopts Double Ratchet as the
key-rotation model, and uses OpenPGP where it actually earns its cost:
long-term identity, key discovery/verification, and signing — not as a
per-message asymmetric operation.

## 2. Design goals

1. Forward secrecy: compromise of a current key must not expose past messages.
2. Post-compromise (self-healing) security: after a compromise, the session
   heals itself once both sides exchange a couple more messages.
3. Tolerate real-world queueing: offline recipients, bursts, out-of-order
   delivery, retries — without breaking decryption or blocking on lock-step
   replies.
4. Every symmetric message key is single-use and is deleted immediately after
   one encrypt/decrypt.
5. OpenPGP is used for identity and key-agreement material (so keys are
   auditable, exportable, and interoperable with existing OpenPGP tooling),
   but never as a per-message bottleneck.
6. Native desktop app on Windows, macOS, Linux from one codebase.

## 3. Cryptographic protocol

### 3.1 Identity keys (OpenPGP)

Each user has one long-term OpenPGP identity keypair (Ed25519 signing +
Curve25519 ECDH, OpenPGP v6 per RFC 9580, following the modern GnuPG default
profile). This is the key a user backs up, the key behind their fingerprint,
and the key used to sign everything below. It is **never** used to encrypt
message content directly.

### 3.2 Session establishment — X3DH over OpenPGP subkeys

Modeled on Signal's X3DH, but the key material is carried as OpenPGP packets:

- Each user publishes a **prekey bundle** to the relay server:
  - Identity key (long-term).
  - One **signed prekey** (ECDH Curve25519 subkey), signed by the identity
    key, rotated periodically (e.g. weekly).
  - A batch of **one-time prekeys** (ECDH Curve25519 subkeys), uploaded in
    bulk; the server hands out one per new session and then deletes it.
- To start a session, the initiator fetches the recipient's bundle, verifies
  the signed prekey's signature, and performs the X3DH DH computations
  (IK_A×SPK_B, EK_A×IK_B, EK_A×SPK_B, EK_A×OPK_B) to derive a shared secret
  via HKDF. This becomes the Double Ratchet **root key**.
- The consumed one-time prekey is deleted server-side immediately and
  client-side once the session is confirmed — this is the genuinely
  single-use, discard-after-use keypair in the system.

### 3.3 Message layer — Double Ratchet

Once the root key exists, per-message crypto is entirely symmetric:

- **Symmetric-key ratchet:** every message advances a one-way HMAC chain
  (`KDF_CK`) to derive a per-message key. That message key encrypts exactly
  one message (AEAD: ChaCha20-Poly1305 or AES-256-GCM) and is deleted right
  after use — this is where "single-use key, discarded after one message" is
  fully and cheaply true.
- **DH ratchet:** each message header carries the sender's *current* ratchet
  public key (an OpenPGP-compatible Curve25519 ECDH key) — this is the
  "follow-on message includes the latest public key for the next
  transmission" behavior from the original brief. A *new* DH keypair is
  generated, and the ratchet steps forward (new root + chain keys), the first
  time a side replies after receiving — i.e., key rotation is driven by
  turn-taking, not by a literal count of messages. The old ratchet private
  key is discarded the moment the new one replaces it.
- **Skipped-message key cache:** because the chain KDF is a one-way function,
  keys can be derived ahead and cached (bounded, e.g. `MAX_SKIP = 1000`) for
  messages that arrive out of order or after a backlog. **This is the direct
  answer to the queue-depth question**: Double Ratchet was built to tolerate
  exactly the burst/offline/out-of-order conditions that break a strict
  alternating-PGP-keypair scheme.

### 3.4 Key lifecycle summary

| Key | Lifetime | Discarded when |
|---|---|---|
| Identity keypair | Long-term (years) | User rotates/revokes identity |
| Signed prekey | Days–weeks | Replaced on rotation schedule |
| One-time prekey | Single session handshake | Immediately after session establishment |
| DH ratchet keypair | Until the peer's next reply | Replaced by next DH ratchet step |
| Per-message symmetric key | Single message | Immediately after that message is encrypted/decrypted |

### 3.5 OpenPGP wire-format decision

Recommendation: use **OpenPGP key formats** (RFC 9580 packets) for identity
keys, signed prekeys, and one-time prekeys — so keys are portable/inspectable
and could interoperate with existing OpenPGP tooling for identity purposes.
Message payloads themselves use a lightweight custom envelope (ratchet
header + AEAD ciphertext), *not* OpenPGP's own public-key-encrypted-session-key
packet per message — wrapping every message in full OpenPGP would reintroduce
the per-message asymmetric-op cost problem this design exists to avoid. Flag
this as an open decision if full OpenPGP wire compatibility for message
bodies turns out to be a hard requirement — it's possible but meaningfully
more expensive and still needs a ratchet-derived session key underneath to
stay queue-depth-safe.

## 4. System architecture

- **Relay server**: store-and-forward only — queues ciphertext per recipient
  device, hosts prekey bundles, never sees plaintext or ratchet state
  (untrusted by design, same trust model as Signal's server).
- **Client**: owns all key material and ratchet state; server is dumb
  transport + mailbox.
- Large backlog handling: skipped-key cache is bounded; if a recipient is
  offline long enough to exceed `MAX_SKIP`, client falls back to a fresh
  session establishment (X3DH resync) rather than growing the cache
  unbounded.
- Multi-device and group chat are **out of scope for v1** (flagged in
  Roadmap) — both are real extensions (Signal's "Sesame" for multi-device,
  sender-keys for groups) but add significant complexity better tackled
  after the 1:1 ratchet is solid.

## 5. Client / platform architecture

Recommendation: **Tauri (Rust core) + web-based UI**, one codebase for
Windows/macOS/Linux.

- Rust core handles all cryptography and ratchet state — no crypto in the UI
  layer. Candidate crates: `sequoia-openpgp` (OpenPGP identity/prekeys),
  `x25519-dalek` (ECDH), `hkdf` + `hmac` + `sha2` (ratchet KDFs),
  `chacha20poly1305` (AEAD). All are audited, widely used RustCrypto/Sequoia
  ecosystem crates rather than hand-rolled primitives.
  - Rust over Electron/Node for this project specifically because the crypto
    core benefits from memory safety and a mature native OpenPGP
    implementation (Sequoia); Tauri's footprint and update size are also
    substantially smaller than Electron's.
- Local storage: SQLite (SQLCipher-encrypted) for session/ratchet state, with
  the local database encryption key sealed via the OS credential store —
  Windows DPAPI, macOS Keychain, Linux Secret Service (libsecret) — not a
  user password alone.
- IPC between the web UI and Rust core stays within Tauri's command bridge;
  the UI never handles raw key material, only decrypted message text and
  metadata.

## 6. Threat model

In scope:
- Passive network eavesdropping.
- A compromised or malicious relay server (never sees plaintext or long-term
  key material).
- Forward secrecy against a future endpoint compromise (old messages stay
  safe).
- Post-compromise security: session self-heals after a transient key
  compromise, once a couple of ratchet steps occur.

Explicitly out of scope for v1 (call out, don't silently ignore):
- Endpoint malware / device compromise while keys are live in memory.
- Metadata protection (who talks to whom, timing) — would need sealed-sender
  style techniques later.
- Multi-device and group messaging (see Roadmap).

## 7. Roadmap

1. **v0 — crypto core**: identity keys, X3DH handshake, Double Ratchet
   engine, unit + property tests (including out-of-order/skipped-key tests
   simulating queue depth), no UI.
2. **v1 — desktop MVP**: Tauri app, 1:1 chat only, relay server, local
   encrypted storage, manual fingerprint verification (safety-number style).
3. **v2**: multi-device support, group chat (sender-keys), prekey bundle
   auto-replenishment, push notifications.

## 8. Open decisions for confirmation

- Full OpenPGP wire compatibility for *message bodies* (not just identity),
  vs. the lighter custom envelope recommended above — recommend the latter
  unless interop with existing PGP/GPG clients for message content is a hard
  requirement.
- Tauri/Rust vs. Electron/TypeScript (with `openpgp.js`) — recommend Tauri/
  Rust for the reasons in §5; Electron is faster to prototype in JS but has
  a weaker track record on crypto-safe defaults and ships a much larger
  binary.
- Relay server hosting model (self-hosted vs. managed) — not yet decided,
  doesn't block crypto-core work.
