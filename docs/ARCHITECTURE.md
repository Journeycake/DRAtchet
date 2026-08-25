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
7. Peer identity is authenticated out-of-band (in-person QR, or a remote
   single-use pairing code) rather than trusted on lookup alone.
8. Message history is unrecoverable by default; recovery is only ever an
   explicit, mutual, per-conversation opt-in.

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
| Remote pairing code (§6.4) | Single verification attempt, ~10 min TTL | On first successful match, or expiry — whichever first |
| Conversation recovery key (§7, opt-in only) | Life of the conversation's recoverable-mode setting | Only if recovery is later disabled *and* the user explicitly deletes backups; otherwise persists by design |

### 3.5 Message wire format: full OpenPGP vs. lightweight custom envelope

Two different things can be "OpenPGP" here, and it's worth separating them:
**key material** (identity keys, prekeys — already specified as OpenPGP
packets in §3.1/3.2) vs. **message bodies** (the ciphertext for an individual
chat message). This section is only about the latter.

**Full OpenPGP wire format** means every message is itself a valid OpenPGP
message: a Public-Key Encrypted Session Key (PKESK) packet (or, to actually
carry a ratchet-derived key, a repurposed Symmetric-Key Encrypted Session Key
/ SKESK packet) followed by a Symmetrically Encrypted Integrity Protected
Data (SEIPD) packet per RFC 9580 — the same packet structure as a `.pgp`
file GnuPG produces.

**Lightweight custom envelope** means a minimal, application-defined
structure: a fixed ratchet header (sender's current DH public key, message
number `N`, previous chain length `PN`) followed by an AEAD ciphertext +
tag. Nothing about it is OpenPGP-packet-shaped; only the *keys* (§3.1/3.2)
are OpenPGP objects.

| | Full OpenPGP wire format | Lightweight custom envelope |
|---|---|---|
| **Per-message overhead** | Multiple packet headers + MPI-encoded fields — noticeably larger than the payload for short chat messages | Fixed ~40–50 byte header (32-byte pubkey + two counters) + ciphertext + 16-byte tag — minimal |
| **Where ratchet metadata lives** | No natural home — the DH pubkey/counters would have to be smuggled into Notation Data subpackets or a custom packet type, which itself breaks strict standard-compliance | First-class fields in a header designed exactly for what Double Ratchet needs |
| **Real interoperability** | Looks standard, but a generic OpenPGP/GnuPG client still can't decrypt it — the "session key" is ratchet-derived, not produced by a normal public-key encryption step, so the compatibility is mostly cosmetic | None claimed — doesn't pretend to be readable by outside tools |
| **Parsing surface / attack surface** | Larger — full packet parser, MPI decoding, subpacket handling per message | Small, fully controlled, easy to fuzz/test exhaustively |
| **Engineering cost** | Reuses a standardized format for *framing*, but key derivation is custom either way — you inherit format complexity without shedding protocol-design responsibility | Faster to implement correctly; entire format fits in a page |
| **Future flexibility** | If a hard requirement later appears to bridge to PGP/MIME email or produce gpg-decryptable archives, this gets partway there | Would need a translation layer built later if that requirement ever appears |
| **Tooling** | Can reuse existing OpenPGP packet inspectors for debugging | Debug/inspection tooling must be custom-built (small effort given the format's size) |

**Recommendation (decided, revisit only if a concrete interop requirement
appears):** OpenPGP packet format for identity keys and prekey bundles
(§3.1/3.2), lightweight custom envelope for message bodies. The claimed
interoperability benefit of full OpenPGP message framing is largely
illusory — a stock OpenPGP client still can't decrypt a ratchet-derived
session key — so it doesn't justify the extra size, parsing surface, and
awkward header-metadata fit. Message bodies never leave the app anyway
(they're deleted from the ratchet the instant they're used, per §3.4), so
there's no real-world scenario where a generic PGP tool needs to read one.

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

**Decided:** one stack, one codebase, for all three target platforms —
**Tauri (Rust core) + web-based UI**, shipping natively on Windows, macOS,
and Linux. No per-OS fork and no separate Electron track; platform
differences are handled as integration details within the single core, not
as different stacks.

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
- **Per-platform integration points** (same core logic, different OS glue):
  - *Windows*: DPAPI-backed secret storage; camera access for QR scanning
    (§6) via the WebView2 webview's `getUserMedia`.
  - *macOS*: Keychain Services-backed secret storage; camera access via
    WKWebView's `getUserMedia` (requires the standard camera-usage
    entitlement/Info.plist string).
  - *Linux*: Secret Service API (libsecret) for secret storage; camera
    access via WebKitGTK's `getUserMedia`. Caveat: not every Linux desktop
    environment runs a Secret Service provider by default (minimal window
    managers, some headless/remote setups) — the client needs a graceful
    fallback (e.g., a local passphrase-derived key-encryption-key) rather
    than failing to start when libsecret is unavailable.
  - QR display/scanning itself needs no native camera code on any platform
    — a webview `getUserMedia` call plus in-app QR encode/decode (pure
    Rust or JS library) covers all three.

## 6. Identity addressing & peer authentication

### 6.1 Addressing: `username#NNNN`

Each account has a self-chosen **username** plus a server-assigned random
**4-digit discriminator**, e.g. `alice#4821` — regenerated on collision
within that username (Discord's original scheme). The directory server maps
`username#NNNN` → account ID → current prekey bundle (§3.2). This address is
how you *locate* someone's prekey bundle; it is **not** proof of who
controls it — the server could in principle be compromised or coerced into
serving a substituted bundle, which is exactly what §6.2 defends against.
(Namespace note: a 4-digit discriminator caps a single username at 10,000
accounts before it runs out — fine at the scale this project is targeting;
flagged in §9 as revisitable if that ever becomes a real constraint.)

### 6.2 Trust levels

Every contact is either:

- **Unverified** (default, TOFU — trust-on-first-use): the client has a
  prekey bundle for `username#NNNN` fetched from the directory server, but
  its fingerprint hasn't been independently confirmed. The UI should flag
  this clearly (a persistent banner in the conversation, similar to Signal's
  unverified-safety-number indicator) without blocking sending — flagging
  risk beats blocking usability.
- **Verified**: the identity key's fingerprint has been confirmed through
  one of the two paths below, and is pinned locally. If the peer's identity
  key later changes, the contact reverts to "unverified — identity changed"
  and must be re-verified, the same way Signal treats a safety-number change.

### 6.3 Path 1 — in-person QR exchange (strongest)

Each device can render a QR code encoding `username#NNNN` + the SHA-256
fingerprint of its current identity key (+ a short random nonce so a stale
photographed code is visibly different from a fresh one). Both people scan
each other's codes in the same physical session; each client compares the
scanned fingerprint against the bundle it already has (or fetches fresh) for
that address — match marks the contact **Verified**; mismatch is a hard
stop, never silently marked verified. Because the fingerprint came straight
from a physically-present device, this path doesn't need to trust the
directory server at all — it's the strongest of the two.

### 6.4 Path 2 — remote pairing via username + single-use code

For contacts who aren't in the same room:

1. Initiator looks up `username#NNNN` on the directory server and fetches
   the prekey bundle — this alone is TOFU, no stronger than any first
   contact today.
2. The recipient's app generates a random, single-use, short-TTL numeric
   pairing code (e.g. 6 digits, ~10-minute expiry; generating a new one
   invalidates the previous code).
3. The recipient reads that code to the initiator over a channel they
   already trust more than the directory server (phone call, an existing
   verified DRAtchet conversation, in person, etc.) — the code is the "MFA"
   factor here: proof that the person on the other end of that channel
   currently controls the account, demonstrated by generating and reading
   it out.
4. The initiator enters the code in-app. The client sends it back bound to
   the current handshake's key material (so it can't be replayed against a
   different session); the recipient's device checks the match, and both
   sides are marked **Verified**.
5. The code is consumed (deleted) on first successful match or on expiry,
   whichever comes first; a fresh code is required for another attempt, and
   attempts are rate-limited — a 6-digit space is brute-forceable without
   that limit.

Be precise about what this does and doesn't prove: it authenticates that
whoever generated the code controls the account being paired with, and its
security rests entirely on the secrecy/integrity of whatever side channel
carried the code — the same property Signal's "compare safety number over a
phone call" verification has. It is not stronger than the channel used to
convey the code.

## 7. Per-conversation message recovery

**Default: unrecoverable.** Pure Double Ratchet behavior from §3.3 — every
message key is deleted immediately after one use, nothing is escrowed or
backed up anywhere. Losing a device loses that conversation's history from
that point on; this is forward secrecy working as intended, not a missing
feature.

**Opt-in recoverable mode**, negotiated per conversation, requires
**mutual** consent:

- Either participant can *propose* enabling recovery (a signed in-app
  proposal message). Recovery activates only once **both** sides explicitly
  accept — if only one side agrees, the conversation stays unrecoverable
  (the default holds, per the requirement that it takes both parties).
- Either side can later revoke consent, stopping backup for *future*
  messages. Revoking does not retroactively delete what's already been
  backed up — say this plainly in the UI, and offer a separate "delete my
  backups for this conversation" action rather than implying revoke does it
  automatically.

**Mechanism**, once mutually enabled — deliberately layered *on top of* the
ratchet rather than changing it:

- The normal ratchet encrypt/decrypt path (§3.3) is untouched — per-message
  keys are still single-use and discarded exactly as in the default case.
- A separate **conversation recovery key** is derived once, at the moment
  both sides confirm opt-in, via HKDF over fresh randomness contributed by
  *both* sides (so neither party unilaterally controls it) plus the current
  root key.
- After the normal send/receive path completes, each client additionally
  encrypts the plaintext under the conversation recovery key (AEAD) and
  uploads that ciphertext to a backup store. This keeps forward secrecy
  intact for the live ratchet layer — recoverability is an explicit, opted-in
  second copy, not a weakening of the ratchet itself.
- The conversation recovery key must itself survive a lost device to be
  useful, which means it needs to be escrowed somewhere. Two options,
  covered in §9 as an open decision:
  a. **Self-custodied recovery phrase** (BIP39-style words), shown once,
     stored by the user — the server never holds anything decryptable.
     Strongest privacy, worst UX (permanently lost if the user loses it).
  b. **Server-escrowed, passphrase-protected** blob (Argon2id-derived key,
     Signal-SVR/WhatsApp-backup-key style) — better UX, but needs a
     rate-limited, tamper-resistant attempt counter (typically an HSM/secure
     enclave) to resist offline brute force against the escrowed blob —
     nontrivial infra.
  - Recommendation for v1: (a), self-custodied — no secure-enclave
    infrastructure required to ship; revisit (b) later if user demand for
    better recovery UX justifies building that infra.

## 8. Threat model

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
- Recoverable-mode conversations (§7) intentionally accept a narrower threat
  model by design and by mutual consent: a durable, decryptable-with-the-
  recovery-key copy of plaintext exists somewhere once both sides opt in.
  That's a deliberate trade the *users* made for that conversation, not a
  general weakening of DRAtchet's default guarantees — the UI must state
  this plainly at the moment of opt-in, not just in this document.
- Peer-authentication paths (§6) are only as strong as their inputs: Path 1
  is strong (physical presence); Path 2 is only as strong as the side
  channel used to convey the pairing code. Neither path protects a user who
  verifies against a channel an attacker also controls.

## 9. Roadmap

1. **v0 — crypto core**: identity keys, X3DH handshake, Double Ratchet
   engine, unit + property tests (including out-of-order/skipped-key tests
   simulating queue depth), no UI.
2. **v1 — desktop MVP**: Tauri app, 1:1 chat only, relay server, local
   encrypted storage, QR and remote-pairing-code verification (§6),
   per-conversation opt-in recovery with self-custodied recovery phrase (§7).
3. **v2**: multi-device support, group chat (sender-keys), prekey bundle
   auto-replenishment, push notifications, optional server-escrowed
   passphrase-protected recovery (§7 option b).

## 10. Open decisions for confirmation

- Recovery-key escrow: self-custodied recovery phrase (recommended for v1)
  vs. server-escrowed passphrase-protected blob (§7) — the latter needs
  secure-enclave-backed rate limiting to be safe, deferred to v2 pending
  demand.
- Discriminator namespace: 4 digits (10,000 accounts/username) is the
  Discord-style default requested; revisit only if a username's collision
  rate becomes an actual product problem.
- Pairing-code parameters (§6.4): code length (6 digits assumed), TTL
  (~10 minutes assumed), and attempt rate limit — reasonable defaults
  chosen, tune once there's real usage data.
- Relay server hosting model (self-hosted vs. managed) — not yet decided,
  doesn't block crypto-core work.
