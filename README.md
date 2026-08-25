# DRAtchet

An end-to-end encrypted chat application built around the **Double Ratchet**
algorithm for key rotation, using **OpenPGP** key material for identity and
session establishment. Cross-platform desktop app for Windows, macOS, and
Linux.

Every message is encrypted with a single-use symmetric key that is deleted
immediately after use. Key rotation is driven by the Double Ratchet
algorithm rather than a naive "new PGP keypair per message" scheme, so the
protocol tolerates real-world conditions: offline recipients, bursts of
queued messages, out-of-order delivery, and retries.

Status: **v0 crypto core implemented and tested** (`core/`) — X3DH handshake
+ Double Ratchet engine, OpenPGP identity. No transport, no UI yet.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full protocol and
system design, [`docs/MESSAGE_SCHEMA.md`](docs/MESSAGE_SCHEMA.md) for the
concrete wire formats, and [`docs/SERVERS.md`](docs/SERVERS.md) for the two
optional 1:1-model server components (signaling/presence, and per-user
recovery storage) plus the mandatory Group Coordination Service that group
chat (v2) adds. Highlights:

- Why a literal per-message PGP-keypair rotation isn't feasible under
  message queueing, and how Double Ratchet solves it.
- The X3DH-over-OpenPGP session establishment handshake.
- The Double Ratchet message layer and key lifecycle (what's single-use,
  what's rotated, what's discarded, and when).
- Peer identity verification via in-person QR exchange or a remote
  single-use pairing code (`username#NNNN` addressing).
- A serverless-first, tiered delivery model: direct peer-to-peer by default,
  an optional ephemeral (auto-expiring) relay to bridge offline recipients,
  and no durable storage of any kind unless both participants opt in.
- Presence: contacts-only online-status, held in memory only by the same
  minimal signaling service used for peer-to-peer rendezvous — never
  logged, never queryable for arbitrary accounts.
- Per-conversation message recovery — off by default, graded into three
  profiles (full, sent-only, none) each account sets for itself, composed
  per conversation with the more restrictive side always winning, and
  hostable on storage the participants themselves control rather than a
  DRAtchet-run service.
- Group chat roadmap (v2): MLS/TreeKEM (RFC 9420) over a custom group
  ratchet, why a Group Coordination Service becomes mandatory once
  membership changes need one agreed-upon ordering, and how the same
  most-restrictive-wins recovery policy extends from two participants to N.
- Client architecture (Tauri + Rust, one codebase for Windows/macOS/Linux)
  and threat model.
- Security hardening pulled from prior art: Signal (sealed sender, message
  padding, PQXDH, Key Transparency), Apple iMessage's PQ3, Briar (Tor-based
  P2P, panic response), and OTR (message deniability).

## Building

```
cargo test -p dratchet-core
```

Requires `libssl-dev`/`pkg-config` on Linux (`sequoia-openpgp`'s crypto
backend); see [`.github/workflows/ci.yml`](.github/workflows/ci.yml) for
the exact CI setup. `core/tests/queue_depth.rs` is the test that actually
checks the queue-depth claim above against arbitrarily-ordered delivery,
including a property test over random burst sizes and delivery orderings.

Fuzz targets for the two parsers that handle untrusted bytes off the wire
(`Envelope::decode`, `payload::untag_and_unpad`) live in `core/fuzz/` — see
[`core/fuzz/README.md`](core/fuzz/README.md). CI runs a 60-second smoke pass
on each per PR; a longer local run is worth doing before any change to
either parser.

## License

GPL-3.0 — see [`LICENSE`](LICENSE).
