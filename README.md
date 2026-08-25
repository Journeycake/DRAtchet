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

Status: **design phase, no application code yet.**

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full protocol and
system design, and [`docs/MESSAGE_SCHEMA.md`](docs/MESSAGE_SCHEMA.md) for
the concrete wire formats. Highlights:

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
- Per-conversation message recovery — off by default, opt-in only with
  mutual consent from both participants, and hostable on storage the
  participants themselves control rather than a DRAtchet-run service.
- Client architecture (Tauri + Rust, one codebase for Windows/macOS/Linux)
  and threat model.

## License

GPL-3.0 — see [`LICENSE`](LICENSE).
