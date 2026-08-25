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
system design, including:

- Why a literal per-message PGP-keypair rotation isn't feasible under
  message queueing, and how Double Ratchet solves it.
- The X3DH-over-OpenPGP session establishment handshake.
- The Double Ratchet message layer and key lifecycle (what's single-use,
  what's rotated, what's discarded, and when).
- Client architecture (Tauri + Rust) and threat model.

## License

GPL-3.0 — see [`LICENSE`](LICENSE).
