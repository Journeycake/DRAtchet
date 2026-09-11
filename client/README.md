# dratchet-client — reference CLI client

A reference/test implementation of Option B (`docs/ARCHITECTURE.md` §6.3a):
the X3DH handshake happens **directly between two clients**, never touching
`dratchetd`, and the server is used only to relay Double Ratchet envelopes
through a temporary, single-use Tier 1 mailbox neither party's long-term
identity is ever registered under. It exists to exercise the real protocol
end to end — real WebSocket connections to a real server, real X3DH, a real
Double Ratchet — the same "no mocked crypto" testing philosophy
`server/tests/` already follows (see `client/tests/integration.rs`).

**This is not the production app.** There's no persistence, no QR code
rendering/scanning, no multi-device, no group chat, and the terminal UI is
deliberately minimal. The eventual Tauri desktop/mobile client is a
separate, future piece of work; this crate's job is to prove the protocol
works and to give the rest of the project something concrete to test
against.

## What "Option B" means here

- Each run generates a **fresh identity** (`Account::generate()`) — no
  persistence between runs.
- Pairing exchanges a fresh, single-use **routing id**, never the identity
  fingerprint, so the server can never correlate this conversation with
  either party's long-term identity or any other conversation they have.
- The shared Tier 1 mailbox is `dratchet_core::conversation_id(routing_id_a,
  routing_id_b)` — one mailbox, shared by **both directions** of the
  conversation.
- The X3DH handshake (`src/handshake.rs`) runs entirely client-to-client.
  `dratchetd` never sees identity keys, prekey bundles, or ratchet state —
  only opaque routing ids and encrypted envelope bytes.

## QR code stand-in

`docs/ARCHITECTURE.md` §6.3a describes exchanging pairing material via QR
code, scanned in person (and, in a future version, with an added SAS
comparison step to defeat relay/MITM attacks — see that section for why).
This CLI has no camera and no display to render a QR code to, so
`src/pairing.rs` stands that step in with a base64-encoded CBOR blob you
copy from one terminal and paste into the other. The **data format** in
`pairing.rs` (`PairingBundle`/`PairingResponse`) is the real thing, not a
placeholder — only the QR rendering/scanning step itself is stubbed out.

## Running two clients against each other

1. Start a server (see `../server/README.md`):
   ```sh
   cargo run -p dratchet-server --bin dratchetd
   ```
2. In one terminal, run client A:
   ```sh
   cargo run -p dratchet-client --bin dratchet-cli
   ```
   When prompted "scan or wait", choose **wait** — this side generates and
   prints a `PairingBundle` blob first.
3. In a second terminal, run client B:
   ```sh
   cargo run -p dratchet-client --bin dratchet-cli
   ```
   Choose **scan**, then paste in the blob client A printed. Client B
   prints a `PairingResponse` blob back.
4. Paste client B's response blob into client A's terminal.
5. Both sides are now paired and share a mailbox id. **Client B (the one
   that chose "scan") must send the first message** — standard Double
   Ratchet behavior: the responder side has no sending chain until it's
   received and ratcheted forward on the initiator's first message.
   Client B sending first is a protocol requirement here, not a client
   limitation; after that, either side can send in any order. Type a line
   and press Enter in either terminal to send it; each side polls for new
   messages every couple of seconds.
6. `/quit` to exit either side.

By default both point at `ws://127.0.0.1:8787/v1/ws`; pass `--server
ws://host:port/v1/ws` to point elsewhere.

## Why a decrypt failure is never an error here

Because the mailbox is shared by both directions, a client's own poll will
periodically see its own previously-sent envelopes — it has no receiving
chain for its own outgoing DH key, so decrypting them always fails. That's
expected, not a bug: `receive_pending` in `src/main.rs` treats any decrypt
failure as a silent skip, and only ever deletes an entry after a
**successful** decrypt — so a message is never destroyed before its actual
intended recipient has had the chance to read and decrypt it.

## Testing

`tests/integration.rs` spins up a real `dratchet_server::app()` on an
ephemeral port and drives two full accounts through pairing and a real
two-way encrypted message exchange — no interactive stdio, no mocks:

```sh
cargo test -p dratchet-client
```
