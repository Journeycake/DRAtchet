# dratchet-server — Signaling & Presence Service

Phase 1.1 of the v1 build plan. This is the first of DRAtchet's two
*optional* 1:1-model server components described in
[`docs/SERVERS.md`](../docs/SERVERS.md) §1 — a single small service that
does four related jobs over one WebSocket endpoint:

1. **Prekey bundle directory** — publish/fetch by `username#NNNN`.
2. **WebRTC rendezvous** — relay SDP offer/answer + ICE candidates so two
   online clients can establish a direct (Tier 0) connection.
3. **Tier 1 mailbox** — hold ratchet message envelopes transiently, TTL'd,
   for a recipient who isn't reachable for direct delivery.
4. **Presence** — online/away/offline status, visible only to a connection
   that has previously fetched the target's bundle.

It never sees plaintext, ratchet state, or long-term private key material,
and it holds **no durable state**: everything lives in memory and is lost
(harmlessly, by design) on restart — see §1.4 of `docs/SERVERS.md`.

This document covers installing and running the service itself
(`dratchetd`). For the wire protocol it speaks, see
[`src/protocol.rs`](src/protocol.rs)'s module documentation and
[`docs/MESSAGE_SCHEMA.md`](../docs/MESSAGE_SCHEMA.md) §1. For the security
reasoning behind its authentication handshake, see the module
documentation at the top of [`src/ws.rs`](src/ws.rs).

## Installation

### Prerequisites

- **Rust** (stable toolchain), via [rustup](https://rustup.rs/). No other
  system dependencies — the workspace is pure Rust, with no native/OpenSSL
  dependency to install.

### Build from source

From the repository root:

```sh
git clone https://github.com/Journeycake/DRAtchet.git
cd DRAtchet
cargo build --release -p dratchet-server
```

The binary is produced at `target/release/dratchetd`. A debug build
(`cargo build -p dratchet-server`, no `--release`) is faster to compile and
fine for local testing, but noticeably slower under load — use `--release`
for anything resembling the stress test below or a real deployment.

### Verify the build

```sh
cargo test -p dratchet-server
```

This runs the full test suite against a real, locally-bound instance of the
service for every test (no mocked networking or crypto) — see
[Testing](#testing) below for what each suite covers.

## Operation

### Running the service

```sh
./target/release/dratchetd
```

By default it binds `127.0.0.1:8787` and logs:

```
INFO dratchetd listening on 127.0.0.1:8787
INFO WebSocket endpoint: ws://127.0.0.1:8787/v1/ws
```

Stop it with `Ctrl-C` — it shuts down gracefully (`with_graceful_shutdown`),
letting in-flight requests finish rather than dropping connections
mid-frame.

### Configuration

The service takes exactly one setting, since it has no database and no
secrets to configure — everything else about its behavior (auth, TTLs,
frame limits) is fixed by the protocol itself, not tunable at deploy time.

| Setting | Flag | Environment variable | Default |
|---|---|---|---|
| Bind address | `--bind <addr>` | `DRATCHETD_BIND` | `127.0.0.1:8787` |

```sh
# Listen on all interfaces, a non-default port, via the flag:
./target/release/dratchetd --bind 0.0.0.0:8787

# ...or equivalently via the environment:
DRATCHETD_BIND=0.0.0.0:8787 ./target/release/dratchetd
```

Run `./target/release/dratchetd --help` for the auto-generated usage text.

### Endpoints

| Path | Protocol | Purpose |
|---|---|---|
| `/v1/ws` | WebSocket (binary frames) | The service — every job above is multiplexed over this one connection per client. |
| `/healthz` | HTTP GET | Liveness check; returns `200 OK` with body `ok`. Suitable for a load balancer or container orchestrator's health probe. |

```sh
curl http://127.0.0.1:8787/healthz
# ok
```

### Logging

Structured logs via `tracing`, controlled with the standard `RUST_LOG`
environment variable (defaults to `info` if unset):

```sh
RUST_LOG=debug ./target/release/dratchetd
```

### Deployment posture

`docs/SERVERS.md` §1.5 describes two ways to host this same protocol:

- **Ephemeral-fallback (v1 default)**: run as a short-lived process
  (serverless function or equivalent), only ever contacted after a direct
  Tier 0 connection attempt fails. Uptime expectations are modest — a gap
  just means messages sit in a sender's local outbox a little longer.
- **Always-on primary**: the identical binary, run as a persistently
  monitored service (systemd unit, container with a restart policy, etc.)
  and treated as clients' primary path, with Tier 0 attempted only as a
  latency optimization or not at all.

Because all state is in-memory, a restart under either posture is a
non-event for correctness: clients reconnect, re-authenticate, and
re-publish/re-subscribe as needed. It is **not** a non-event for
availability of the Tier 1 mailbox, whose whole purpose is bridging an
offline recipient — a mailbox entry written and not yet fetched is lost if
the service restarts before delivery. Choose the always-on posture (or
front it with a process supervisor that restarts it promptly) if your
deployment leans on Tier 1 store-and-forward rather than Tier 0 direct
connections.

No database, migration, or backup story is needed for this service by
design — see `docs/SERVERS.md` §1.4.

## Testing

```sh
cargo test -p dratchet-server
```

runs four suites, all against a real service bound to an OS-assigned
ephemeral port (`tests/common/mod.rs::spawn_server`) — no mocked
networking, WebSocket transport, or cryptography anywhere in the suite,
matching the project's testing philosophy established in `core/`:

- **Unit tests** (`src/protocol.rs`) — frame encode/decode round-trips,
  and that malformed/truncated/adversarial byte input is always rejected
  as a plain `Err`, never a panic.
- **`tests/integration.rs`** — the golden paths: publish → fetch a bundle,
  one-time prekeys consumed exactly once, the full auth handshake,
  presence subscribe → update delivery, rendezvous relay to an online
  peer (and correctly failing, not silently succeeding, against an offline
  one), and a mailbox write/fetch/delete round trip.
- **`tests/adversarial.rs`** — the paths an attacker (not a well-behaved
  client) would take: connecting and immediately hammering mailbox/
  rendezvous/presence endpoints before authenticating; a forged
  `AuthResponse` signature; replaying a signature captured from a *previous*
  connection against a new connection's (necessarily different) nonce;
  subscribing to a target's presence without ever having fetched their
  bundle first (the anti-enumeration check); one mailbox's entries never
  leaking into a fetch for a different `mailbox_id`; bundles with a
  tampered DH or signed-prekey signature being rejected at publish time
  (and not silently overwriting a previously-good bundle); and a
  `proptest`-driven fuzz of the frame parser against arbitrary byte
  sequences (256 cases) to confirm it never panics.
- **`tests/stress.rs`** — a concurrency/load smoke test: 40 simulated
  clients, each held behind a start barrier until every one of them has
  published a bundle and authenticated, then all 40 run 15 iterations
  concurrently of fetch-bundle → mailbox write/fetch → presence announce →
  rendezvous offer to a ring-neighbor peer, every response validated as
  strictly as the sequential integration tests. On the development
  hardware used to write this service it completes 3,000 request/response
  round trips in roughly a second (~2,500 ops/sec); the test itself only
  asserts a generous 30-second ceiling rather than a specific number, since
  the point is to catch a pathological regression (e.g. an accidental lock
  that serializes every connection), not to make a benchmark claim. Run it
  on its own, with output, to see the actual numbers for your machine:

  ```sh
  cargo test -p dratchet-server --test stress -- --nocapture
  ```

Run everything with `-- --nocapture` if you want to see `tracing` log
output interleaved with test progress.

## Project layout

```
server/
├── src/
│   ├── main.rs      — dratchetd binary: CLI args, logging, bind, graceful shutdown
│   ├── lib.rs        — the axum Router + shared AppState (used by main.rs and tests)
│   ├── protocol.rs   — wire frame format: [tag: u8][CBOR body], all message types
│   ├── state.rs      — in-memory server state (directory, presence, mailboxes, connections)
│   ├── ws.rs          — the connection handler: auth, dispatch, all four jobs
│   └── error.rs       — the service's error type
└── tests/
    ├── common/mod.rs  — shared real-WebSocket test client
    ├── integration.rs — golden-path end-to-end tests
    ├── adversarial.rs — auth-bypass, replay, tamper, and fuzz tests
    └── stress.rs       — concurrent-client load test
```
