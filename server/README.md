# dratchet-server — Signaling & Presence Service

Phases 1.1 and 1.2 of the v1 build plan. This is the first of DRAtchet's
two *optional* 1:1-model server components described in
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

Phase 1.2 adds directory abuse resistance on top of that (`ARCHITECTURE.md`
§11.8, [`src/abuse.rs`](src/abuse.rs)):

- **Prekey-fetch rate limiting** — a per-(connection, target) token bucket
  on `FetchBundle`, so repeatedly fetching one account's bundle to exhaust
  its one-time-prekey pool costs increasingly more wall-clock time instead
  of being free.
- **Registration proof-of-work** — claiming a brand-new `username#NNNN`
  requires solving a small SHA-256 grinding puzzle first, a PII-free,
  cost-based floor against mass-registering usernames to squat them.
  Rotating a username your own identity already owns never needs this.
- **Username ownership enforcement** — a `PublishBundle` for a
  `username#NNNN` already owned by a *different* identity is rejected
  outright, regardless of proof-of-work; first-come-first-served, not
  first-*claims*-wins.

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

### Shutdown signals

`dratchetd` shuts down gracefully (finishing in-flight requests rather than
dropping connections mid-frame) on either `SIGINT` (Ctrl-C, interactive use)
or `SIGTERM` (what `docker stop` and a Kubernetes pod termination/rolling
update send) — see `shutdown_signal()` in `src/main.rs`.

## Container image

A [`Dockerfile`](../Dockerfile) at the repository root builds `dratchetd` as
a statically-linked musl binary (`rust:1-alpine` builder stage) and ships it
in a minimal `alpine:3.20` runtime image, running as a non-root user
(uid `10001`). The whole workspace is pure Rust with no native/C
dependencies, so nothing beyond the Rust toolchain itself is needed to build
it — no extra `apt`/`apk` packages in the runtime image, no OpenSSL.

```sh
docker build -t dratchet-server:local .
docker run --rm -p 8787:8787 dratchet-server:local
curl http://127.0.0.1:8787/healthz
```

Configuration is via environment variables, same as running the binary
directly (see [Configuration](#configuration) above) — `DRATCHETD_BIND` is
set to `0.0.0.0:8787` in the image by default so it's reachable from outside
the container without extra flags.

## Kubernetes / Helm deployment

A Helm chart at [`chart/dratchet-server`](../chart/dratchet-server) deploys
the container image above: a `Deployment`, a `ClusterIP` `Service`, a
dedicated `ServiceAccount`, a `ConfigMap` for the environment variables
above, an optional `Ingress` (disabled by default), an optional
`PodDisruptionBudget` (disabled by default), and a `helm test` hook that
curls `/healthz` from inside the cluster.

### Before you deploy: this service does not horizontally scale by default

**Read `values.yaml`'s `replicaCount` comment before setting it above `1`.**
`dratchetd` holds its entire state — prekey directory, presence, mailboxes,
live connections — in memory, per pod (`docs/SERVERS.md` §1.4: there is no
database, and nothing is shared between replicas). A client's WebSocket
connection lives on whichever one pod it happened to land on. Running
multiple replicas behind the chart's single `Service` gives you *N*
independent, inconsistent copies of that state, not a scaled-out view of
one — a client load-balanced to a different pod than the one it published
its bundle to simply won't find it there. The chart defaults to
`replicaCount: 1` for exactly this reason; only raise it if you've solved
routing consistency yourself (e.g. consistent-hashing per identity
fingerprint at the ingress/load-balancer layer), which this chart does not
set up for you. The rendered `NOTES.txt` repeats this warning if
`replicaCount` is set above `1`.

### Install

```sh
# Build and make the image available to your cluster first (push it to a
# registry your cluster can pull from, or import it directly if your
# runtime supports that — see the RKE2/containerd note below).
docker build -t <your-registry>/dratchet-server:0.1.0 .
docker push <your-registry>/dratchet-server:0.1.0

helm install dratchet chart/dratchet-server \
  --set image.repository=<your-registry>/dratchet-server \
  --set image.tag=0.1.0

kubectl get pods -l app.kubernetes.io/name=dratchet-server
helm test dratchet
```

### Configuration (`values.yaml`)

| Key | Default | Purpose |
|---|---|---|
| `image.repository` / `image.tag` | `dratchet-server` / chart's `appVersion` | Where to pull the image built above from. |
| `replicaCount` | `1` | See the scaling warning above — change with care. |
| `service.port` | `8787` | Also becomes `DRATCHETD_BIND`'s port via the chart's `ConfigMap`. |
| `config.logLevel` | `"info"` | `RUST_LOG` value passed to the container. |
| `resources` | `50m`/`32Mi` requests, `500m`/`256Mi` limits | Conservative starting points — use `tests/stress.rs`'s load pattern as a starting point for load-testing your own limits before tuning these. |
| `probes.liveness` / `probes.readiness` | both hit `/healthz` | Identical by design — there's no dependency (database, external call) for readiness to check that liveness doesn't already cover. |
| `terminationGracePeriodSeconds` | `30` | Time given to `SIGTERM`-triggered graceful shutdown (see above) to let in-flight WebSocket connections wind down before a forced kill. |
| `ingress.enabled` | `false` | See the WebSocket-upgrade note in `templates/ingress.yaml` if you enable it — your ingress controller needs WebSocket support and long-enough proxy timeouts for a persistent connection. |
| `podDisruptionBudget.enabled` | `false` | Off by default since it's only meaningful once you've deliberately decided to run more than one replica. |

Full reference: [`chart/dratchet-server/values.yaml`](../chart/dratchet-server/values.yaml).

### Validating the chart

```sh
helm lint chart/dratchet-server
helm template dratchet chart/dratchet-server | kubeconform -summary -strict -
```

[`kubeconform`](https://github.com/yannh/kubeconform) validates rendered
manifests against the upstream Kubernetes OpenAPI schemas without needing a
live cluster. CI (`.github/workflows/ci.yml`'s `helm` job) runs both of the
above, plus a second render with `ingress`, `podDisruptionBudget`, multiple
replicas, and `imagePullSecrets` all enabled, so the less-common code paths
through the templates are exercised too — not just the defaults.

### RKE2 (containerd) specifics

Nothing RKE2-specific is required — RKE2 uses `containerd` as a standard,
CRI-compliant container runtime, the same interface any other modern
Kubernetes distribution (k3s, EKS, GKE, kubeadm) presents. This is a
stateless-per-pod (see above), volume-free service with no host-level
requirements (no privileged containers, no hostPath mounts, no special
node capabilities), so it needs nothing beyond what any workload needs to
run under containerd:

- **Getting the image to the cluster**: if you don't have a registry
  reachable from your RKE2 nodes, `containerd` supports importing a locally
  built image directly, bypassing a registry entirely:

  ```sh
  docker save dratchet-server:local -o dratchet-server.tar
  # on each RKE2 node (or via your node-provisioning tooling):
  sudo ctr -n k8s.io images import dratchet-server.tar
  ```

  Then reference it in `values.yaml`/`--set` with a tag `containerd` already
  has locally and `image.pullPolicy: IfNotPresent` (the chart's default) so
  it doesn't try to pull from a registry that doesn't have it.
- **Private registries**: if you do use one, set `imagePullSecrets` in
  `values.yaml` (the chart wires it straight into the pod spec) — same as
  any other Kubernetes distribution; RKE2 doesn't need anything extra.
- **Ingress**: RKE2 ships an nginx-based ingress controller by default
  (`rke2-ingress-nginx`), which already handles WebSocket upgrades
  correctly out of the box — no special annotation is required for the
  upgrade itself, just make sure `ingress.className` matches what your RKE2
  install uses (`nginx` unless you changed it) if you enable `ingress` in
  the chart.

### A note on what was, and wasn't, verified in the environment this was built in

`cargo build`/`cargo test` (the Rust code itself, including the `SIGTERM`
change above) were run and passed directly. `helm lint`, `helm template`
against several value combinations, and `kubeconform -strict` validation of
every rendered manifest were also run directly and passed. Actually running
`docker build` and deploying to a live cluster were **not** possible in the
sandbox this was developed in — its egress policy blocks pulls from Docker
Hub's image storage CDN — so the `Dockerfile` itself was reviewed carefully
but not executed; CI's new `docker` job (`.github/workflows/ci.yml`) builds
it for real on every push/PR from here on, which is the first real build
signal for it. Treat the first CI run and your own first `helm install`
against a real RKE2 cluster as the actual verification of those two pieces.

## Testing

```sh
cargo test -p dratchet-server
```

runs five suites, all against a real service bound to an OS-assigned
ephemeral port (`tests/common/mod.rs::spawn_server`) — no mocked
networking, WebSocket transport, or cryptography anywhere in the suite,
matching the project's testing philosophy established in `core/`:

- **Unit tests** (`src/protocol.rs`, `src/abuse.rs`) — frame encode/decode
  round-trips and malformed/truncated/adversarial byte input always
  rejected as a plain `Err`, never a panic (`protocol.rs`); the
  proof-of-work solve/verify primitives and the fetch rate limiter's
  token-bucket behavior in isolation (`abuse.rs`).
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
- **`tests/abuse.rs`** — Phase 1.2's directory-abuse-resistance defenses
  wired into the real `PublishBundle`/`FetchBundle` dispatch path (not just
  the `abuse.rs` unit tests' isolated primitives): a brand-new username
  registered with no proof-of-work, or with a solution solved for a
  different username, is rejected and never stored; a valid solution
  succeeds; rotating a bundle's own already-owned username never requires
  solving it again; a second identity cannot steal an already-registered
  username even with its own valid proof-of-work; and bursting
  `FetchBundle` calls against one target from one connection eventually
  gets rate-limited, without affecting a different, never-fetched target's
  own budget.
- **`tests/stress.rs`** — a concurrency/load smoke test: 40 simulated
  clients, each held behind a start barrier until every one of them has
  published a bundle and authenticated, then all 40 fetch their ring
  neighbor's bundle once (like a real client establishing one X3DH
  session — repeating it every iteration would just exercise the Phase 1.2
  fetch rate limiter above, not load-test the service) and run 15
  iterations concurrently of mailbox write/fetch → presence announce →
  rendezvous offer to that peer, every response validated as strictly as
  the sequential integration tests. On the development hardware used to
  write this service it completes a couple thousand request/response round
  trips in about a second (~2,000+ ops/sec); the test itself only asserts a
  generous 30-second ceiling rather than a specific number, since the point
  is to catch a pathological regression (e.g. an accidental lock that
  serializes every connection), not to make a benchmark claim. Run it on
  its own, with output, to see the actual numbers for your machine:

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
│   ├── abuse.rs        — Phase 1.2: fetch rate limiter, registration proof-of-work
│   └── error.rs       — the service's error type
└── tests/
    ├── common/mod.rs  — shared real-WebSocket test client
    ├── integration.rs — golden-path end-to-end tests
    ├── adversarial.rs — auth-bypass, replay, tamper, and fuzz tests
    ├── abuse.rs        — directory-abuse-resistance tests (Phase 1.2)
    └── stress.rs       — concurrent-client load test
```
