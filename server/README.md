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

Settings come from, in increasing order of precedence: the defaults, a
`dratchet.cfg` file (TOML; read from the working directory, or the path in
`--config` / `DRATCHETD_CONFIG`), environment variables, and command-line
flags. An unknown key in `dratchet.cfg` is an error, so a mistyped setting
can't be silently ignored. `server/dratchet.cfg.example` lists every key.

| Setting | `dratchet.cfg` key | Flag | Environment variable | Default |
|---|---|---|---|---|
| Bind address | `bind` | `--bind` | `DRATCHETD_BIND` | `127.0.0.1:8787` |
| Directory database path | `directory_db` | `--directory-db` | `DRATCHETD_DIRECTORY_DB` | `dratchetd-directory.redb` |
| Trusted reverse proxies (CIDRs) | `trusted_proxies` | `--trusted-proxies` | `DRATCHETD_TRUSTED_PROXIES` | empty (use the TCP peer address) |
| Save queued mail to disk | `persist_mailboxes` | `--persist-mailboxes` | `DRATCHETD_PERSIST_MAILBOXES` | off; on below 2 GB of usable memory |
| Fragment directories (two or more) | `fragment_dirs` | `--fragment-dir` (repeat) | `DRATCHETD_FRAGMENT_DIRS` (comma-separated) | none |
| Mail store index | `mailbox_index_db` | `--mailbox-index-db` | `DRATCHETD_MAILBOX_INDEX_DB` | `dratchetd-mailbox-index.redb` |
| Seconds between saves (0–15) | `flush_interval` | `--flush-interval` | `DRATCHETD_FLUSH_INTERVAL` | `10` |
| Bytes of unsaved mail held in memory | `memory_limit` | `--memory-limit` | `DRATCHETD_MEMORY_LIMIT` | a tenth of usable memory |
| Mail store key file | `mailbox_key_file` | `--mailbox-key-file` | `DRATCHETD_MAILBOX_KEY_FILE` | none |
| Mail store key itself | never in the file | — | `DRATCHETD_MAILBOX_KEY` | none |

```sh
# Listen on all interfaces, a non-default port, via the flag:
./target/release/dratchetd --bind 0.0.0.0:8787

# ...or equivalently via the environment:
DRATCHETD_BIND=0.0.0.0:8787 ./target/release/dratchetd
```

The directory database (`username#NNNN` → prekey bundle) is durable
state. Point `--directory-db` at a path on storage that actually survives
a restart; the default (a file in the working directory) does not survive
a container recreate. Without durable storage behind it, a restart forgets
every registration and reopens the squatting window
`docs/ARCHITECTURE.md` §6.1 describes.

#### Queued mail: in memory, or saved to disk (`docs/adr/0001`)

By default, queued mail lives only in memory: a seized disk holds no mail,
and a restart loses whatever was waiting. Clients detect that through the
**Server Epoch** sent when they connect, and offer to resend anything not
yet delivered.

With `persist_mailboxes` on, each queued message is encrypted with the
mail store key into a Sealed Message and split into Fragments, one per
fragment directory, in files named by random UUIDs. An encrypted index
holds which Fragments make up which message and each message's SHA-256.
Put the fragment directories on different volumes where you can: someone
holding only one of them holds no complete message. In this mode:

- A sender's single checkmark waits until its message is on disk. Saves
  run every `flush_interval` seconds, and immediately once unsaved mail
  reaches half of `memory_limit`. Clients are told the interval and wait
  that much longer for the checkmark.
- When memory holds `memory_limit` bytes of unsaved mail, new writes are
  refused without saying why.
- A clean shutdown (SIGTERM or Ctrl-C) makes a last save and records it;
  the next start keeps the same Server Epoch. A start without that record,
  a message that can't be rebuilt intact, or a store that can't be opened
  with the configured key starts a new epoch, so senders are offered Retry.
- Starting with a different key discards the old store. Changing the key
  without losing queued mail is planned for v1.5.

Persistence refuses to start without a key (64 hex characters; a key file
must be readable only by its owner) and at least two different fragment
directories, and says everything that is missing at once. Below 2 GB of
usable memory it is on by default, so a small host needs either both, or
`persist_mailboxes = false` set explicitly. "Usable memory" is the smaller
of total RAM and the container's memory limit.

```sh
# Generate a key file:
umask 077; head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > /etc/dratchetd/mailbox.key
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

For a copy-paste-able, step-by-step walkthrough of deploying this to an
actual test RKE2 cluster (build → ship the image → install → verify →
tear down), including a companion script that automates all of it, see
[`docs/DEPLOY_RKE2.md`](../docs/DEPLOY_RKE2.md). If you don't have a
cluster yet and want to stand one up from scratch on a Raspberry Pi 5
running Rocky Linux (ARM64), see
[`docs/DEPLOY_K3S_PI.md`](../docs/DEPLOY_K3S_PI.md) instead — it bootstraps
a single-node k3s cluster on the Pi itself, then runs the same
build/ship/deploy/verify flow locally (no registry or SSH needed, since the
cluster and the build are the same box). The rest of this section covers
the chart's configuration surface in general — not tied to any one
cluster.

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

### Before you deploy: this chart doesn't yet persist the directory across a pod restart

The binary itself now persists the directory (`username#NNNN` → prekey
bundle) to `--directory-db`'s path — see
[Configuration](#configuration) above and `docs/ARCHITECTURE.md` §6.1 for
why. This chart does not yet mount a `PersistentVolumeClaim` at that
path, so on Kubernetes specifically, a pod restart, reschedule, or rolling
update still writes the directory to the pod's own ephemeral filesystem
and loses it exactly as if persistence weren't built at all. Until a PVC
is added here, running on this chart gets the in-process crash-recovery
benefit (a process restart within the same pod keeps its directory) but
not the pod-lifecycle one. Mount a volume at `--directory-db`'s path
yourself in the meantime if that matters for your deployment.

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
| `config.trustedProxies` | `""` | `DRATCHETD_TRUSTED_PROXIES`. Set to the ingress controller's pod CIDR when `ingress.enabled: true`, so per-address connection limits see real client addresses (DRA-0055). |
| `resources` | `50m`/`32Mi` requests, `500m`/`256Mi` limits | Conservative starting points — use `tests/stress.rs`'s load pattern as a starting point for load-testing your own limits before tuning these. |
| `probes.liveness` / `probes.readiness` | both hit `/healthz` | Identical by design — there's no dependency (database, external call) for readiness to check that liveness doesn't already cover. |
| `terminationGracePeriodSeconds` | `30` | Time given to `SIGTERM`-triggered graceful shutdown (see above) to let in-flight WebSocket connections wind down before a forced kill. |
| `ingress.enabled` | `false` | See the WebSocket-upgrade note in `templates/ingress.yaml` if you enable it — your ingress controller needs WebSocket support and long-enough proxy timeouts for a persistent connection. |
| `ingress.tls` | `[]` | See [TLS / wss://](#tls--wss) directly below — required to get `wss://` instead of plain `ws://` externally. |
| `podDisruptionBudget.enabled` | `false` | Off by default since it's only meaningful once you've deliberately decided to run more than one replica. |
| `mailPersistence.enabled` | `true` | Save queued mail to an encrypted, fragmented store ([Queued mail](#queued-mail-in-memory-or-saved-to-disk-docsadr0001)). Always set explicitly: under this chart's memory limits, dratchetd would otherwise turn it on by itself. With it on, the Deployment uses the `Recreate` strategy, and only one replica can run. |
| `mailPersistence.flushInterval` | `10` | Seconds between saves, 0–15. |
| `mailPersistence.memoryLimit` | `""` | Bytes of unsaved mail held in memory; empty is a tenth of the container's memory limit. |
| `mailPersistence.key.existingSecret` / `.secretKey` | `""` / `key` | A Secret you manage holding the 64-hex-character key. |
| `mailPersistence.key.generate` | `true` | Without `existingSecret`, generate a key into a chart-owned Secret, reused across upgrades; the key never lives on the fragment volumes. Set `false` to make an install without `existingSecret` fail. |
| `mailPersistence.fragments` | two 1 Gi volumes, `a` and `b` | One PersistentVolumeClaim per fragment directory (at least two). Use different storage classes where you can, so no single volume holds a complete message. |
| `mailPersistence.index` | 256 Mi | The PersistentVolumeClaim for the encrypted index. |
| `mailPersistence.ephemeral` | `false` | emptyDir volumes instead of claims, for clusters without a storage provisioner; queued mail is lost when the pod is replaced. `values-test.yaml` sets it. |

Full reference: [`chart/dratchet-server/values.yaml`](../chart/dratchet-server/values.yaml).

**Generating a starting values override**: rather than hand-editing
`values.yaml`, an interactive wizard can walk you through the table above
and write a ready `-f`-able override file:

```sh
cargo run --features wizard --bin dratchetd-config-wizard
# Wrote dratchet-values.generated.yaml
helm upgrade --install dratchet chart/dratchet-server -f dratchet-values.generated.yaml
```

It's a separate, optional binary (`feature = "wizard"`, off by default) —
building the regular `dratchetd` service binary never pulls in its
dependencies. It only covers this deploy-time surface; like everything
else in this section, a change to the generated file still requires a
`helm upgrade` + pod restart to take effect (see the Configuration section
above — `dratchetd` itself has no runtime config reload).

### TLS / wss://

`dratchetd` itself speaks plain `ws://` only — it has no built-in TLS
support, by design: TLS termination belongs at the Ingress, the standard
place for it in Kubernetes, not duplicated into every application. Once
the Ingress serves HTTPS for a host, the WebSocket upgrade on that same
connection automatically becomes `wss://` from the client's point of
view — there's no separate "turn on wss" toggle beyond configuring TLS on
the Ingress. The hop from the Ingress to the pod stays plain `ws://` inside
the cluster network, which is expected (that hop never crosses the
internet).

Two ways to populate `ingress.tls` (see the fuller comment in
[`values.yaml`](../chart/dratchet-server/values.yaml) for the exact
shape):

- **cert-manager** (recommended if your cluster has it) — add its issuer
  annotation to `ingress.annotations` and reference the Secret name it'll
  create in `ingress.tls`; cert-manager issues and renews the certificate
  for you.
- **A TLS Secret you already have** — `kubectl create secret tls ...`,
  then reference that `secretName` in `ingress.tls` directly. No
  annotation needed.

Leaving `ingress.tls: []` while `ingress.enabled: true` is valid — the
chart doesn't require TLS — but it means the endpoint is served as plain,
unencrypted `ws://` externally. The chart surfaces this explicitly rather
than silently: `helm install`'s printed `NOTES.txt` lists the actual
`ws://`/`wss://` URL(s) it computed per host based on `ingress.tls`, and
calls out in bold when none of them are covered by TLS.

**Scope this chart doesn't cover**: exposing a plain `Service` directly
(`NodePort` or a cloud `LoadBalancer`, with `ingress.enabled: false`) has
no TLS story of its own in this chart — that's exactly the posture
[`docs/DEPLOY_RKE2.md`](../docs/DEPLOY_RKE2.md)'s test-cluster runbook
uses (`NodePort`, for a quick smoke test), and it is **not** meant to be
carried into a real deployment for that reason. Getting `wss://` on that
path would need a TLS-terminating layer of your own in front (a cloud
load balancer with TLS termination, a sidecar, etc.) — use the Ingress
path above instead if you need `wss://`.

Verifying it once deployed:

```sh
# From any machine that can resolve/reach the ingress host:
curl -v https://dratchet.example.com/healthz          # confirms the cert
openssl s_client -connect dratchet.example.com:443 -alpn http/1.1 </dev/null

# A WebSocket-aware client, if you have one installed (e.g. `websocat` or
# `wscat`) is the real end-to-end check, since curl doesn't speak the
# WebSocket upgrade itself:
websocat wss://dratchet.example.com/v1/ws
```

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
