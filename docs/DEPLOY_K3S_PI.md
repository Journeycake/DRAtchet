# Deploying to a single-node k3s cluster on a Raspberry Pi 5 (Rocky Linux)

A step-by-step runbook for turning a fresh Raspberry Pi 5 running Rocky
Linux (aarch64) into a working single-node [k3s](https://k3s.io/) cluster
and getting `dratchet-server` (`server/README.md`) running on it, end to
end: bootstrap the host, build the image, get it into the cluster, install
the Helm chart (`chart/dratchet-server/`), verify it's actually serving
traffic, and tear it back down. Two companion scripts run every step below
for you:

- [`scripts/bootstrap-k3s-pi.sh`](../scripts/bootstrap-k3s-pi.sh) — host
  prep + k3s + Helm install. Run once per Pi.
- [`scripts/deploy-k3s-local.sh`](../scripts/deploy-k3s-local.sh) — build,
  ship, deploy, verify, teardown. Run as often as you like.

This document explains what they're doing and why; the scripts are the
source of truth if the two ever disagree.

**Scope**: this is written for a *test* cluster and a *smoke-test* deploy —
confirming the service builds, ships, and comes up healthy on real ARM64
hardware — not a production rollout. See `server/README.md`'s
"Kubernetes / Helm deployment" section for the production-shaped chart
defaults, and
[`docs/DEPLOY_RKE2.md`](DEPLOY_RKE2.md) for the equivalent runbook against
an existing multi-node cluster reached remotely.

**How this differs from `docs/DEPLOY_RKE2.md`**: that runbook assumes a
cluster already exists somewhere reachable over the network, and you're
deploying to it from a separate workstation (image shipped via a registry,
or scp+ssh to each node). Here there's no existing cluster — this *creates*
one, and everything (the cluster, the image build, `kubectl`/`helm`) runs
on the one Pi, so "shipping" the image is a local save + import into k3s's
own `containerd`, no registry or SSH required.

## Prerequisites

- A Raspberry Pi 5 running Rocky Linux (aarch64), with `dnf` and
  `firewalld` (both standard on a default Rocky install), SELinux enforcing
  (also the default — the bootstrap script installs the proper SELinux
  policy for k3s rather than working around it), and outbound internet
  access (to fetch k3s, its SELinux policy RPM, and Helm from their
  upstream sources).
- Root access on the Pi (both scripts expect to run as root or via `sudo`
  where they specifically need it).
- A checkout of this repository on the Pi (`git clone` it, or copy it over)
  — the image build needs the repo's own `Dockerfile` and source tree.

## Step 1 — Bootstrap the host and install k3s

From the repository root, on the Pi:

```sh
sudo ./scripts/bootstrap-k3s-pi.sh
```

What this does, and why each step is there:

- **Disables swap** (`swapoff -a`, comments out any `fstab` swap line, masks
  a zram-swap generator if present) — k3s/kubelet expect swap off by
  default.
- **Loads `overlay`/`br_netfilter` and sets the bridge/forwarding sysctls**
  flannel (k3s's default CNI) needs to route pod traffic correctly.
- **Installs the `k3s-selinux` RPM from Rancher's repo *before* installing
  k3s itself**, so the k3s installer detects it and applies the correct
  SELinux context automatically
  ([documented here](https://docs.k3s.io/advanced#selinux-support)). This
  is the actual fix for Rocky's SELinux-enforcing default — not something
  this runbook works around by suggesting permissive mode.
- **Opens exactly the firewalld ports k3s needs** (`6443/tcp` API,
  `8472/udp` flannel VXLAN, `10250/tcp` kubelet, `30000-32767/tcp` NodePort
  range — this chart's test overlay uses NodePort) rather than disabling
  the firewall outright. Set `FIREWALL_MODE=disable` if you'd rather just
  turn firewalld off entirely (fine for a throwaway box on a trusted
  network, not something to carry into anything longer-lived).
- **Installs `podman`** (Rocky's default container engine — there's no
  Docker in Rocky's own repos) if neither it nor `docker` is already
  present, to build the image with in Step 2.
- **Installs k3s** via the official install script, as a single-node
  `server` (both control-plane and worker — the only sane topology for one
  box), with `--write-kubeconfig-mode 644` so `kubectl`/`helm` work for any
  local user without needing `sudo` for every command. That permission
  relaxation is a testing convenience, not a production posture — the
  doc-comment in the script calls this out too.
- **Waits for the node to report `Ready`**, then **installs Helm** (also
  not in Rocky's default repos).

Idempotent — safe to re-run if something fails partway through. See the
script's own header comment for every environment variable it accepts.

When it finishes, export the kubeconfig it printed (add to `~/.bashrc` if
you want this to persist across shells):

```sh
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
kubectl get nodes
helm version
```

## Step 2 — Build, ship, deploy, and verify

```sh
./scripts/deploy-k3s-local.sh all
```

This runs, in order:

1. **`build`** — `podman build --platform linux/arm64 -t dratchet-server:pi-test .`
   using the repo's existing root [`Dockerfile`](../Dockerfile): a
   multi-stage build producing a statically-linked musl binary in a
   minimal, non-root Alpine runtime image. Nothing Pi-specific needed here
   — the whole workspace is pure Rust with no native/C dependencies
   (`server/README.md`'s "Container image" section), and both `rust:1-alpine`
   and `alpine:3.20` are official multi-arch images, so building natively
   on the Pi's own ARM64 CPU just works — no cross-compilation, no QEMU
   emulation layer.
2. **`ship`** — saves the built image to a tarball and imports it directly
   into k3s's own `containerd` content store
   (`k3s ctr -n k8s.io images import`) — this is the one genuinely
   different step from `docs/DEPLOY_RKE2.md`'s equivalent: no registry
   push, no `scp`/`ssh` to a remote node, because the cluster and the build
   are the same machine. (`podman build`'s image lives in podman's own
   local store, which k3s's separate embedded `containerd` can't see on its
   own — hence the explicit save+import, even though it's all local.)
3. **`deploy`** — `helm upgrade --install` with
   [`chart/dratchet-server/values-pi.yaml`](../chart/dratchet-server/values-pi.yaml),
   an overlay for this exact scenario: `NodePort` Service (reachable
   without configuring ingress), `debug` log level, resource
   requests/limits trimmed further than even `values-test.yaml`'s (a Pi 5's
   RAM is shared with the host OS and k3s's own system pods — coredns,
   traefik, local-path-provisioner, servicelb — not just this service), and
   an explicit `kubernetes.io/arch: arm64` `nodeSelector` (redundant on a
   single-node arm64 cluster, but documents intent and fails fast and
   clearly if this overlay is ever pointed at a mixed-arch cluster later).
4. **`verify`** — waits for rollout, runs the chart's built-in `helm test`
   smoke test (a `Pod` that curls `/healthz` from inside the cluster,
   cleaned up automatically), and prints exactly how to reach it: the
   `NodePort` on the Pi's own IP, or a `kubectl port-forward` alternative.

Run steps individually instead of `all` if you want to inspect in between:

```sh
./scripts/deploy-k3s-local.sh build
./scripts/deploy-k3s-local.sh ship
./scripts/deploy-k3s-local.sh deploy
./scripts/deploy-k3s-local.sh verify
./scripts/deploy-k3s-local.sh logs      # tail the pod's logs
```

Both reachability checks in `verify` should return `ok`:

```sh
curl http://<this-pi's-ip>:<node-port>/healthz

# or
kubectl port-forward -n dratchet-test svc/test-dratchet-server 8787:8787
curl http://127.0.0.1:8787/healthz
```

If not, check logs first:

```sh
kubectl logs -n dratchet-test -l app.kubernetes.io/instance=test --tail=100
```

## Step 3 — Point a real client at it

`dratchetd`'s WebSocket endpoint is `ws://<node-port-url>/v1/ws` (plain
`ws://`, not `wss://` — this NodePort path has no TLS termination; see
`values.yaml`'s `ingress` section and `server/README.md`'s "TLS / wss://"
note if you want to add that later). Point a local dev build of the
`ui/` Tauri app or `app/examples/seed_dev_pair.rs` at it via
`DRATCHETD_BIND`-equivalent client config to exercise the deployed server
with real traffic, the same way `docs/DEPLOY_RKE2.md`'s runbook assumes for
a remote test cluster.

## Step 4 — Tear down

```sh
./scripts/deploy-k3s-local.sh teardown
```

Uninstalls the Helm release and (on confirmation) the namespace. The
imported image stays cached in k3s's `containerd` — harmless to leave, or
remove explicitly:

```sh
sudo k3s ctr -n k8s.io images rm dratchet-server:pi-test
```

To remove k3s itself from the Pi entirely (not run by either script — a
separate, more destructive step):

```sh
sudo /usr/local/bin/k3s-uninstall.sh   # installed by the k3s install script itself
```

## Why nothing about this is fundamentally different from any other Kubernetes distro

Same point `docs/DEPLOY_RKE2.md` makes, still true here: `dratchet-server`
needs no privileged access, host networking, or special node capabilities
(the chart's `securityContext` already runs it as a non-root user with a
read-only root filesystem and all Linux capabilities dropped), and it's
stateless-per-pod with no volumes (`docs/SERVERS.md` §1.4), so there's no
storage class or node-local-storage concern. Everything genuinely specific
to *this* runbook is about getting a cluster to exist at all on a fresh
Rocky Linux ARM64 box in the first place (SELinux policy, firewalld ports,
swap, no Docker in Rocky's default repos) — once k3s is up, it's a normal,
CRI-compliant Kubernetes cluster like any other.
