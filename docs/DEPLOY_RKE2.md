# Deploying to a test RKE2 cluster

A step-by-step runbook for getting `dratchet-server` (`server/README.md`)
running on a test [RKE2](https://docs.rke2.io/) cluster, end to end: build
the image, get it onto the cluster, install the Helm chart
(`chart/dratchet-server/`), verify it's actually serving traffic, and tear
it back down. A companion script,
[`scripts/deploy-rke2-test.sh`](../scripts/deploy-rke2-test.sh), runs every
step below for you — this document explains what it's doing and why, and is
the source of truth if the two ever disagree.

**Scope**: this is written for a *test* cluster and a *smoke-test* deploy —
confirming the service builds, ships, and comes up healthy — not a
production rollout. It uses `chart/dratchet-server/values-test.yaml`, an
overlay with a `NodePort` Service (so it's reachable without an ingress
controller configured) and lower resource requests. See
`server/README.md`'s "Kubernetes / Helm deployment" section for the
production-shaped defaults.

## Prerequisites

On the machine you'll run these commands from (your workstation, a CI
runner, a jump box — anywhere with network access to the cluster):

- `docker` (or another OCI builder — adjust the build command if so)
- `helm` v3
- `kubectl`, with `KUBECONFIG` pointed at your test RKE2 cluster and the
  right context selected (`kubectl config current-context` — confirm this
  before proceeding; a `helm install` against the wrong cluster context is
  a real, easy mistake)
- If you'll use the registry-less image-import path (below): `ssh`/`scp`
  access to the RKE2 node(s), with sudo rights to run `ctr`

On the cluster side: a reachable RKE2 cluster you're allowed to deploy
test workloads to. Nothing else — no special RKE2 configuration, add-ons,
or feature flags are required (see "Why nothing RKE2-specific is needed"
below).

Confirm you're actually pointed at the right cluster before doing anything
else:

```sh
kubectl config current-context
kubectl get nodes
```

## Step 1 — Build the image

From the repository root:

```sh
docker build -t dratchet-server:test .
```

This is the [`Dockerfile`](../Dockerfile) at the repo root: a multi-stage
build producing a statically-linked musl binary in a minimal, non-root
Alpine runtime image. See `server/README.md`'s "Container image" section
for more on it.

## Step 2 — Get the image onto the cluster

RKE2 uses `containerd` as its container runtime — a standard, CRI-compliant
runtime, the same interface any other modern Kubernetes distribution (k3s,
EKS, GKE, kubeadm) presents. Nothing about this step is RKE2-specific;
pick whichever of the two paths below fits how your test cluster is set
up.

### Path A — push to a registry (recommended if you have one)

Works uniformly regardless of node count, and is what you'd do for a real
deployment too:

```sh
docker tag dratchet-server:test <your-registry>/dratchet-server:test
docker push <your-registry>/dratchet-server:test
```

If the registry needs authentication that your cluster's nodes also need
in order to pull, create an `imagePullSecret` and reference it via the
chart's `imagePullSecrets` value (see `values.yaml`) — standard Kubernetes
mechanics that RKE2 doesn't change:

```sh
kubectl create secret docker-registry my-registry-secret \
  --docker-server=<your-registry> \
  --docker-username=<user> --docker-password=<pass> \
  -n dratchet-test  # create the namespace first if it doesn't exist yet
```

### Path B — import directly into containerd (no registry needed)

Useful for a small, disposable test cluster where standing up a registry
isn't worth it. `containerd` supports importing a local image tarball
directly, bypassing a registry entirely — but note this has to be repeated
on **every node** the pod could be scheduled onto, since the image only
lands in that one node's local containerd store:

```sh
docker save dratchet-server:test -o dratchet-server.tar

# Repeat for each RKE2 node (or automate with your usual node-provisioning
# tooling — this is the one-node version):
scp dratchet-server.tar <user>@<node>:/tmp/
ssh <user>@<node> "sudo ctr -n k8s.io images import /tmp/dratchet-server.tar"
```

With this path, set `image.pullPolicy: IfNotPresent` (the chart's default
already) so Kubernetes uses the locally-imported image instead of trying
to pull from a registry that doesn't have it — and either import to every
node, or pin the pod to the node(s) you did import to via
`nodeSelector`/`tolerations` (both exposed in `values.yaml`).

## Step 3 — Install the Helm chart

```sh
kubectl create namespace dratchet-test

helm upgrade --install test chart/dratchet-server \
  --namespace dratchet-test \
  -f chart/dratchet-server/values-test.yaml \
  --set image.repository=<your-registry>/dratchet-server \
  --set image.tag=test \
  --wait --timeout 2m
```

(Drop the `--set image.repository=...` prefix — use just
`--set image.repository=dratchet-server` — if you used Path B's
registry-less import with that exact local tag.)

`values-test.yaml` switches the Service to `NodePort` (reachable without
configuring ingress) and lowers the resource requests/limits for a
small test node — see the comments in that file for the full list of what
it changes from `values.yaml`'s production-shaped defaults, and why.

**Before raising `replicaCount` above 1 for this test**, read the warning
in `values.yaml` and `server/README.md`: `dratchetd`'s state (prekey
directory, presence, mailboxes, live connections) is in-memory and per-pod,
not shared between replicas — multiple replicas behind one Service means
independent, inconsistent copies of that state, not a scaled-out view of
one.

## Step 4 — Verify it's actually up

```sh
kubectl rollout status -n dratchet-test deployment/test-dratchet-server
kubectl get pods -n dratchet-test -l app.kubernetes.io/instance=test
```

Run the chart's built-in smoke test — a `Pod` that curls `/healthz` from
inside the cluster, deleted automatically afterward:

```sh
helm test test -n dratchet-test
```

Reach it directly, two ways:

```sh
# NodePort (values-test.yaml sets service.type: NodePort):
kubectl get svc -n dratchet-test test-dratchet-server
# note the NodePort under 8787:<NODE_PORT>/TCP, then from anywhere that can
# reach a cluster node's IP:
curl http://<any-node-ip>:<NODE_PORT>/healthz

# Or, from any machine with kubectl access, without needing a reachable
# node IP at all:
kubectl port-forward -n dratchet-test svc/test-dratchet-server 8787:8787
curl http://127.0.0.1:8787/healthz
```

Both should return `ok`. Check logs if not:

```sh
kubectl logs -n dratchet-test -l app.kubernetes.io/instance=test --tail=100
```

## Step 5 — Tear down

```sh
helm uninstall test -n dratchet-test
kubectl delete namespace dratchet-test   # optional, removes everything else too
```

If you used Path B (registry-less import), the image tarball you imported
stays cached in each node's `containerd` store — harmless to leave, or
remove explicitly with `sudo ctr -n k8s.io images rm <image>:<tag>` on each
node if you want the space back.

## Why nothing RKE2-specific is needed

Every step above is standard Kubernetes/`containerd` mechanics — RKE2
doesn't introduce anything this service needs to work around:

- It's stateless-per-pod with no volumes (`docs/SERVERS.md` §1.4 — no
  database, nothing written to disk), so there's no storage class, PVC, or
  node-local-storage concern to configure.
- It needs no privileged access, host networking, or special node
  capabilities — the chart's `securityContext` already runs it as a
  non-root user with a read-only root filesystem and all Linux capabilities
  dropped.
- If you enable the chart's optional `Ingress` (off by default; not used
  in this test-cluster runbook, which uses `NodePort` instead) — RKE2
  ships an nginx-based ingress controller by default
  (`rke2-ingress-nginx`), which already handles WebSocket upgrades
  correctly out of the box (this is a WebSocket service,
  `docs/SERVERS.md` §1.2). Just make sure `ingress.className` in
  `values.yaml` matches your RKE2 install's ingress class (`nginx` unless
  you changed it).

## Using the companion script instead

[`scripts/deploy-rke2-test.sh`](../scripts/deploy-rke2-test.sh) automates
every step above:

```sh
# Path A (registry):
REGISTRY=<your-registry> ./scripts/deploy-rke2-test.sh all

# Path B (registry-less import):
RKE2_NODES="node1.example.com node2.example.com" ./scripts/deploy-rke2-test.sh all

# Individually:
./scripts/deploy-rke2-test.sh build
./scripts/deploy-rke2-test.sh ship
./scripts/deploy-rke2-test.sh deploy
./scripts/deploy-rke2-test.sh verify
./scripts/deploy-rke2-test.sh logs
./scripts/deploy-rke2-test.sh teardown
```

Run it with no arguments (or `all`) to do the whole thing in order. See the
script's own header comment for every configuration variable it accepts.
