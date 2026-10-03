#!/usr/bin/env bash
# Build and deploy dratchet-server into the local single-node k3s cluster
# bootstrapped by scripts/bootstrap-k3s-pi.sh — companion script to
# docs/DEPLOY_K3S_PI.md, which explains every step this runs and why. This
# script exists for convenience (copy-paste-run, on the Pi itself); the doc
# is the source of truth if the two ever disagree.
#
# Unlike scripts/deploy-rke2-test.sh (a remote multi-node cluster reached
# over kubectl, image shipped via registry or scp+ssh), this is the
# single-box case: the cluster, the build, and `kubectl`/`helm` all run on
# the same machine, so "shipping" the image is just a local save + import
# into k3s's own containerd — no registry, no SSH, no network hop at all.
#
# Requires, on this machine: k3s + helm (scripts/bootstrap-k3s-pi.sh),
# podman or docker (bootstrap installs podman by default), KUBECONFIG
# pointed at the local cluster (bootstrap prints the export line).
#
# Usage:
#   ./scripts/deploy-k3s-local.sh <command>
#
# Commands:
#   build      Build the container image locally (podman or docker).
#   ship       Save the built image and import it into k3s's containerd.
#   deploy     helm upgrade --install the chart with the Pi overlay.
#   verify     Wait for rollout, run `helm test`, print how to reach it.
#   logs       Tail the running pod's logs.
#   teardown   helm uninstall and (optionally) delete the namespace.
#   all        build + ship + deploy + verify, in order (the default).
#
# Configuration is via environment variables, all optional — every one has
# a test-appropriate default:
#
#   NAMESPACE     Kubernetes namespace to deploy into.        (dratchet-test)
#   RELEASE       Helm release name.                          (test)
#   IMAGE_REPO    Image name.                                 (dratchet-server)
#   IMAGE_TAG     Image tag.                                  (pi-test)
#   ENGINE        "podman" or "docker" — auto-detected
#                 (prefers podman, Rocky's default) if unset.
#   CHART_DIR     Path to the Helm chart.           (chart/dratchet-server)
#   VALUES_FILE   Values overlay for this deploy.
#                 (chart/dratchet-server/values-pi.yaml)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

NAMESPACE="${NAMESPACE:-dratchet-test}"
RELEASE="${RELEASE:-test}"
IMAGE_REPO="${IMAGE_REPO:-dratchet-server}"
IMAGE_TAG="${IMAGE_TAG:-pi-test}"
CHART_DIR="${CHART_DIR:-chart/dratchet-server}"
VALUES_FILE="${VALUES_FILE:-chart/dratchet-server/values-pi.yaml}"
FULL_IMAGE="${IMAGE_REPO}:${IMAGE_TAG}"

log() { printf '\n\033[1;36m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

require() {
  command -v "$1" >/dev/null 2>&1 || die "'$1' is required on PATH but was not found"
}

detect_engine() {
  if [ -n "${ENGINE:-}" ]; then
    echo "$ENGINE"
    return
  fi
  if command -v podman >/dev/null 2>&1; then
    echo podman
  elif command -v docker >/dev/null 2>&1; then
    echo docker
  else
    die "neither podman nor docker found — scripts/bootstrap-k3s-pi.sh installs podman; install one or set ENGINE"
  fi
}

cmd_build() {
  local engine
  engine="$(detect_engine)"
  require "$engine"
  log "Building $FULL_IMAGE with $engine (--platform linux/arm64)"
  "$engine" build --platform linux/arm64 -t "$FULL_IMAGE" .
}

cmd_ship() {
  local engine tarball as_root
  engine="$(detect_engine)"
  require "$engine"
  require k3s
  # k3s's containerd socket is root-owned regardless of the kubeconfig
  # permissions bootstrap-k3s-pi.sh relaxed — sudo only if not already root.
  as_root=""
  [ "$(id -u)" -eq 0 ] || as_root="sudo"
  tarball="$(mktemp -t dratchet-server-XXXXXX.tar)"
  log "Saving $FULL_IMAGE to $tarball"
  # Explicit docker-archive format for podman — ctr's importer reads both
  # OCI and Docker archives, but pinning this removes any doubt across
  # podman versions whose default has shifted before.
  if [ "$engine" = "podman" ]; then
    "$engine" save --format docker-archive "$FULL_IMAGE" -o "$tarball"
  else
    "$engine" save "$FULL_IMAGE" -o "$tarball"
  fi
  log "Importing into k3s's containerd (no registry, no SSH — same box)"
  $as_root k3s ctr -n k8s.io images import "$tarball"
  rm -f "$tarball"
}

cmd_deploy() {
  require kubectl
  require helm
  log "Ensuring namespace $NAMESPACE exists"
  kubectl get namespace "$NAMESPACE" >/dev/null 2>&1 || kubectl create namespace "$NAMESPACE"

  log "helm upgrade --install $RELEASE ($CHART_DIR, +$VALUES_FILE)"
  helm upgrade --install "$RELEASE" "$CHART_DIR" \
    --namespace "$NAMESPACE" \
    -f "$VALUES_FILE" \
    --set image.repository="$IMAGE_REPO" \
    --set image.tag="$IMAGE_TAG" \
    --wait --timeout 2m
}

cmd_verify() {
  require kubectl
  require helm
  log "Rollout status"
  kubectl rollout status -n "$NAMESPACE" "deployment/${RELEASE}-dratchet-server" --timeout=90s

  log "Pods"
  kubectl get pods -n "$NAMESPACE" -l app.kubernetes.io/instance="$RELEASE"

  log "Running helm test (curls /healthz from inside the cluster)"
  helm test "$RELEASE" -n "$NAMESPACE"

  log "How to reach it"
  local node_port node_ip
  node_port="$(kubectl get svc -n "$NAMESPACE" "${RELEASE}-dratchet-server" -o jsonpath='{.spec.ports[0].nodePort}' 2>/dev/null || true)"
  node_ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  if [ -n "$node_port" ]; then
    echo "  NodePort ${node_port} on this Pi:"
    echo "    curl http://${node_ip:-<this-pi-ip>}:${node_port}/healthz"
  fi
  echo "  Or, from this machine directly:"
  echo "    kubectl port-forward -n ${NAMESPACE} svc/${RELEASE}-dratchet-server 8787:8787"
  echo "    curl http://127.0.0.1:8787/healthz"
}

cmd_logs() {
  require kubectl
  kubectl logs -n "$NAMESPACE" -l app.kubernetes.io/instance="$RELEASE" --tail=200 -f
}

cmd_teardown() {
  require helm
  require kubectl
  log "helm uninstall $RELEASE"
  helm uninstall "$RELEASE" -n "$NAMESPACE" || true
  read -r -p "Delete namespace '$NAMESPACE' too? [y/N] " reply
  if [[ "$reply" =~ ^[Yy]$ ]]; then
    kubectl delete namespace "$NAMESPACE"
  fi
  echo "Note: the imported image is still cached in k3s's containerd."
  echo "Remove it if you want the space back: sudo k3s ctr -n k8s.io images rm ${FULL_IMAGE}"
}

case "${1:-all}" in
  build) cmd_build ;;
  ship) cmd_ship ;;
  deploy) cmd_deploy ;;
  verify) cmd_verify ;;
  logs) cmd_logs ;;
  teardown) cmd_teardown ;;
  all)
    cmd_build
    cmd_ship
    cmd_deploy
    cmd_verify
    ;;
  *)
    echo "Usage: $0 {build|ship|deploy|verify|logs|teardown|all}" >&2
    exit 1
    ;;
esac
