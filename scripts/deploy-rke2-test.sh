#!/usr/bin/env bash
# Deploy dratchet-server to a test RKE2 cluster — companion script to
# docs/DEPLOY_RKE2.md, which explains every step this runs and why. This
# script exists for convenience (copy-paste-run); the doc is the source of
# truth if the two ever disagree.
#
# Requires, on the machine running this script: docker, helm, kubectl,
# already pointed at your test cluster (KUBECONFIG set, correct context
# current). Requires, on the cluster side: a reachable test RKE2 cluster.
#
# Usage:
#   ./scripts/deploy-rke2-test.sh <command>
#
# Commands:
#   build      Build the container image locally.
#   ship       Get the built image to the cluster (registry push, or
#              registry-less node import — see SHIP_MODE below).
#   deploy     helm upgrade --install the chart with the test overlay.
#   verify     Wait for rollout, run `helm test`, print how to reach it.
#   logs       Tail the running pod's logs.
#   teardown   helm uninstall and (optionally) delete the namespace.
#   all        build + ship + deploy + verify, in order (the default).
#
# Configuration is via environment variables, all optional except
# REGISTRY or RKE2_NODES (exactly one of which SHIP_MODE needs — see
# below). Every variable has a test-appropriate default otherwise:
#
#   NAMESPACE       Kubernetes namespace to deploy into.        (dratchet-test)
#   RELEASE         Helm release name.                          (test)
#   IMAGE_REPO      Image name (without registry prefix).       (dratchet-server)
#   IMAGE_TAG       Image tag.                                  (test)
#   SHIP_MODE       "registry" or "import" (see docs/DEPLOY_RKE2.md
#                   for the tradeoff). Auto-detected: "registry" if
#                   REGISTRY is set, else "import".
#   REGISTRY        e.g. "registry.example.com/myteam" — required if
#                   SHIP_MODE=registry.
#   RKE2_NODES      Space-separated SSH-reachable node hostnames/IPs —
#                   required if SHIP_MODE=import. Every node the
#                   scheduler might place the pod on needs the image
#                   imported, so list them all (or add a nodeSelector/
#                   taint to pin the pod to the ones you did import to).
#   SSH_USER        SSH user for the import path.                (root)
#   CHART_DIR       Path to the Helm chart.           (chart/dratchet-server)
#   VALUES_FILE     Values overlay for the test deploy.
#                   (chart/dratchet-server/values-test.yaml)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

NAMESPACE="${NAMESPACE:-dratchet-test}"
RELEASE="${RELEASE:-test}"
IMAGE_REPO="${IMAGE_REPO:-dratchet-server}"
IMAGE_TAG="${IMAGE_TAG:-test}"
REGISTRY="${REGISTRY:-}"
RKE2_NODES="${RKE2_NODES:-}"
SSH_USER="${SSH_USER:-root}"
CHART_DIR="${CHART_DIR:-chart/dratchet-server}"
VALUES_FILE="${VALUES_FILE:-chart/dratchet-server/values-test.yaml}"

if [ -n "$REGISTRY" ]; then
  SHIP_MODE="${SHIP_MODE:-registry}"
else
  SHIP_MODE="${SHIP_MODE:-import}"
fi

if [ "$SHIP_MODE" = "registry" ]; then
  FULL_IMAGE="${REGISTRY:?REGISTRY must be set when SHIP_MODE=registry}/${IMAGE_REPO}:${IMAGE_TAG}"
else
  FULL_IMAGE="${IMAGE_REPO}:${IMAGE_TAG}"
fi

log() { printf '\n\033[1;36m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

require() {
  command -v "$1" >/dev/null 2>&1 || die "'$1' is required on PATH but was not found"
}

cmd_build() {
  require docker
  log "Building $FULL_IMAGE from $REPO_ROOT/Dockerfile"
  docker build -t "$FULL_IMAGE" .
}

cmd_ship() {
  case "$SHIP_MODE" in
    registry)
      require docker
      log "Pushing $FULL_IMAGE"
      docker push "$FULL_IMAGE"
      ;;
    import)
      [ -n "$RKE2_NODES" ] || die "SHIP_MODE=import requires RKE2_NODES (space-separated hosts)"
      require docker
      require ssh
      require scp
      local tarball
      tarball="$(mktemp -t dratchet-server-XXXXXX.tar)"
      log "Saving $FULL_IMAGE to $tarball"
      docker save "$FULL_IMAGE" -o "$tarball"
      local node
      for node in $RKE2_NODES; do
        log "Copying image to $node and importing into containerd"
        scp "$tarball" "${SSH_USER}@${node}:/tmp/dratchet-server.tar"
        ssh "${SSH_USER}@${node}" "sudo ctr -n k8s.io images import /tmp/dratchet-server.tar && rm -f /tmp/dratchet-server.tar"
      done
      rm -f "$tarball"
      ;;
    *)
      die "unknown SHIP_MODE '$SHIP_MODE' (expected 'registry' or 'import')"
      ;;
  esac
}

cmd_deploy() {
  require kubectl
  require helm
  log "Ensuring namespace $NAMESPACE exists"
  kubectl get namespace "$NAMESPACE" >/dev/null 2>&1 || kubectl create namespace "$NAMESPACE"

  log "helm upgrade --install $RELEASE ($CHART_DIR, +$VALUES_FILE)"
  local image_repo_arg="$IMAGE_REPO"
  [ "$SHIP_MODE" = "registry" ] && image_repo_arg="${REGISTRY}/${IMAGE_REPO}"

  helm upgrade --install "$RELEASE" "$CHART_DIR" \
    --namespace "$NAMESPACE" \
    -f "$VALUES_FILE" \
    --set image.repository="$image_repo_arg" \
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
  if [ -n "$node_port" ]; then
    node_ip="$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="ExternalIP")].address}' 2>/dev/null || true)"
    [ -z "$node_ip" ] && node_ip="$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}' 2>/dev/null || true)"
    echo "  NodePort ${node_port} on any cluster node, e.g.:"
    echo "    curl http://${node_ip:-<node-ip>}:${node_port}/healthz"
  fi
  echo "  Or, from any machine with kubectl access to this cluster:"
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
  if [ "$SHIP_MODE" = "import" ] && [ -n "$RKE2_NODES" ]; then
    echo "Note: the imported image is still cached in containerd on: $RKE2_NODES"
    echo "Remove it manually if you want, e.g.: ssh <node> sudo ctr -n k8s.io images rm ${FULL_IMAGE}"
  fi
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
