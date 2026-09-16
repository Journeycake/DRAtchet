#!/usr/bin/env bash
# Bootstrap a single-node k3s cluster on a Raspberry Pi 5 running Rocky
# Linux (aarch64) for testing dratchet-server — companion script to
# docs/DEPLOY_K3S_PI.md, which explains every step this runs and why. This
# script exists for convenience (copy-paste-run on the Pi itself, as root
# or via sudo); the doc is the source of truth if the two ever disagree.
#
# Scope: turns a fresh Rocky Linux install into a working single-node k3s
# cluster with Helm available, ready for scripts/deploy-k3s-local.sh. Not a
# production hardening guide — see the "not production" callouts below for
# the specific corners cut for test-cluster convenience.
#
# Usage (run ON the Pi, as root):
#   curl -fsSL <raw-url-to-this-script> | bash
#   # or, from a checked-out copy of this repo:
#   sudo ./scripts/bootstrap-k3s-pi.sh
#
# Idempotent: safe to re-run. Already-applied steps are detected and
# skipped rather than redone.
#
# Configuration via environment variables, all optional:
#
#   K3S_CHANNEL      k3s release channel to install.              (stable)
#   K3S_KUBECONFIG_MODE  Permission mode for the written
#                        kubeconfig — 0644 makes `kubectl`/`helm`
#                        work for any local user without `sudo`,
#                        which is a testing convenience, not a
#                        production posture (root can always read
#                        the default 0600 file via sudo instead).   (644)
#   FIREWALL_MODE    "ports" (open exactly what k3s/flannel/NodePort
#                    need, permanent firewalld rules) or "disable"
#                    (stop+disable firewalld entirely — faster, and
#                    fine for a throwaway single-node test box on a
#                    trusted network, but not something to carry
#                    into anything long-lived or shared).          (ports)
#   SKIP_SWAP_DISABLE   Set to "1" to leave swap alone (advanced;
#                       k3s/kubelet expect swap off by default).    (unset)
#
# Requires: Rocky Linux (or another EL9-family distro) on aarch64, run as
# root, with outbound internet access (installs k3s, k3s-selinux, and Helm
# from their upstream sources).

set -euo pipefail

log() { printf '\n\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run this as root (or with sudo) — it installs packages and system services"

K3S_CHANNEL="${K3S_CHANNEL:-stable}"
K3S_KUBECONFIG_MODE="${K3S_KUBECONFIG_MODE:-644}"
FIREWALL_MODE="${FIREWALL_MODE:-ports}"
SKIP_SWAP_DISABLE="${SKIP_SWAP_DISABLE:-}"

# --- Sanity checks (warn, don't hard-fail, in case this is run on a close
# cousin of the target platform — e.g. Rocky 9 on a different aarch64 SBC) ---
ARCH="$(uname -m)"
if [ "$ARCH" != "aarch64" ]; then
  warn "expected aarch64 (Raspberry Pi 5), found '$ARCH' — continuing anyway, but k3s/the image build below assume ARM64"
fi
if [ -r /etc/os-release ]; then
  . /etc/os-release
  case "${ID:-}" in
    rocky) : ;;
    *) warn "expected Rocky Linux, found ID='${ID:-unknown}' — continuing anyway; this script assumes dnf + firewalld + SELinux enforcing (standard EL9 defaults)" ;;
  esac
fi

log "Disabling swap (k3s/kubelet expect it off)"
if [ -n "$SKIP_SWAP_DISABLE" ]; then
  warn "SKIP_SWAP_DISABLE set — leaving swap as-is"
else
  swapoff -a
  # Comment out (don't delete) any swap line in fstab so a reboot doesn't
  # silently re-enable it.
  if grep -qE '^\s*[^#].*\sswap\s' /etc/fstab; then
    sed -i.bak -E 's/^(\s*[^#].*\sswap\s.*)$/#\1/' /etc/fstab
    log "commented out swap entries in /etc/fstab (backup at /etc/fstab.bak)"
  fi
  # Some Raspberry Pi OS images (and occasionally EL remixes for it) use
  # zram-backed swap via a generator service rather than an fstab line —
  # that needs masking too, or it re-creates a swap device on next boot.
  if systemctl list-unit-files 2>/dev/null | grep -q '^zram-generator\|^zramswap'; then
    systemctl disable --now zram-generator.service zramswap.service 2>/dev/null || true
    log "disabled zram swap generator"
  fi
fi

log "Kernel modules + sysctls the CNI (flannel) needs"
cat >/etc/modules-load.d/k3s.conf <<'EOF'
overlay
br_netfilter
EOF
modprobe overlay 2>/dev/null || true
modprobe br_netfilter 2>/dev/null || true

cat >/etc/sysctl.d/90-k3s.conf <<'EOF'
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward = 1
EOF
sysctl --system >/dev/null

log "Installing k3s-selinux policy (before k3s itself, so the installer picks it up)"
# Without this, k3s under Rocky's default SELinux-enforcing posture either
# refuses to start cleanly or runs noisy/broken under a slew of AVC
# denials — this is the officially documented fix
# (https://docs.k3s.io/advanced#selinux-support), not a workaround.
if ! rpm -q k3s-selinux >/dev/null 2>&1; then
  cat >/etc/yum.repos.d/rancher-k3s-common.repo <<'EOF'
[rancher-k3s-common-stable]
name=Rancher K3s Common (stable)
baseurl=https://rpm.rancher.io/k3s/stable/common/centos/9/noarch
enabled=1
gpgcheck=1
repo_gpgcheck=0
gpgkey=https://rpm.rancher.io/public.key
EOF
  dnf install -y container-selinux selinux-policy-base k3s-selinux
else
  log "k3s-selinux already installed, skipping"
fi

log "Configuring firewalld ($FIREWALL_MODE mode)"
# Ports per https://docs.k3s.io/installation/requirements#networking:
#   6443/tcp        Kubernetes API
#   8472/udp        flannel VXLAN (the default CNI backend)
#   10250/tcp       kubelet metrics/exec
#   30000-32767/tcp NodePort range (values-pi.yaml's Service uses NodePort)
if systemctl is-active --quiet firewalld 2>/dev/null; then
  if [ "$FIREWALL_MODE" = "disable" ]; then
    systemctl disable --now firewalld
    log "firewalld disabled"
  else
    firewall-cmd --permanent --add-port=6443/tcp
    firewall-cmd --permanent --add-port=8472/udp
    firewall-cmd --permanent --add-port=10250/tcp
    firewall-cmd --permanent --add-port=30000-32767/tcp
    # Traffic between the pod/flannel network and the host needs to be
    # trusted for the CNI to function — scope this to the flannel
    # interface only, not the whole box.
    firewall-cmd --permanent --zone=trusted --add-interface=flannel.1 2>/dev/null || true
    firewall-cmd --reload
    log "firewalld rules applied"
  fi
else
  log "firewalld not active, nothing to configure"
fi

log "Installing a container engine to build the image with (podman — Rocky's default)"
if ! command -v podman >/dev/null 2>&1 && ! command -v docker >/dev/null 2>&1; then
  dnf install -y podman
else
  log "a container engine is already present, skipping"
fi

log "Installing k3s (channel: $K3S_CHANNEL)"
if command -v k3s >/dev/null 2>&1; then
  log "k3s already installed ($(k3s --version | head -1)), skipping install (re-run with INSTALL_K3S_FORCE_RESTART=true curl ... | bash if you want to reinstall)"
else
  curl -fsSL https://get.k3s.io | \
    INSTALL_K3S_CHANNEL="$K3S_CHANNEL" \
    INSTALL_K3S_EXEC="server --write-kubeconfig-mode $K3S_KUBECONFIG_MODE" \
    sh -
fi

log "Waiting for the node to report Ready"
for _ in $(seq 1 60); do
  if k3s kubectl get nodes 2>/dev/null | grep -q ' Ready'; then
    break
  fi
  sleep 2
done
k3s kubectl get nodes || die "node never became Ready — check: journalctl -u k3s -e"

log "Installing Helm"
if command -v helm >/dev/null 2>&1; then
  log "helm already installed ($(helm version --short 2>/dev/null)), skipping"
else
  curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
fi

KUBECONFIG_PATH=/etc/rancher/k3s/k3s.yaml
log "Done"
cat <<EOF

k3s is up. For this shell (and add to ~/.bashrc if you want it to persist):

    export KUBECONFIG=$KUBECONFIG_PATH

Then confirm:

    kubectl get nodes
    helm version

Next: scripts/deploy-k3s-local.sh (see docs/DEPLOY_K3S_PI.md) builds the
dratchet-server image and deploys it into this cluster.
EOF
