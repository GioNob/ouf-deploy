#!/usr/bin/env bash
# Runbook task-30b: governed upgrade of the Registry credential worker v1 -> v2 (D-031).
# Uso:  bash registry-owner-upgrade.sh prepare <attempt>
#       bash registry-owner-upgrade.sh issue|install|start <reviewPath> <reviewSha256>
#       bash registry-owner-upgrade.sh rollback-plan <reviewPath> <reviewSha256>
#       bash registry-owner-upgrade.sh rollback-apply <reviewPath> <reviewSha256> <planSha256>
set -euo pipefail
umask 077

clean() { printf %s "${1:-}" | tr -d "[:space:]"; }
mode=$(clean "${1:-}")
a2=$(clean "${2:-}")
a3=$(clean "${3:-}")
a4=$(clean "${4:-}")
hex() { [[ "$1" =~ ^[0-9a-f]{64}$ ]] || { echo "atteso sha256 (ricevuti ${#1} caratteri)" >&2; exit 2; }; }
review() {
  [[ "$a2" =~ ^/etc/ouf/deploy-snapshots/[A-Za-z0-9._/-]+/review\.json$ ]] \
    || { echo "atteso il path della review (ricevuti ${#a2} caratteri)" >&2; exit 2; }
  hex "$a3"
}
case "$mode" in
  prepare) [[ "$a2" =~ ^[1-9]$ ]] || { echo 'uso: prepare <attempt 1-9>' >&2; exit 2; } ;;
  issue|install|start|rollback-plan) review ;;
  rollback-apply) review; hex "$a4" ;;
  *) echo 'uso: prepare | issue | install | start | rollback-plan | rollback-apply' >&2; exit 2 ;;
esac

# Claude fills C, B and K after review and commit (D-001).
C=d6086f7571a8a4a6869f9b50e7c9bdf05e7d633a
B=98e8541d332df997c4c144e57e4fa4a5ccb46f9c1add9bdb064e0e42d43d6d92
K=fdfe489eb8e0a450b3da0529b61c1e22c759bcb62846b139d7e0e738840db0f9
[[ "$C" =~ ^[0-9a-f]{40}$ && "$C" != 0000000000000000000000000000000000000000 ]] \
  || { echo 'runbook non ancora fissato a un commit' >&2; exit 2; }
V1=0b72275fcc2c51be0929ca0ba454de932ae4863af1b2410dd67bef61bf81e91a
P=889c603f0d17cb54060951bcf4c4f9b8c9ebd9e52b392c70209bbb9755d797d9
S=/etc/ouf/deploy-snapshots
R=https://raw.githubusercontent.com/GioNob/ouf-deploy/$C
printf '%s  %s\n' "$P" /usr/bin/python3.13 | sudo sha256sum --check --status

work=$(sudo mktemp -d "$S/registry-owner-v2-source.XXXXXXXX")
sudo chmod 0700 "$work"
trap 'printf "OUF_REGISTRY_OWNER_UPGRADE_DELIVERY=%s\n" "$work"' EXIT

get() {
  sudo mkdir -p -m 0700 "$work/$(dirname "$1")"
  sudo curl --fail --silent --show-error --max-time 30 --proto '=https' --tlsv1.2 "$R/$1" -o "$work/$1"
  sudo chmod 0600 "$work/$1"
}

# The builder is pinned by hash; its only output, the capsule, is pinned by K.
get scripts/build-registry-operational-owner-v2-capsule.py
printf '%s  %s\n' "$B" "$work/scripts/build-registry-operational-owner-v2-capsule.py" | sudo sha256sum --check --status
get releases/semantic-registry-checkpoint-successor-20261023.py
get tools/semantic_authority_mandates/mandates.py
O=tools/semantic_registry_operational_owner_v2
for m in core store contract guard durable adapter service installation upgrade entry; do get "$O/$m.py"; done

sudo /usr/bin/python3.13 -I -B "$work/scripts/build-registry-operational-owner-v2-capsule.py" \
  --source-commit "$C" --output "$work/capsule.py"
sudo chmod 0400 "$work/capsule.py"
printf '%s  %s\n' "$K" "$work/capsule.py" | sudo sha256sum --check --status

run() { sudo /usr/bin/python3.13 -I -B -S "$work/capsule.py" "$@"; }
case "$mode" in
  prepare) run upgrade-prepare "$V1" "$a2" ;;
  issue) run upgrade-issue "$a2" "$a3" ;;
  install) run upgrade-install "$a2" "$a3" ;;
  start) run upgrade-start "$a2" "$a3" ;;
  rollback-plan) run upgrade-rollback "$a2" "$a3" ;;
  rollback-apply) run upgrade-rollback "$a2" "$a3" "$a4" ;;
esac
