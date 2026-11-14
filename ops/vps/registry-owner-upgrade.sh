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

# Claude fills C and the input hashes after review and commit (D-001).
# Every input is pinned; gzip output depends on zlib, so the capsule bytes are not.
C=d6086f7571a8a4a6869f9b50e7c9bdf05e7d633a
B=98e8541d332df997c4c144e57e4fa4a5ccb46f9c1add9bdb064e0e42d43d6d92
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
  sudo mkdir -p -m 0700 "$work/$(dirname "$2")"
  sudo curl --fail --silent --show-error --max-time 30 --proto '=https' --tlsv1.2 "$R/$2" -o "$work/$2"
  sudo chmod 0600 "$work/$2"
  printf '%s  %s\n' "$1" "$work/$2" | sudo sha256sum --check --status
}

O=tools/semantic_registry_operational_owner_v2
get "$B" scripts/build-registry-operational-owner-v2-capsule.py
get f7d5c566dc3bab63873970ed781682d65f18f10aa69b01b74c037c9e1780cb57 \
  releases/semantic-registry-checkpoint-successor-20261023.py
get 86e70b8cc043c6b5b44b186601d098e71c46130039fe9d35d3c1529adfc09a79 \
  tools/semantic_authority_mandates/mandates.py
get 5ef38d897dce2a03e5d3583d001166cb9fc0e28e67497cdc608074ac53843a2c "$O/core.py"
get 74ace46309720c7ffc3365e5089b66783283a8930a01a26419f9a3c0ba6f41e1 "$O/store.py"
get ddd1a425decb0bf6ad2661831dc8160b0580c3d097f55e198cddcef0881cefb1 "$O/contract.py"
get 22e07b8907dc9d1a5b83eda9bce30d2308137eae4b149ebf9a21c6d969f9199e "$O/guard.py"
get 5507e3e67bf8b6248cd2875217176bc887703fe051d8d42d875743b514f32cb7 "$O/durable.py"
get 4424a2437b90f6142823e2024e362f35068896cdfe4b4459243e3448124558d9 "$O/adapter.py"
get 5b52217bea987b58a09e8841c02875e45f798a267f76cd7099c671d2236f20b1 "$O/service.py"
get 1e66136d9e36e072a8eaeb824000f32b4f29043ad00def403b6d13aaf64bf996 "$O/installation.py"
get 13a5492f8d3a2338280e6aaf61c120b12324e85113e0a7dd2d451c7a98e59c19 "$O/upgrade.py"
get 6cb118b045b295893fd18b83246b51114288aa58c24acb547b8c69691933a509 "$O/entry.py"

# Deterministic payload; the capsule bootstrap re-verifies payload and sources.
sudo /usr/bin/python3.13 -I -B "$work/scripts/build-registry-operational-owner-v2-capsule.py" \
  --source-commit "$C" --output "$work/capsule.py"
sudo chmod 0400 "$work/capsule.py"

run() { sudo /usr/bin/python3.13 -I -B -S "$work/capsule.py" "$@"; }
case "$mode" in
  prepare) run upgrade-prepare "$V1" "$a2" ;;
  issue) run upgrade-issue "$a2" "$a3" ;;
  install) run upgrade-install "$a2" "$a3" ;;
  start) run upgrade-start "$a2" "$a3" ;;
  rollback-plan) run upgrade-rollback "$a2" "$a3" ;;
  rollback-apply) run upgrade-rollback "$a2" "$a3" "$a4" ;;
esac
