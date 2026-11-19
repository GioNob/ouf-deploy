#!/usr/bin/env bash
# Runbook task-28: installazione governata del job di rinnovo dei mandati (D-028, D-030).
# Prerequisito (D-030): collector del gateway (task-31) gia' rilasciato sul VPS.
# Uso:  bash mandate-renewal-install.sh plan               (sola lettura)
#       bash mandate-renewal-install.sh apply <planSha256> (installa e abilita il timer)
set -euo pipefail
umask 077

mode=$(printf %s "${1:-}" | tr -d "[:space:]")
hash=$(printf %s "${2:-}" | tr -d "[:space:]")
case "$mode" in
  plan) extra=(--plan) ;;
  apply)
    [[ "$hash" =~ ^[0-9a-f]{64}$ ]] || { echo "uso: apply <planSha256> (ricevuti ${#hash} caratteri)" >&2; exit 2; }
    extra=(--apply --plan-sha256 "$hash") ;;
  *) echo 'uso: plan | apply <planSha256>' >&2; exit 2 ;;
esac

# Claude fills these pins after review and commit (D-001).
C=ca8f195e1c5f2cdf55a275905bfbb8c7573694ba
R=e897704c2387896ad527c65d52b622796324b4f18a80a11a7e8285693f2065be
M=86e70b8cc043c6b5b44b186601d098e71c46130039fe9d35d3c1529adfc09a79
[[ "$C" =~ ^[0-9a-f]{40}$ && "$C" != 0000000000000000000000000000000000000000 ]] \
  || { echo 'runbook non ancora fissato a un commit' >&2; exit 2; }
P=889c603f0d17cb54060951bcf4c4f9b8c9ebd9e52b392c70209bbb9755d797d9
S=/etc/ouf/deploy-snapshots
printf '%s  %s\n' "$P" /usr/bin/python3.13 | sudo sha256sum --check --status

work=$(sudo mktemp -d "$S/authority-mandate-renewal-source.XXXXXXXX")
sudo chmod 0700 "$work"
trap 'printf "OUF_MANDATE_RENEWAL_DELIVERY=%s\n" "$work"' EXIT

fetch() {
  local path=$1 expected=$2
  sudo mkdir -p -m 0700 "$work/$(dirname "$path")"
  sudo curl --fail --silent --show-error --max-time 30 --proto '=https' --tlsv1.2 \
    "https://raw.githubusercontent.com/GioNob/ouf-deploy/$C/$path" -o "$work/$path"
  sudo chmod 0600 "$work/$path"
  printf '%s  %s\n' "$expected" "$work/$path" | sudo sha256sum --check --status
}

fetch tools/semantic_mandate_renewal/renewal.py "$R"
fetch tools/semantic_authority_mandates/mandates.py "$M"

A=/etc/ouf/deploy-snapshots
args=(
  --source-dir "$work"
  --b1b2-anchor "$A/semantic-provider-b1b2-trust-policy-20261112/trust-policy.json"
  --b1b2-anchor-sha256 6ef247ee727484777557cdb5adb05428e6d020da1e2e49773a84eedc56be4f95
  --base-anchor "$A/semantic-trust-policy-preparation-20261004-172336/trust-policy.json"
  --base-anchor-sha256 21122630e52cb63c3744fee89f5c81ed926dad55231190243ca11be6d481bd42
  --authority-profile "$A/semantic-creation-issuer-install-USjonf22/installation-authority-profile.json"
  --authority-profile-sha256 7fb7880d58e43ab40f9f53dac07a5dbad462d12e3a96f3b1287c6763b1d7ce18
  --installation-ref ouf-lab-netcup-01
  --entity-ref ouf-lab
)
printf '%s  %s\n' "$P" /usr/bin/python3.13 | sudo sha256sum --check --status
sudo /usr/bin/python3.13 -I -B "$work/tools/semantic_mandate_renewal/renewal.py" install "${extra[@]}" "${args[@]}"
