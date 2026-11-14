#!/usr/bin/env bash
# Runbook task-32: rilascio della sonda authority-mandates sul collector del gateway (D-030).
# Uso:  bash gateway-authority-probe.sh plan               (sola lettura)
#       bash gateway-authority-probe.sh apply <planSha256>
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

# Claude fills C and L after review and commit (D-001).
C=0000000000000000000000000000000000000000
L=0000000000000000000000000000000000000000000000000000000000000000
[[ "$C" =~ ^[0-9a-f]{40}$ && "$C" != 0000000000000000000000000000000000000000 ]] \
  || { echo 'runbook non ancora fissato a un commit' >&2; exit 2; }
G=5b93e56748034ec678d732cfd40ca915695fefb5
T=a0599016495b4794ab60c8b9f9bc488bbe23ea65f39312176353858fb676bcdf
P=889c603f0d17cb54060951bcf4c4f9b8c9ebd9e52b392c70209bbb9755d797d9
J=/var/lib/ouf-gateway-authority-probe-20261114
printf '%s  %s\n' "$P" /usr/bin/python3.13 | sudo sha256sum --check --status

work=$(sudo mktemp -d /etc/ouf/deploy-snapshots/gateway-authority-probe-source.XXXXXXXX)
sudo chmod 0700 "$work"
trap 'printf "OUF_GATEWAY_AUTHORITY_PROBE_DELIVERY=%s\n" "$work"' EXIT

fetch() {
  local url=$1 out=$2 expected=$3
  sudo curl --fail --silent --show-error --max-time 30 --proto '=https' --tlsv1.2 "$url" -o "$out"
  sudo chmod 0600 "$out"
  printf '%s  %s\n' "$expected" "$out" | sudo sha256sum --check --status
}

fetch "https://raw.githubusercontent.com/GioNob/ouf-deploy/$C/scripts/apply-gateway-authority-probe-20261114.py" \
  "$work/apply.py" "$L"
fetch "https://raw.githubusercontent.com/GioNob/ouf-api-gateway/$G/tools/gateway_operational_collector.py" \
  "$work/gateway_operational_collector.py" "$T"

sudo install -d -m 0700 -o root -g root "$J"
sudo /usr/bin/python3.13 -I -B "$work/apply.py" "${extra[@]}" \
  --candidate-file "$work/gateway_operational_collector.py" --journal-root "$J"
