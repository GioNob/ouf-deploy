#!/usr/bin/env bash
set -euo pipefail

case "${1-}:$#" in
  --plan:1|--apply:3) ;;
  *) printf '%s\n' 'Uso: --plan oppure --apply --plan-sha256 HASH' >&2; exit 2 ;;
esac
if [[ "$1" == --apply && ( "$2" != --plan-sha256 || ! "$3" =~ ^[0-9a-f]{64}$ ) ]]; then
  printf '%s\n' 'Per --apply serve il planSha256 della ricevuta PLAN_READY.' >&2
  exit 2
fi

ouf_source='https://raw.githubusercontent.com/GioNob/ouf-deploy/7f1506fa4742ac853c8e39ffd89a69c3480fc28b'
ouf_cutover='cutover-semantic-provider-20261111.py'
ouf_cutover_sha='1d34c20d5e06909f8d81389f3eed971c56492d93f55244dd90a3edd417c79096'
ouf_work=$(mktemp -d "${TMPDIR:-/tmp}/ouf-semantic-provider-cutover.XXXXXXXX")
trap 'rm -rf -- "$ouf_work"' EXIT

ouf_fetch() {
  local source=$1 expected=$2 destination="$ouf_work/${1##*/}"
  curl --fail --silent --show-error --max-time 30 --proto '=https' --tlsv1.2 \
    "$ouf_source/$source" -o "$destination"
  printf '%s  %s\n' "$expected" "$destination" | sha256sum --check --status
}

ouf_fetch "scripts/$ouf_cutover" "$ouf_cutover_sha"
ouf_fetch scripts/upgrade-semantic-application-20261108.py 2e7e7e42367b3329f6ebd441bba665f974ea43871049d863415524610138efb1
ouf_fetch tools/acquisition_read_native/retained_mac.py cb5dbbee4a80ce71860dfe5d32362a662d98898c58fd82009e69c5eb6ac1f7ce
ouf_fetch tools/m2_discovery_installation_profile/audit.py e8b7813a8f6f009054593025dc2df9b79315bf2100a70f02a41973a0536658c3
ouf_fetch tools/m2_discovery_installation_profile/public_truststore.py ade7e834d8b011da28534f416bfbb958d9cab1b1eb32dd94360c4c29dd589579

sudo /usr/bin/python3 -I -B - "$ouf_work/$ouf_cutover" "$ouf_cutover_sha" "$@" <<'PY'
import hashlib
from pathlib import Path
import sys

path, expected, *args = sys.argv[1:]
source = Path(path).read_bytes()
if hashlib.sha256(source).hexdigest() != expected:
    raise SystemExit("CONTROLLER_SOURCE_CHANGED")
sys.argv = [path, *args]
exec(compile(source, path, "exec"), {"__name__": "__main__", "__file__": path})
PY
