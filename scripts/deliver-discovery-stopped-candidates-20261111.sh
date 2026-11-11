#!/usr/bin/env bash
set -euo pipefail

case "${1-}:$#" in
  --plan:1|--apply:3|--remove-first:3) ;;
  *) printf '%s\n' 'Uso: --plan, --apply --plan-sha256 HASH oppure --remove-first CID TRANSACTION' >&2; exit 2 ;;
esac
if [[ "$1" == --apply && ( "$2" != --plan-sha256 || ! "$3" =~ ^[0-9a-f]{64}$ ) ]]; then
  printf '%s\n' 'Per --apply serve il planSha256 della ricevuta PLAN_READY.' >&2
  exit 2
fi

ouf_source='https://raw.githubusercontent.com/GioNob/ouf-deploy/ed320955f0dc04870336f916a6494c8edae8ceaf/scripts'
ouf_creator='create-discovery-stopped-candidates-20261111.py'
ouf_preflight='read-discovery-stopped-creation-preflight-20261110.py'
ouf_image='read-discovery-stopped-image-review-20261111.py'
ouf_creator_hash='74f7b1cbf5d43f39cd7485bee8dc7a8c2ef461d5d22ef48c495764bc186183f3'
ouf_preflight_hash='90524a905926e37fce9445adfab6928ada42989093f9b66d80abcb8de6a4b3f7'
ouf_image_hash='ee38a75f4b2e5d715816fa75a93bf5f390020e27e82ea4b37fb4c8444b823ce0'
ouf_work=$(mktemp -d "${TMPDIR:-/tmp}/ouf-discovery-stopped.XXXXXXXX")
trap 'rm -rf -- "$ouf_work"' EXIT

for ouf_file in "$ouf_creator" "$ouf_preflight" "$ouf_image"; do
  curl --fail --silent --show-error --max-time 30 --proto '=https' --tlsv1.2 \
    "$ouf_source/$ouf_file" -o "$ouf_work/$ouf_file"
done
printf '%s  %s\n' \
  "$ouf_creator_hash" "$ouf_work/$ouf_creator" \
  "$ouf_preflight_hash" "$ouf_work/$ouf_preflight" \
  "$ouf_image_hash" "$ouf_work/$ouf_image" | sha256sum --check --status

sudo /usr/bin/python3 -I -B - "$ouf_work/$ouf_creator" "$ouf_creator_hash" \
  --preflight "$ouf_work/$ouf_preflight" --image-review "$ouf_work/$ouf_image" "$@" <<'PY'
import hashlib
from pathlib import Path
import sys

path, expected, *args = sys.argv[1:]
source = Path(path).read_bytes()
if hashlib.sha256(source).hexdigest() != expected:
    raise SystemExit("CREATOR_SOURCE_CHANGED")
sys.argv = [path, *args]
exec(compile(source, path, "exec"), {"__name__": "__main__", "__file__": path})
PY
