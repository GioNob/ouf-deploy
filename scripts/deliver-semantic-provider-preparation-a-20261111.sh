#!/usr/bin/env bash
set -euo pipefail
umask 077

case "${1-}:$#" in
  --plan:1|--apply:3) ;;
  *) printf '%s\n' 'Uso: --plan oppure --apply --plan-sha256 HASH' >&2; exit 2 ;;
esac
if [[ "$1" == --apply && ( "$2" != --plan-sha256 || ! "$3" =~ ^[0-9a-f]{64}$ ) ]]; then
  printf '%s\n' 'Per --apply serve il planSha256 della ricevuta PLAN_READY.' >&2
  exit 2
fi

ouf_repo='https://raw.githubusercontent.com/GioNob/ouf-deploy'
ouf_controller='prepare-semantic-provider-a-20261111.py'
ouf_controller_sha='719a3ee3051ecddcd45c9830b5894d5abc6fac16674b3e57bbefc193b1d3aa4e'
ouf_work=$(mktemp -d "${TMPDIR:-/tmp}/ouf-semantic-provider-a.XXXXXXXX")
trap 'rm -rf -- "$ouf_work"' EXIT

ouf_fetch() {
  local commit=$1 file=$2 expected=$3 destination="$ouf_work/$2"
  curl --fail --silent --show-error --max-time 30 --proto '=https' --tlsv1.2 \
    "$ouf_repo/$commit/scripts/$file" -o "$destination"
  printf '%s  %s\n' "$expected" "$destination" | sha256sum --check --status
}

ouf_fetch 799350fb4570a8b20fa54ec2d63b1126cba93f86 "$ouf_controller" "$ouf_controller_sha"
ouf_fetch 9b6c01122c826872fef21064a98c78a30acc8081 cutover-semantic-provider-20261111.py ec69f0d86d337596ad562078eee18f87189310bb08f44a4f2b3550122b0366d9
ouf_fetch 9b6c01122c826872fef21064a98c78a30acc8081 upgrade-semantic-application-20261108.py 2e7e7e42367b3329f6ebd441bba665f974ea43871049d863415524610138efb1

sudo /usr/bin/python3 -I -B - "$ouf_work/$ouf_controller" "$ouf_controller_sha" "$@" <<'PY'
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
