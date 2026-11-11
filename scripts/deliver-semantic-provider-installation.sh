#!/usr/bin/env bash
set -euo pipefail
umask 077

controller='prepare-semantic-provider-installation.py'
controller_sha='9e0617f80e16d2dd28e5d2a82931a608d0cd55d0eceababc0faa39b5ab49cb66'
source_root='https://raw.githubusercontent.com/GioNob/ouf-deploy/f846940c7d01c997fedc0972f3a54389befffbef/scripts'
work=$(mktemp -d "${TMPDIR:-/tmp}/ouf-semantic-installation-p.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT

curl --fail --silent --show-error --max-time 30 --proto '=https' --tlsv1.2 \
  "$source_root/$controller" -o "$work/$controller"
printf '%s  %s\n' "$controller_sha" "$work/$controller" | sha256sum --check --status

sudo /usr/bin/python3 -I -B - "$work/$controller" "$controller_sha" "$@" <<'PY'
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
