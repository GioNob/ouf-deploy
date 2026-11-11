#!/usr/bin/env bash
set -euo pipefail
umask 077

controller='prepare-semantic-provider-installation.py'
controller_sha='9255dbf738e11a25a92fd29eb0a460965af7cbf7eeec32ba39b7459cfbfca444'
source_root='https://raw.githubusercontent.com/GioNob/ouf-deploy/692a0595375e740ba1db16c463c3c06180a92282/scripts'
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
