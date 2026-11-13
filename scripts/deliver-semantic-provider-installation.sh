#!/usr/bin/env bash
set -euo pipefail
umask 077

controller='prepare-semantic-provider-installation.py'
controller_sha='b65d2bb79c9c43052adc2bcfa578a1dc622f96c229fb558805f316657935e955'
source_root='https://raw.githubusercontent.com/GioNob/ouf-deploy/17ffb7f41fb7b7201230ed83315becde3f29ed6f/scripts'
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
