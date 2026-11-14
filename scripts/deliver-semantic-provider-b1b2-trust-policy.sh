#!/usr/bin/env bash
set -euo pipefail
umask 077

# Claude replaces all three pins after review and commit; never use a branch URL.
commit='fa81424bf208d0f10f754eda2cc0f4ffa96941a8'
controller_sha='2b6f2c1d164e98bfc797031a44de70b0d25f33a3b68486fa81af14d2ed3321bb'
authority_sha='04510e275622cde812da86599e5a191a0f7575650b32aa3208d1b6d47768c728'
[[ "$commit" =~ ^[0-9a-f]{40}$ && "$controller_sha" =~ ^[0-9a-f]{64}$ && "$authority_sha" =~ ^[0-9a-f]{64}$ ]] || {
  printf '%s\n' 'B1B2_SOURCE_PINS_REQUIRED' >&2
  exit 1
}
source_root="https://raw.githubusercontent.com/GioNob/ouf-deploy/$commit"
work=$(mktemp -d "${TMPDIR:-/tmp}/ouf-semantic-b1b2.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
controller='prepare-semantic-provider-b1b2-trust-policy.py'
curl --fail --silent --show-error --max-time 30 --proto '=https' --tlsv1.2 \
  "$source_root/scripts/$controller" -o "$work/$controller"
curl --fail --silent --show-error --max-time 30 --proto '=https' --tlsv1.2 \
  "$source_root/tools/semantic_b1b2_authority/authority.py" -o "$work/authority.py"
printf '%s  %s\n' "$controller_sha" "$work/$controller" "$authority_sha" "$work/authority.py" | sha256sum --check --status

sudo /usr/bin/python3 -I -B - "$work/$controller" "$controller_sha" "$work/authority.py" "$authority_sha" "$@" <<'PY'
import hashlib
from pathlib import Path
import sys
import types

controller, controller_pin, authority, authority_pin, *args = sys.argv[1:]
sources = []
for path, expected in ((controller, controller_pin), (authority, authority_pin)):
    raw = Path(path).read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected:
        raise SystemExit("B1B2_SOURCE_CHANGED")
    sources.append(raw)
# Execute only the bytes checked in the privileged interpreter. No later import
# reopens the downloaded module, and no ambient PYTHONPATH participates.
module = types.ModuleType("_ouf_semantic_b1b2_authority")
module.__file__ = authority
exec(compile(sources[1], authority, "exec"), module.__dict__)
sys.modules[module.__name__] = module
sys.argv = [controller, *args]
exec(compile(sources[0], controller, "exec"), {"__name__": "__main__", "__file__": controller})
PY
