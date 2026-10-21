#!/usr/bin/env bash
# Retry-safe protected metadata intake; no keys, services, lease lock or apply.
(
  set -euo pipefail
  umask 077
  OUF_BINDINGS_DIR=not_created
  OUF_PHASE=DOWNLOAD_PINNED_PROTECTED_METADATA_READER
  trap 'OUF_CODE=$?; printf "OUF_PROTECTED_BINDINGS_EXIT=%s PHASE=%s OUTPUT=%s/result.txt\n" "$OUF_CODE" "$OUF_PHASE" "$OUF_BINDINGS_DIR"' EXIT
  OUF_GH="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
  if [ ! -x "$OUF_GH" ]; then OUF_GH="$(command -v gh)"; fi
  OUF_BINDINGS_DIR="$(mktemp -d "$HOME/ouf-protected-bindings.XXXXXXXX")"
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' "repos/GioNob/ouf-deploy/contents/scripts/read-replacement-protected-bindings.py?ref=2c7787647ebacc614d3041c86fd1eb58e3b55f23" > "$OUF_BINDINGS_DIR/read.py"
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' "repos/GioNob/ouf-deploy/contents/tools/semantic_target_review/prepare_application_runtime_inputs.py?ref=2c7787647ebacc614d3041c86fd1eb58e3b55f23" > "$OUF_BINDINGS_DIR/custody.py"
  printf '%s  %s\n' 'e4e5458b5e7adbe2bfc4885496220030886902cbb751b7f921ae0fac8c9dbb5c' "$OUF_BINDINGS_DIR/read.py" 'cb9ff64684243d563da79d327eb7d7e325dbea6a3922c91a0b7791a3ceec9baf' "$OUF_BINDINGS_DIR/custody.py" | sha256sum -c -
  OUF_PHASE=READ_PROTECTED_METADATA_NO_KEYS_NO_LOCK_NO_APPLY
  sudo /usr/bin/python3 -I -B -c '
import hashlib,pathlib,sys
expected=("e4e5458b5e7adbe2bfc4885496220030886902cbb751b7f921ae0fac8c9dbb5c","cb9ff64684243d563da79d327eb7d7e325dbea6a3922c91a0b7791a3ceec9baf")
if len(sys.argv)!=3:raise SystemExit("OUF_BINDINGS_EXACT_SOURCE_SET_REQUIRED")
sources=[]
for path,digest in zip(sys.argv[1:],expected):
    with pathlib.Path(path).open("rb") as stream:raw=stream.read(131073)
    if len(raw)>131072 or hashlib.sha256(raw).hexdigest()!=digest:raise SystemExit("OUF_BINDINGS_SOURCE_HASH_MISMATCH")
    sources.append(raw)
p=sys.argv[1];sys.argv=[p]
exec(compile(sources[0],p,"exec"),{"__name__":"__main__","__file__":p,"__custody_source__":sources[1]})
' "$OUF_BINDINGS_DIR/read.py" "$OUF_BINDINGS_DIR/custody.py" | tee "$OUF_BINDINGS_DIR/result.txt"
)
