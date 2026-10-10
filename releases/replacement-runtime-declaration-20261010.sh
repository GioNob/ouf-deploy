#!/usr/bin/env bash
# Retry-safe historical runtime declaration; no keys, Docker, lease lock or apply.
(
  set -euo pipefail
  umask 077
  OUF_DECLARATION_DIR=not_created
  OUF_PHASE=DOWNLOAD_PINNED_RUNTIME_DECLARATION_COMPILER
  trap 'OUF_CODE=$?; printf "OUF_RUNTIME_DECLARATION_EXIT=%s PHASE=%s OUTPUT=%s/result.txt\n" "$OUF_CODE" "$OUF_PHASE" "$OUF_DECLARATION_DIR"' EXIT
  OUF_GH="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
  if [ ! -x "$OUF_GH" ]; then OUF_GH="$(command -v gh)"; fi
  OUF_DECLARATION_DIR="$(mktemp -d "$HOME/ouf-runtime-declaration.XXXXXXXX")"
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' "repos/GioNob/ouf-deploy/contents/scripts/compile-replacement-runtime-declaration.py?ref=c80b7584a1b7f403c3ecf113c2c4debad1de405e" > "$OUF_DECLARATION_DIR/read.py"
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' "repos/GioNob/ouf-deploy/contents/tools/semantic_target_review/prepare_application_runtime_inputs.py?ref=c80b7584a1b7f403c3ecf113c2c4debad1de405e" > "$OUF_DECLARATION_DIR/custody.py"
  printf '%s  %s\n' 'ed099ee6e67ee7e15a0c4ebf4325c69a64d6de66b6c2bfa0377720b02cecad7e' "$OUF_DECLARATION_DIR/read.py" 'cb9ff64684243d563da79d327eb7d7e325dbea6a3922c91a0b7791a3ceec9baf' "$OUF_DECLARATION_DIR/custody.py" | sha256sum -c -
  OUF_PHASE=DECLARE_RETAINED_HOST_INTENT_NO_KEYS_NO_DOCKER_NO_APPLY
  sudo /usr/bin/python3 -I -B -c '
import hashlib,pathlib,sys
expected=("ed099ee6e67ee7e15a0c4ebf4325c69a64d6de66b6c2bfa0377720b02cecad7e","cb9ff64684243d563da79d327eb7d7e325dbea6a3922c91a0b7791a3ceec9baf")
if len(sys.argv)!=3:raise SystemExit("OUF_DECLARATION_EXACT_SOURCE_SET_REQUIRED")
sources=[]
for path,digest in zip(sys.argv[1:],expected):
    with pathlib.Path(path).open("rb") as stream:raw=stream.read(131073)
    if len(raw)>131072 or hashlib.sha256(raw).hexdigest()!=digest:raise SystemExit("OUF_DECLARATION_SOURCE_HASH_MISMATCH")
    sources.append(raw)
p=sys.argv[1];sys.argv=[p]
exec(compile(sources[0],p,"exec"),{"__name__":"__main__","__file__":p,"__custody_source__":sources[1]})
' "$OUF_DECLARATION_DIR/read.py" "$OUF_DECLARATION_DIR/custody.py" | tee "$OUF_DECLARATION_DIR/result.txt"
)

