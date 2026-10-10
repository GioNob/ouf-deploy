#!/usr/bin/env bash
# One-use private runtime inputs only; no application/lease cutover or restart.
(
  set -euo pipefail
  umask 077
  OUF_PHASE=DOWNLOAD_PINNED_APPLICATION_INPUTS
  OUF_INPUT_DIR=not_created
  trap 'OUF_CODE=$?; printf "OUF_APPLICATION_INPUTS_EXIT=%s PHASE=%s OUTPUT=%s/result.txt\n" "$OUF_CODE" "$OUF_PHASE" "$OUF_INPUT_DIR"' EXIT
  OUF_GH="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
  if [ ! -x "$OUF_GH" ]; then OUF_GH="$(command -v gh || true)"; fi
  if [ -z "$OUF_GH" ] || [ ! -x "$OUF_GH" ]; then printf 'OUF_APPLICATION_INPUTS_DELIVERY=EXISTING_GH_NOT_FOUND\n'; exit 1; fi
  OUF_INPUT_DIR="$(mktemp -d "$HOME/ouf-application-inputs.XXXXXXXX")"
  for OUF_NAME in prepare_application_runtime_inputs.py read_cutover_inputs.py; do
    "$OUF_GH" api -H 'Accept: application/vnd.github.raw' "repos/GioNob/ouf-deploy/contents/tools/semantic_target_review/$OUF_NAME?ref=b71638367b3cb2b48ce3e65933078b51feb2f85c" > "$OUF_INPUT_DIR/$OUF_NAME"
  done
  printf '%s  %s\n' 'cb9ff64684243d563da79d327eb7d7e325dbea6a3922c91a0b7791a3ceec9baf' "$OUF_INPUT_DIR/prepare_application_runtime_inputs.py" 'b9ea8aa1a8cf31d28dfa1df0960dcf6930880d11244fe1f84e710bfe0b9ec4cf' "$OUF_INPUT_DIR/read_cutover_inputs.py" | sha256sum -c -
  OUF_PHASE=PREPARE_ROLE_OWNED_INPUTS_ONCE_NO_MOUNTS_NO_SERVICES
  sudo /usr/bin/python3 -I -B -c '

import hashlib,pathlib,sys
if len(sys.argv)!=3:raise SystemExit("OUF_APPLICATION_INPUT_DELIVERY_EXACT_PAIR_REQUIRED")
sources=[]
for path,expected in zip(sys.argv[1:],("cb9ff64684243d563da79d327eb7d7e325dbea6a3922c91a0b7791a3ceec9baf","b9ea8aa1a8cf31d28dfa1df0960dcf6930880d11244fe1f84e710bfe0b9ec4cf")):
    with pathlib.Path(path).open("rb") as stream:raw=stream.read(131073)
    if len(raw)>131072 or hashlib.sha256(raw).hexdigest()!=expected:raise SystemExit("OUF_APPLICATION_INPUT_DELIVERY_HASH_MISMATCH")
    sources.append(raw)
if len(sources)!=2:raise SystemExit("OUF_R9_READ_EXACT_SOURCE_PAIR_REQUIRED")
p=sys.argv[1];sys.argv=[p]
exec(compile(sources[0],p,"exec"),{"__name__":"__main__","__file__":p,"__reader_source_bytes__":sources[1]})

' "$OUF_INPUT_DIR/prepare_application_runtime_inputs.py" "$OUF_INPUT_DIR/read_cutover_inputs.py" | tee "$OUF_INPUT_DIR/result.txt"
)
