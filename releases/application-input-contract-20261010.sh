#!/usr/bin/env bash
# Retry-safe application input contract only; no mounts or cutover.
(
  set -euo pipefail
  umask 077
  OUF_CONTRACT_DIR=not_created
  OUF_PHASE=DOWNLOAD_PINNED_CONTRACT_COMPILER
  trap 'OUF_CODE=$?; printf "OUF_APPLICATION_CONTRACT_EXIT=%s PHASE=%s OUTPUT=%s/result.txt\n" "$OUF_CODE" "$OUF_PHASE" "$OUF_CONTRACT_DIR"' EXIT
  OUF_GH="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
  if [ ! -x "$OUF_GH" ]; then OUF_GH="$(command -v gh)"; fi
  OUF_CONTRACT_DIR="$(mktemp -d "$HOME/ouf-application-contract.XXXXXXXX")"
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' "repos/GioNob/ouf-deploy/contents/scripts/compile-replacement-application-contract.py?ref=88eb054043483a30b54b74ad0af8a2b55091cfe9" > "$OUF_CONTRACT_DIR/compile.py"
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' "repos/GioNob/ouf-deploy/contents/tools/semantic_target_review/prepare_application_runtime_inputs.py?ref=88eb054043483a30b54b74ad0af8a2b55091cfe9" > "$OUF_CONTRACT_DIR/custody.py"
  printf '%s  %s\n' '225f6226c0af22185be87a3f9c4c711b941c38cfdcdeab86ca5ec729583a9961' "$OUF_CONTRACT_DIR/compile.py" 'cb9ff64684243d563da79d327eb7d7e325dbea6a3922c91a0b7791a3ceec9baf' "$OUF_CONTRACT_DIR/custody.py" | sha256sum -c -
  OUF_PHASE=PREPARE_FROZEN_APPLICATION_CONTRACT_NO_MOUNTS_NO_APPLY
  sudo /usr/bin/python3 -I -B -c '
import hashlib,pathlib,sys
expected=("225f6226c0af22185be87a3f9c4c711b941c38cfdcdeab86ca5ec729583a9961","cb9ff64684243d563da79d327eb7d7e325dbea6a3922c91a0b7791a3ceec9baf")
if len(sys.argv)!=3:raise SystemExit("OUF_CONTRACT_EXACT_SOURCE_SET_REQUIRED")
sources=[]
for path,digest in zip(sys.argv[1:],expected):
    with pathlib.Path(path).open("rb") as stream:raw=stream.read(131073)
    if len(raw)>131072 or hashlib.sha256(raw).hexdigest()!=digest:raise SystemExit("OUF_CONTRACT_SOURCE_HASH_MISMATCH")
    sources.append(raw)
p=sys.argv[1];sys.argv=[p]
exec(compile(sources[0],p,"exec"),{"__name__":"__main__","__file__":p,"__custody_source__":sources[1]})
' "$OUF_CONTRACT_DIR/compile.py" "$OUF_CONTRACT_DIR/custody.py" | tee "$OUF_CONTRACT_DIR/result.txt"
)
