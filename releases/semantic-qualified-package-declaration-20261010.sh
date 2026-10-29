#!/usr/bin/env bash
# Compile private review evidence; no lease lock, Docker, credentials or apply.
(
  set -euo pipefail
  umask 077
  OUF_DIR=not_created
  OUF_PHASE=DOWNLOAD_PINNED_PACKAGE_DECLARATION_COMPILER
  trap 'OUF_CODE=$?; printf "OUF_PACKAGE_DECLARATION_EXIT=%s PHASE=%s OUTPUT=%s/result.txt\n" "$OUF_CODE" "$OUF_PHASE" "$OUF_DIR"' EXIT
  OUF_GH="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
  if [ ! -x "$OUF_GH" ]; then OUF_GH="$(command -v gh)"; fi
  OUF_DIR="$(mktemp -d "$HOME/ouf-package-declaration.XXXXXXXX")"
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' "repos/GioNob/ouf-deploy/contents/scripts/rebase-semantic-package-declaration.py?ref=eee3a3c240df53c30fd25fdb8c77f469c3f63fd7" > "$OUF_DIR/read.py"
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' "repos/GioNob/ouf-deploy/contents/tools/semantic_target_review/prepare_application_runtime_inputs.py?ref=eee3a3c240df53c30fd25fdb8c77f469c3f63fd7" > "$OUF_DIR/custody.py"
  printf '%s  %s\n' '134a31a840373938c3e65cb9d80f588fe8006b472dfb9582ff3bb024733842ed' "$OUF_DIR/read.py" 'cb9ff64684243d563da79d327eb7d7e325dbea6a3922c91a0b7791a3ceec9baf' "$OUF_DIR/custody.py" | sha256sum -c -
  OUF_PHASE=COMPILE_QUALIFIED_PACKAGE_INTENT_NO_APPLY
  sudo /usr/bin/python3 -I -B -c '
import hashlib,pathlib,sys
expected=("134a31a840373938c3e65cb9d80f588fe8006b472dfb9582ff3bb024733842ed","cb9ff64684243d563da79d327eb7d7e325dbea6a3922c91a0b7791a3ceec9baf")
if len(sys.argv)!=3:raise SystemExit("OUF_PACKAGE_DECLARATION_EXACT_SOURCE_SET_REQUIRED")
sources=[]
for path,digest in zip(sys.argv[1:],expected):
    with pathlib.Path(path).open("rb") as stream:raw=stream.read(131073)
    if len(raw)>131072 or hashlib.sha256(raw).hexdigest()!=digest:raise SystemExit("OUF_PACKAGE_DECLARATION_SOURCE_HASH_MISMATCH")
    sources.append(raw)
p=sys.argv[1];sys.argv=[p]
exec(compile(sources[0],p,"exec"),{"__name__":"__main__","__file__":p,"__custody_source__":sources[1]})
' "$OUF_DIR/read.py" "$OUF_DIR/custody.py" | tee "$OUF_DIR/result.txt"
)
