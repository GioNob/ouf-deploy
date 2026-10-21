#!/usr/bin/env bash
# Compile private current creation intent; no application or lease changes.
(
  set -euo pipefail
  umask 077
  OUF_DIR=not_created
  OUF_PHASE=DOWNLOAD_PINNED_CURRENT_CREATION_PLANNER
  trap 'OUF_CODE=$?; printf "OUF_CURRENT_CREATION_PLAN_EXIT=%s PHASE=%s OUTPUT=%s/result.txt\n" "$OUF_CODE" "$OUF_PHASE" "$OUF_DIR"' EXIT
  OUF_GH="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
  if [ ! -x "$OUF_GH" ]; then OUF_GH="$(command -v gh || true)"; fi
  if [ -z "$OUF_GH" ] || [ ! -x "$OUF_GH" ]; then echo "OUF_EXISTING_GITHUB_CLIENT_REQUIRED" >&2; exit 1; fi
  OUF_DIR="$(mktemp -d "$HOME/ouf-current-creation-plan.XXXXXXXX")"
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/scripts/compile-semantic-creation-plan-after-r12.py?ref=9fdf4bed6ded1a01640bcaed2ffadb58204e42d5' > "$OUF_DIR/plan.py"
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/scripts/prepare-semantic-inputs-after-r12.py?ref=9fdf4bed6ded1a01640bcaed2ffadb58204e42d5' > "$OUF_DIR/prepare.py"
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/tools/semantic_target_review/prepare_application_runtime_inputs.py?ref=9fdf4bed6ded1a01640bcaed2ffadb58204e42d5' > "$OUF_DIR/custody.py"
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/tools/semantic_application_cutover/creation_plan.py?ref=9fdf4bed6ded1a01640bcaed2ffadb58204e42d5' > "$OUF_DIR/creation.py"
  printf '%s  %s\n' '38bb934fedfcdd38d11fc29ff4d60e75170854686273b7592edcae92fa0d1d28' "$OUF_DIR/plan.py" | sha256sum -c -
  printf '%s  %s\n' '693ec0196a60d3a9f6adee96571947306df4a0cffb449905c3dcf8c09a34da1b' "$OUF_DIR/prepare.py" | sha256sum -c -
  printf '%s  %s\n' 'cb9ff64684243d563da79d327eb7d7e325dbea6a3922c91a0b7791a3ceec9baf' "$OUF_DIR/custody.py" | sha256sum -c -
  printf '%s  %s\n' 'e018567bbd67504ec00d5cbd830c65adbb2670dd7a627b63b9ae20ffa420d665' "$OUF_DIR/creation.py" | sha256sum -c -
  OUF_PHASE=COMPILE_CURRENT_PRIVATE_CREATION_INTENT_NO_APPLY
  sudo /usr/bin/python3 -I -B -c '
import hashlib,pathlib,sys
expected=["38bb934fedfcdd38d11fc29ff4d60e75170854686273b7592edcae92fa0d1d28","693ec0196a60d3a9f6adee96571947306df4a0cffb449905c3dcf8c09a34da1b","cb9ff64684243d563da79d327eb7d7e325dbea6a3922c91a0b7791a3ceec9baf","e018567bbd67504ec00d5cbd830c65adbb2670dd7a627b63b9ae20ffa420d665"]
if len(sys.argv)!=5:raise SystemExit("OUF_CURRENT_CREATION_EXACT_SOURCE_SET_REQUIRED")
sources=[]
for path,digest in zip(sys.argv[1:],expected):
    with pathlib.Path(path).open("rb") as stream:raw=stream.read(131073)
    if len(raw)>131072 or hashlib.sha256(raw).hexdigest()!=digest:raise SystemExit("OUF_CURRENT_CREATION_SOURCE_HASH_MISMATCH")
    sources.append(raw)
p=sys.argv[1];sys.argv=[p]
exec(compile(sources[0],p,"exec"),{"__name__":"__main__","__file__":p,"__planner_sources__":dict(zip(("prepare","custody","creation"),sources[1:]))})
' "$OUF_DIR/plan.py" "$OUF_DIR/prepare.py" "$OUF_DIR/custody.py" "$OUF_DIR/creation.py" | tee "$OUF_DIR/result.txt"
)

