#!/usr/bin/env bash
# Compile a new private V11 declaration/request for review; no target apply.
(
  set -euo pipefail
  umask 077
  OUF_DIR=not_created
  OUF_PHASE=DOWNLOAD_EXACT_V11_PLAN_CLOSURE
  trap 'OUF_CODE=$?; printf "OUF_CURRENT_V11_PLAN_LAUNCHER_EXIT=%s PHASE=%s OUTPUT=%s/result.txt\n" "$OUF_CODE" "$OUF_PHASE" "$OUF_DIR"' EXIT
  OUF_GH="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
  if [ ! -x "$OUF_GH" ]; then OUF_GH="$(command -v gh || true)"; fi
  if [ -z "$OUF_GH" ] || [ ! -x "$OUF_GH" ]; then echo OUF_EXISTING_GITHUB_CLIENT_REQUIRED >&2; exit 1; fi
  OUF_DIR="$(mktemp -d "$HOME/ouf-current-v11-plan.XXXXXXXX")"
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/scripts/prepare-current-durable-v11-plan.py?ref=6b847ef56b31118af45667b6e3137fd1336d4683' > "$OUF_DIR/program.py"
  printf '%s  %s\n' '7a0e92954684abe12320a0fc56391a5e869e78eb92dbe5f5d0958620bb7bf4e3' "$OUF_DIR/program.py" | sha256sum -c -
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/scripts/read-current-r12-cutover-custody.py?ref=3ed7815b8164ffab212b44318fb8fbd213256fcc' > "$OUF_DIR/reader.py"
  printf '%s  %s\n' '4d4da44d8ef27f77e00982d978ad8400eb7a0b79997bd468535fc49654b2ac3f' "$OUF_DIR/reader.py" | sha256sum -c -
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/scripts/compile-semantic-creation-plan-after-r12.py?ref=9fdf4bed6ded1a01640bcaed2ffadb58204e42d5' > "$OUF_DIR/planner.py"
  printf '%s  %s\n' '38bb934fedfcdd38d11fc29ff4d60e75170854686273b7592edcae92fa0d1d28' "$OUF_DIR/planner.py" | sha256sum -c -
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/scripts/prepare-semantic-inputs-after-r12.py?ref=9fdf4bed6ded1a01640bcaed2ffadb58204e42d5' > "$OUF_DIR/prepare.py"
  printf '%s  %s\n' '693ec0196a60d3a9f6adee96571947306df4a0cffb449905c3dcf8c09a34da1b' "$OUF_DIR/prepare.py" | sha256sum -c -
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/tools/semantic_target_review/prepare_application_runtime_inputs.py?ref=9fdf4bed6ded1a01640bcaed2ffadb58204e42d5' > "$OUF_DIR/custody.py"
  printf '%s  %s\n' 'cb9ff64684243d563da79d327eb7d7e325dbea6a3922c91a0b7791a3ceec9baf' "$OUF_DIR/custody.py" | sha256sum -c -
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/tools/semantic_application_cutover/creation_plan.py?ref=9fdf4bed6ded1a01640bcaed2ffadb58204e42d5' > "$OUF_DIR/creation.py"
  printf '%s  %s\n' 'e018567bbd67504ec00d5cbd830c65adbb2670dd7a627b63b9ae20ffa420d665' "$OUF_DIR/creation.py" | sha256sum -c -
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/scripts/rebase-semantic-package-declaration.py?ref=37ff0eebcc5e100877f357ba791fe662b2deb508' > "$OUF_DIR/package.py"
  printf '%s  %s\n' '134a31a840373938c3e65cb9d80f588fe8006b472dfb9582ff3bb024733842ed' "$OUF_DIR/package.py" | sha256sum -c -
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/tools/semantic_application_cutover/rebase_verified_package.py?ref=6b847ef56b31118af45667b6e3137fd1336d4683' > "$OUF_DIR/rebind.py"
  printf '%s  %s\n' '9ac4fa362db432b4a4d3e6febc016d0d827934d300c23ebd60e6273364ada486' "$OUF_DIR/rebind.py" | sha256sum -c -
  OUF_PHASE=PREPARE_CURRENT_PRIVATE_V11_PLAN_NO_APPLY
  sudo /usr/bin/python3 -I -B -c '
import hashlib,os,pathlib,stat,sys
expected=["7a0e92954684abe12320a0fc56391a5e869e78eb92dbe5f5d0958620bb7bf4e3","4d4da44d8ef27f77e00982d978ad8400eb7a0b79997bd468535fc49654b2ac3f","38bb934fedfcdd38d11fc29ff4d60e75170854686273b7592edcae92fa0d1d28","693ec0196a60d3a9f6adee96571947306df4a0cffb449905c3dcf8c09a34da1b","cb9ff64684243d563da79d327eb7d7e325dbea6a3922c91a0b7791a3ceec9baf","e018567bbd67504ec00d5cbd830c65adbb2670dd7a627b63b9ae20ffa420d665","134a31a840373938c3e65cb9d80f588fe8006b472dfb9582ff3bb024733842ed","9ac4fa362db432b4a4d3e6febc016d0d827934d300c23ebd60e6273364ada486"]
if len(sys.argv)!=9:raise SystemExit("OUF_CURRENT_V11_EXACT_SOURCE_SET_REQUIRED")
sources=[]
for path,digest in zip(sys.argv[1:],expected):
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW),"rb") as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1:raise SystemExit("OUF_CURRENT_V11_REGULAR_SOURCE_REQUIRED")
        raw=stream.read(131073)
    if len(raw)>131072 or hashlib.sha256(raw).hexdigest()!=digest:raise SystemExit("OUF_CURRENT_V11_SOURCE_HASH_MISMATCH")
    sources.append(raw)
path=sys.argv[1];sys.argv=[path]
exec(compile(sources[0],path,"exec"),{"__name__":"__main__","__file__":path,"__v11_plan_sources__":dict(zip(("reader","planner","prepare","custody","creation","package","rebind"),sources[1:]))})
' "$OUF_DIR/program.py" "$OUF_DIR/reader.py" "$OUF_DIR/planner.py" "$OUF_DIR/prepare.py" "$OUF_DIR/custody.py" "$OUF_DIR/creation.py" "$OUF_DIR/package.py" "$OUF_DIR/rebind.py" | tee "$OUF_DIR/result.txt"
)
