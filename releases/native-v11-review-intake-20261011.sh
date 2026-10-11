#!/usr/bin/env bash
# Atomic publication of existing native V11 review files; no runtime authority.
(
  set -euo pipefail
  umask 077
  OUF_DIR=not_created
  OUF_PHASE=DOWNLOAD_EXACT_NATIVE_V11_REVIEW_INTAKE_CLOSURE
  trap 'OUF_CODE=$?; printf "OUF_NATIVE_V11_REVIEW_INTAKE_LAUNCHER_EXIT=%s PHASE=%s OUTPUT=%s/result.txt\n" "$OUF_CODE" "$OUF_PHASE" "$OUF_DIR"' EXIT
  OUF_GH="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
  if [ ! -x "$OUF_GH" ]; then OUF_GH="$(command -v gh || true)"; fi
  if [ -z "$OUF_GH" ] || [ ! -x "$OUF_GH" ]; then echo OUF_EXISTING_GITHUB_CLIENT_REQUIRED >&2; exit 1; fi
  OUF_DIR="$(mktemp -d "$HOME/ouf-native-v11-review-intake.XXXXXXXX")"
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/scripts/publish-native-v11-review-intake.py?ref=d4edb3286a13a6f1c0bd1fc04848a284f8fae933' > "$OUF_DIR/program.py"
  printf '%s  %s\n' '6ec32cdd81af7fd8e70b4dc2f876ecfabfd2772c1cd6fba70b8e9e4bafe9f666' "$OUF_DIR/program.py" | sha256sum -c -
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/tools/semantic_application_cutover/atomic_review_intake.py?ref=bdcf4594d152ea12d6b9b39b51e0d2533d83b7ef' > "$OUF_DIR/atomic.py"
  printf '%s  %s\n' 'c113f578b027c39573b4562cd3ac324abb8108a393b82dde19f8eb53d98e0ea6' "$OUF_DIR/atomic.py" | sha256sum -c -
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/tools/semantic_target_review/prepare_application_runtime_inputs.py?ref=9fdf4bed6ded1a01640bcaed2ffadb58204e42d5' > "$OUF_DIR/custody.py"
  printf '%s  %s\n' 'cb9ff64684243d563da79d327eb7d7e325dbea6a3922c91a0b7791a3ceec9baf' "$OUF_DIR/custody.py" | sha256sum -c -
  OUF_PHASE=PUBLISH_COMPLETE_PRIVATE_REVIEW_ATOMICALLY_NO_APPLICATION_APPLY
  sudo /usr/bin/python3 -I -B -c '
import hashlib,os,stat,sys
expected=["6ec32cdd81af7fd8e70b4dc2f876ecfabfd2772c1cd6fba70b8e9e4bafe9f666", "c113f578b027c39573b4562cd3ac324abb8108a393b82dde19f8eb53d98e0ea6", "cb9ff64684243d563da79d327eb7d7e325dbea6a3922c91a0b7791a3ceec9baf"]
if len(sys.argv)!=4:raise SystemExit("OUF_NATIVE_REVIEW_INTAKE_EXACT_SOURCE_SET_REQUIRED")
sources=[]
for path,digest in zip(sys.argv[1:],expected):
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW),"rb") as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1:raise SystemExit("OUF_NATIVE_REVIEW_INTAKE_REGULAR_SOURCE_REQUIRED")
        raw=stream.read(131073)
    if len(raw)>131072 or hashlib.sha256(raw).hexdigest()!=digest:raise SystemExit("OUF_NATIVE_REVIEW_INTAKE_SOURCE_HASH_MISMATCH")
    sources.append(raw)
path=sys.argv[1];sys.argv=[path]
exec(compile(sources[0],path,"exec"),{"__name__":"__main__","__file__":path,"__sealed_program_sha__":expected[0],"__intake_sources__":dict(zip(("atomic","custody"),sources[1:]))})
' "$OUF_DIR/program.py" "$OUF_DIR/atomic.py" "$OUF_DIR/custody.py" | tee "$OUF_DIR/result.txt"
)
