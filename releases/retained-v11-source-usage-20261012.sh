#!/usr/bin/env bash
# Read-only retained metadata diagnosis. No source bytes, private writes or apply.
(
  set -euo pipefail
  umask 077
  OUF_DIR=not_created
  OUF_PHASE=DOWNLOAD_SEALED_RETAINED_SOURCE_USAGE
  trap 'OUF_CODE=$?; printf "OUF_RETAINED_V11_SOURCE_USAGE_EXIT=%s PHASE=%s OUTPUT=%s/result.txt\n" "$OUF_CODE" "$OUF_PHASE" "$OUF_DIR"' EXIT
  OUF_GH="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
  if [ ! -x "$OUF_GH" ]; then OUF_GH="$(command -v gh || true)"; fi
  if [ -z "$OUF_GH" ] || [ ! -x "$OUF_GH" ]; then echo OUF_EXISTING_GITHUB_CLIENT_REQUIRED >&2; exit 1; fi
  OUF_DIR="$(mktemp -d "$HOME/ouf-retained-v11-source-usage.XXXXXXXX")"
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/scripts/read-retained-v11-source-usage.py?ref=8bfb64d163d3bcdc2a9afe42e8d7b309ee1cd424' > "$OUF_DIR/program.py"
  printf '%s  %s\n' '7afa2cba1c8892707c5eba2e76615863e1155fa0ea7f59d7421dde4b21b04916' "$OUF_DIR/program.py" | sha256sum -c -
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/scripts/prepare-retained-v11-source-expectations.py?ref=58f8235cbecf5b41f538c0df1158d43ff5c2b23f' > "$OUF_DIR/planner.py"
  printf '%s  %s\n' 'c89caa119ef7c4fea07ac6a65dd5d2b173c144cf6a802e646929418acc859d56' "$OUF_DIR/planner.py" | sha256sum -c -
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/tools/semantic_application_cutover/atomic_review_intake.py?ref=bdcf4594d152ea12d6b9b39b51e0d2533d83b7ef' > "$OUF_DIR/atomic.py"
  printf '%s  %s\n' 'c113f578b027c39573b4562cd3ac324abb8108a393b82dde19f8eb53d98e0ea6' "$OUF_DIR/atomic.py" | sha256sum -c -
  OUF_PHASE=READ_ONLY_RETAINED_SOURCE_USAGE_NO_REFRESH
  sudo /usr/bin/python3 -I -B -c '
import hashlib,os,stat,sys
expected=["7afa2cba1c8892707c5eba2e76615863e1155fa0ea7f59d7421dde4b21b04916","c89caa119ef7c4fea07ac6a65dd5d2b173c144cf6a802e646929418acc859d56","c113f578b027c39573b4562cd3ac324abb8108a393b82dde19f8eb53d98e0ea6"]
if len(sys.argv)!=4:raise SystemExit("OUF_SOURCE_USAGE_EXACT_SOURCE_SET_REQUIRED")
identity=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
sources=[]
for path,digest in zip(sys.argv[1:],expected):
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),"rb") as stream:
        before=os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1:raise SystemExit("OUF_SOURCE_USAGE_REGULAR_SOURCE_REQUIRED")
        raw=stream.read(131073)
        if identity(before)!=identity(os.fstat(stream.fileno())) or identity(before)!=identity(os.lstat(path)):raise SystemExit("OUF_SOURCE_USAGE_SOURCE_CHANGED")
    if len(raw)>131072 or hashlib.sha256(raw).hexdigest()!=digest:raise SystemExit("OUF_SOURCE_USAGE_SOURCE_HASH_MISMATCH")
    sources.append(raw)
path=sys.argv[1];sys.argv=[path]
exec(compile(sources[0],path,"exec"),{"__name__":"__main__","__file__":path,"__planner_source__":sources[1],"__atomic_source__":sources[2]})
' "$OUF_DIR/program.py" "$OUF_DIR/planner.py" "$OUF_DIR/atomic.py" | tee "$OUF_DIR/result.txt"
)
