#!/usr/bin/env bash
# Private gated plan and retained metadata only. No application apply.
(
  set -euo pipefail
  umask 077
  OUF_DIR=not_created
  OUF_PHASE=DOWNLOAD_SEALED_GATED_PRIVATE_PLANNER
  trap 'OUF_CODE=$?; printf "OUF_GATED_V11_PLAN_LAUNCHER_EXIT=%s PHASE=%s OUTPUT=%s/result.txt\n" "$OUF_CODE" "$OUF_PHASE" "$OUF_DIR"' EXIT
  OUF_GH="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
  if [ ! -x "$OUF_GH" ]; then OUF_GH="$(command -v gh || true)"; fi
  if [ -z "$OUF_GH" ] || [ ! -x "$OUF_GH" ]; then echo OUF_EXISTING_GITHUB_CLIENT_REQUIRED >&2; exit 1; fi
  OUF_DIR="$(mktemp -d "$HOME/ouf-gated-v11-private-plan.XXXXXXXX")"
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/scripts/prepare-gated-v11-private-plan.py?ref=ae597c3f63c965258c0f74bb66dee5cd20aa1bba' > "$OUF_DIR/program.py"
  printf '%s  %s\n' '11e702a5a8c6162b86ee67503bb85ba708b0142ac8e2bd21d4db66d3653286ac' "$OUF_DIR/program.py" | sha256sum -c -
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/tools/semantic_application_cutover/atomic_review_intake.py?ref=bdcf4594d152ea12d6b9b39b51e0d2533d83b7ef' > "$OUF_DIR/atomic.py"
  printf '%s  %s\n' 'c113f578b027c39573b4562cd3ac324abb8108a393b82dde19f8eb53d98e0ea6' "$OUF_DIR/atomic.py" | sha256sum -c -
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/scripts/publish-native-v11-review-intake.py?ref=d4edb3286a13a6f1c0bd1fc04848a284f8fae933' > "$OUF_DIR/publisher.py"
  printf '%s  %s\n' '6ec32cdd81af7fd8e70b4dc2f876ecfabfd2772c1cd6fba70b8e9e4bafe9f666' "$OUF_DIR/publisher.py" | sha256sum -c -
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/tools/semantic_application_cutover/transition_journal.py?ref=26a80fcb2f0f31f98cd2814621633bbf795635a6' > "$OUF_DIR/journal.py"
  printf '%s  %s\n' 'bda7f2c0e7689856d0257b9b3a9b2a938b6962dbacbeb10cc1bbf7eaef905155' "$OUF_DIR/journal.py" | sha256sum -c -
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/tools/semantic_application_cutover/gated_creation_plan.py?ref=26a80fcb2f0f31f98cd2814621633bbf795635a6' > "$OUF_DIR/gate.py"
  printf '%s  %s\n' 'a4e13489d52697117246f979c42a2df766d19f67c7a99e0922c3bb4ac6b45c44' "$OUF_DIR/gate.py" | sha256sum -c -
  OUF_PHASE=PREPARE_PRIVATE_GATE_AND_RETAINED_MOUNT_METADATA_NO_APPLY
  sudo /usr/bin/python3 -I -B -c '
import hashlib,os,stat,sys
expected=["11e702a5a8c6162b86ee67503bb85ba708b0142ac8e2bd21d4db66d3653286ac","c113f578b027c39573b4562cd3ac324abb8108a393b82dde19f8eb53d98e0ea6","6ec32cdd81af7fd8e70b4dc2f876ecfabfd2772c1cd6fba70b8e9e4bafe9f666","bda7f2c0e7689856d0257b9b3a9b2a938b6962dbacbeb10cc1bbf7eaef905155","a4e13489d52697117246f979c42a2df766d19f67c7a99e0922c3bb4ac6b45c44"]
if len(sys.argv)!=6:raise SystemExit("OUF_GATED_PLAN_EXACT_SOURCE_SET_REQUIRED")
sources=[]
identity=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
for path,digest in zip(sys.argv[1:],expected):
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),"rb") as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1:raise SystemExit("OUF_GATED_PLAN_REGULAR_SOURCE_REQUIRED")
        raw=stream.read(131073)
        if identity(info)!=identity(os.fstat(stream.fileno())) or identity(info)!=identity(os.lstat(path)):raise SystemExit("OUF_GATED_PLAN_SOURCE_CHANGED")
    if len(raw)>131072 or hashlib.sha256(raw).hexdigest()!=digest:raise SystemExit("OUF_GATED_PLAN_SOURCE_HASH_MISMATCH")
    sources.append(raw)
path=sys.argv[1];sys.argv=[path]
exec(compile(sources[0],path,"exec"),{"__name__":"__main__","__file__":path,"__sealed_program_sha__":expected[0],"__gated_sources__":dict(zip(("atomic","publisher","journal","gate"),sources[1:]))})
' "$OUF_DIR/program.py" "$OUF_DIR/atomic.py" "$OUF_DIR/publisher.py" "$OUF_DIR/journal.py" "$OUF_DIR/gate.py" | tee "$OUF_DIR/result.txt"
)
