#!/usr/bin/env bash
# Read-only R12 readiness, reason and retained budget; no recovery or apply.
(
  set -euo pipefail
  umask 077
  OUF_DIR=not_created
  OUF_PHASE=DOWNLOAD_EXACT_R12_READINESS_DIAGNOSIS_CLOSURE
  trap 'OUF_CODE=$?; printf "OUF_R12_READINESS_DIAGNOSIS_LAUNCHER_EXIT=%s PHASE=%s OUTPUT=%s/result.txt\n" "$OUF_CODE" "$OUF_PHASE" "$OUF_DIR"' EXIT
  OUF_GH="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
  if [ ! -x "$OUF_GH" ]; then OUF_GH="$(command -v gh || true)"; fi
  if [ -z "$OUF_GH" ] || [ ! -x "$OUF_GH" ]; then echo OUF_EXISTING_GITHUB_CLIENT_REQUIRED >&2; exit 1; fi
  OUF_DIR="$(mktemp -d "$HOME/ouf-r12-readiness-diagnosis.XXXXXXXX")"
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/scripts/read-r12-readiness-diagnosis.py?ref=57296c0eb1a8cb5c8bfc371a1bf201a39763f94a' > "$OUF_DIR/program.py"
  printf '%s  %s\n' 'd52fa8752dd9d37c3d950c9781ec00be1f9d8a173325049ce7eb43ceff1a607e' "$OUF_DIR/program.py" | sha256sum -c -
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/scripts/prepare-semantic-inputs-after-r12.py?ref=9fdf4bed6ded1a01640bcaed2ffadb58204e42d5' > "$OUF_DIR/prepare.py"
  printf '%s  %s\n' '693ec0196a60d3a9f6adee96571947306df4a0cffb449905c3dcf8c09a34da1b' "$OUF_DIR/prepare.py" | sha256sum -c -
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/tools/semantic_target_review/prepare_application_runtime_inputs.py?ref=9fdf4bed6ded1a01640bcaed2ffadb58204e42d5' > "$OUF_DIR/custody.py"
  printf '%s  %s\n' 'cb9ff64684243d563da79d327eb7d7e325dbea6a3922c91a0b7791a3ceec9baf' "$OUF_DIR/custody.py" | sha256sum -c -
  OUF_PHASE=READ_PROTECTED_R12_READINESS_REASON_AND_BUDGET_NO_RECOVERY
  sudo /usr/bin/python3 -I -B -c '
import hashlib,os,stat,sys
expected=["d52fa8752dd9d37c3d950c9781ec00be1f9d8a173325049ce7eb43ceff1a607e", "693ec0196a60d3a9f6adee96571947306df4a0cffb449905c3dcf8c09a34da1b", "cb9ff64684243d563da79d327eb7d7e325dbea6a3922c91a0b7791a3ceec9baf"]
if len(sys.argv)!=4:raise SystemExit("OUF_R12_DIAGNOSIS_EXACT_SOURCE_SET_REQUIRED")
sources=[]
for path,digest in zip(sys.argv[1:],expected):
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW),"rb") as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1:raise SystemExit("OUF_R12_DIAGNOSIS_REGULAR_SOURCE_REQUIRED")
        raw=stream.read(131073)
    if len(raw)>131072 or hashlib.sha256(raw).hexdigest()!=digest:raise SystemExit("OUF_R12_DIAGNOSIS_SOURCE_HASH_MISMATCH")
    sources.append(raw)
path=sys.argv[1];sys.argv=[path]
exec(compile(sources[0],path,"exec"),{"__name__":"__main__","__file__":path,"__r12_diagnosis_sources__":dict(zip(("prepare","custody"),sources[1:]))})
' "$OUF_DIR/program.py" "$OUF_DIR/prepare.py" "$OUF_DIR/custody.py" | tee "$OUF_DIR/result.txt"
)
