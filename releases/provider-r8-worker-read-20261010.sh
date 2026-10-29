#!/usr/bin/env bash
# Single read-only operator invocation; no installation or lock acquisition.
(
  set -euo pipefail
  umask 077
  OUF_PHASE=DOWNLOAD_PINNED_WORKER_DIAGNOSTICS_READER
  OUF_READ_DIR=not_created
  trap 'OUF_CODE=$?; printf "OUF_R8_WORKER_QUIESCENCE_READ_EXIT=%s PHASE=%s OUTPUT=%s/result.txt\n" "$OUF_CODE" "$OUF_PHASE" "$OUF_READ_DIR"' EXIT
  OUF_GH="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
  if [ ! -x "$OUF_GH" ]; then OUF_GH="$(command -v gh || true)"; fi
  if [ -z "$OUF_GH" ] || [ ! -x "$OUF_GH" ]; then
    printf 'OUF_R8_WORKER_QUIESCENCE_READ_DELIVERY=EXISTING_GH_NOT_FOUND\n'
    exit 1
  fi
  OUF_READ_DIR="$(mktemp -d "$HOME/ouf-r8-worker-read.XXXXXXXX")"
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' \
    'repos/GioNob/ouf-deploy/contents/tools/semantic_target_review/read_r8_worker_quiescence.py?ref=a13d50881e0eeab5fc66e9432b43fa4658e046b8' \
    > "$OUF_READ_DIR/read.py"
  printf '%s  %s\n' 'b7197def3b3f3bf1d108428f61ccc5652dbb916c22f22caf8a5414e761507e3f' "$OUF_READ_DIR/read.py" | sha256sum -c -
  OUF_PHASE=READ_CONSUMED_WORKER_RECORDS_AND_SYSTEMD_ONLY
  sudo /usr/bin/python3 -I -B -c '
import hashlib, pathlib, sys
p = pathlib.Path(sys.argv[1])
with p.open("rb") as stream:
    raw = stream.read(131073)
if len(raw) > 131072 or hashlib.sha256(raw).hexdigest() != "b7197def3b3f3bf1d108428f61ccc5652dbb916c22f22caf8a5414e761507e3f":
    raise SystemExit("OUF_R8_WORKER_QUIESCENCE_READER_HASH_MISMATCH")
sys.argv = [str(p)]
exec(compile(raw, str(p), "exec"), {"__name__": "__main__", "__file__": str(p)})
' "$OUF_READ_DIR/read.py" | tee "$OUF_READ_DIR/result.txt"
)
