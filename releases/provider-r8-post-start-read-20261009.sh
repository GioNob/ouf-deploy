#!/usr/bin/env bash
# Single read-only operator invocation; no installation and no runtime changes.
(
  set -euo pipefail
  umask 077
  OUF_PHASE=DOWNLOAD_PINNED_POST_START_READER
  OUF_READ_DIR=not_created
  trap 'OUF_CODE=$?; printf "OUF_R8_POST_START_EXIT=%s PHASE=%s OUTPUT=%s/result.txt\n" "$OUF_CODE" "$OUF_PHASE" "$OUF_READ_DIR"' EXIT
  OUF_GH="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
  if [ ! -x "$OUF_GH" ]; then OUF_GH="$(command -v gh || true)"; fi
  if [ -z "$OUF_GH" ] || [ ! -x "$OUF_GH" ]; then
    printf 'OUF_R8_POST_START_DELIVERY=EXISTING_GH_NOT_FOUND\n'
    exit 1
  fi
  OUF_READ_DIR="$(mktemp -d "$HOME/ouf-r8-post-read.XXXXXXXX")"
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' \
    'repos/GioNob/ouf-deploy/contents/tools/semantic_target_review/read_r8_post_start.py?ref=a5d849de41c11d1218df393d8c8685f1f63e236d' \
    > "$OUF_READ_DIR/read.py"
  printf '%s  %s\n' 'ab61835ef55396ddacf4513acc0f21adbaab1b50ac32ad2fdc4c80a23d1835c8' "$OUF_READ_DIR/read.py" | sha256sum -c -
  OUF_PHASE=READ_EXISTING_R8_AND_LEASE_STATE_ONLY
  sudo /usr/bin/python3 -I -B -c '
import hashlib, pathlib, sys
p = pathlib.Path(sys.argv[1])
with p.open("rb") as stream:
    raw = stream.read(131073)
if len(raw) > 131072 or hashlib.sha256(raw).hexdigest() != "ab61835ef55396ddacf4513acc0f21adbaab1b50ac32ad2fdc4c80a23d1835c8":
    raise SystemExit("OUF_R8_POST_START_READER_HASH_MISMATCH")
sys.argv = [str(p)]
exec(compile(raw, str(p), "exec"), {"__name__": "__main__", "__file__": str(p)})
' "$OUF_READ_DIR/read.py" | tee "$OUF_READ_DIR/result.txt"
)
