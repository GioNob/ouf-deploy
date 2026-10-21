#!/usr/bin/env bash
# Single read-only operator invocation; no installation or lock acquisition.
(
  set -euo pipefail
  umask 077
  OUF_PHASE=DOWNLOAD_PINNED_CUTOVER_INPUT_READER
  OUF_READ_DIR=not_created
  trap 'OUF_CODE=$?; printf "OUF_DISCOVERY_CUTOVER_READ_EXIT=%s PHASE=%s OUTPUT=%s/result.txt\n" "$OUF_CODE" "$OUF_PHASE" "$OUF_READ_DIR"' EXIT
  OUF_GH="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
  if [ ! -x "$OUF_GH" ]; then OUF_GH="$(command -v gh || true)"; fi
  if [ -z "$OUF_GH" ] || [ ! -x "$OUF_GH" ]; then
    printf 'OUF_DISCOVERY_CUTOVER_READ_DELIVERY=EXISTING_GH_NOT_FOUND\n'
    exit 1
  fi
  OUF_READ_DIR="$(mktemp -d "$HOME/ouf-discovery-cutover-read.XXXXXXXX")"
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' \
    'repos/GioNob/ouf-deploy/contents/tools/semantic_target_review/read_cutover_inputs.py?ref=550c5e733fdafe33ac6b5f0117231d53c603b510' \
    > "$OUF_READ_DIR/read.py"
  printf '%s  %s\n' 'b9ea8aa1a8cf31d28dfa1df0960dcf6930880d11244fe1f84e710bfe0b9ec4cf' "$OUF_READ_DIR/read.py" | sha256sum -c -
  OUF_PHASE=READ_EXISTING_SHARED_INGRESS_PEER_AND_LEASE_ONLY
  sudo /usr/bin/python3 -I -B -c '
import hashlib, pathlib, sys
p = pathlib.Path(sys.argv[1])
with p.open("rb") as stream:
    raw = stream.read(131073)
if len(raw) > 131072 or hashlib.sha256(raw).hexdigest() != "b9ea8aa1a8cf31d28dfa1df0960dcf6930880d11244fe1f84e710bfe0b9ec4cf":
    raise SystemExit("OUF_DISCOVERY_CUTOVER_READER_HASH_MISMATCH")
sys.argv = [str(p)]
exec(compile(raw, str(p), "exec"), {"__name__": "__main__", "__file__": str(p)})
' "$OUF_READ_DIR/read.py" | tee "$OUF_READ_DIR/result.txt"
)
