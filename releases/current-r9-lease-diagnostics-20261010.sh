#!/usr/bin/env bash
# Read-only current R9 and existing shared ingress; no apply, lock or restart.
(
  set -euo pipefail
  umask 077
  OUF_PHASE=DOWNLOAD_PINNED_CURRENT_R9_READ
  OUF_READ_DIR=not_created
  trap 'OUF_CODE=$?; printf "OUF_CURRENT_R9_READ_EXIT=%s PHASE=%s OUTPUT=%s/result.txt\n" "$OUF_CODE" "$OUF_PHASE" "$OUF_READ_DIR"' EXIT
  OUF_GH="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
  if [ ! -x "$OUF_GH" ]; then OUF_GH="$(command -v gh || true)"; fi
  if [ -z "$OUF_GH" ] || [ ! -x "$OUF_GH" ]; then printf 'OUF_CURRENT_R9_READ_DELIVERY=EXISTING_GH_NOT_FOUND\n'; exit 1; fi
  OUF_READ_DIR="$(mktemp -d "$HOME/ouf-current-r9-read.XXXXXXXX")"
  for OUF_NAME in read_current_r9_transition.py read_cutover_inputs.py; do
    "$OUF_GH" api -H 'Accept: application/vnd.github.raw' "repos/GioNob/ouf-deploy/contents/tools/semantic_target_review/$OUF_NAME?ref=b70b1638e1e50776ad68d95198c95adcee75a5ed" > "$OUF_READ_DIR/$OUF_NAME"
  done
  printf '%s  %s\n' '7daf8e08eb530fe8a89fb56e93386c1d995679a4edff7005ed120ff8e92996dc' "$OUF_READ_DIR/read_current_r9_transition.py" 'b9ea8aa1a8cf31d28dfa1df0960dcf6930880d11244fe1f84e710bfe0b9ec4cf' "$OUF_READ_DIR/read_cutover_inputs.py" | sha256sum -c -
  OUF_PHASE=READ_CURRENT_R9_AND_ORIGINAL_SHARED_PEER_NO_LOCK_NO_APPLY
  sudo /usr/bin/python3 -I -B -c '

import hashlib,pathlib,sys
sources=[]
for path,expected in zip(sys.argv[1:],("7daf8e08eb530fe8a89fb56e93386c1d995679a4edff7005ed120ff8e92996dc","b9ea8aa1a8cf31d28dfa1df0960dcf6930880d11244fe1f84e710bfe0b9ec4cf")):
    with pathlib.Path(path).open("rb") as stream:raw=stream.read(131073)
    if len(raw)>131072 or hashlib.sha256(raw).hexdigest()!=expected:raise SystemExit("OUF_R9_READ_DELIVERY_HASH_MISMATCH")
    sources.append(raw)
if len(sources)!=2:raise SystemExit("OUF_R9_READ_EXACT_SOURCE_PAIR_REQUIRED")
p=sys.argv[1];sys.argv=[p]
exec(compile(sources[0],p,"exec"),{"__name__":"__main__","__file__":p,"__reader_source_bytes__":sources[1]})

' "$OUF_READ_DIR/read_current_r9_transition.py" "$OUF_READ_DIR/read_cutover_inputs.py" | tee "$OUF_READ_DIR/result.txt"
)
