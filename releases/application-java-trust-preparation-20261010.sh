#!/usr/bin/env bash
# One-use public Java trust preparation; no application or R9 cutover.
(
  set -euo pipefail
  umask 077
  OUF_TRUST_DIR=not_created
  OUF_PHASE=DOWNLOAD_PINNED_JAVA_TRUST_PREPARATION
  trap 'OUF_CODE=$?; printf "OUF_APPLICATION_JAVA_TRUST_EXIT=%s PHASE=%s OUTPUT=%s/result.txt\n" "$OUF_CODE" "$OUF_PHASE" "$OUF_TRUST_DIR"' EXIT
  OUF_GH="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
  if [ ! -x "$OUF_GH" ]; then OUF_GH="$(command -v gh)"; fi
  OUF_TRUST_DIR="$(mktemp -d "$HOME/ouf-java-trust.XXXXXXXX")"
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' "repos/GioNob/ouf-deploy/contents/tools/semantic_java_trust/prepare_target_trust.py?ref=f25e205b5fe812780cd421a9a742e592268d32b9" > "$OUF_TRUST_DIR/prepare_target_trust.py"
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' "repos/GioNob/ouf-deploy/contents/tools/semantic_target_review/prepare_application_runtime_inputs.py?ref=f25e205b5fe812780cd421a9a742e592268d32b9" > "$OUF_TRUST_DIR/custody.py"
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' "repos/GioNob/ouf-deploy/contents/tools/semantic_target_review/read_cutover_inputs.py?ref=f25e205b5fe812780cd421a9a742e592268d32b9" > "$OUF_TRUST_DIR/reader.py"
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' "repos/GioNob/ouf-deploy/contents/tools/semantic_java_trust/merge_public_roots.py?ref=f25e205b5fe812780cd421a9a742e592268d32b9" > "$OUF_TRUST_DIR/merge.py"
  printf '%s  %s\n' 'd8510d570ea9fdda73af5a53e2cb9d42f2a9af58de7d9533c4fdb143ce794d4f' "$OUF_TRUST_DIR/prepare_target_trust.py" 'cb9ff64684243d563da79d327eb7d7e325dbea6a3922c91a0b7791a3ceec9baf' "$OUF_TRUST_DIR/custody.py" 'b9ea8aa1a8cf31d28dfa1df0960dcf6930880d11244fe1f84e710bfe0b9ec4cf' "$OUF_TRUST_DIR/reader.py" 'e65e009b3c5daac722248d7793fea73cbfef50d2cd3f6da5f1a6e2c82f91a78b' "$OUF_TRUST_DIR/merge.py" | sha256sum -c -
  OUF_PHASE=PREPARE_PUBLIC_JAVA_TRUST_ONCE_OFFLINE_NO_APPLICATION_MOUNTS
  sudo /usr/bin/python3 -I -B -c '
import hashlib,pathlib,sys
expected=("d8510d570ea9fdda73af5a53e2cb9d42f2a9af58de7d9533c4fdb143ce794d4f", "cb9ff64684243d563da79d327eb7d7e325dbea6a3922c91a0b7791a3ceec9baf", "b9ea8aa1a8cf31d28dfa1df0960dcf6930880d11244fe1f84e710bfe0b9ec4cf", "e65e009b3c5daac722248d7793fea73cbfef50d2cd3f6da5f1a6e2c82f91a78b")
if len(sys.argv)!=5:raise SystemExit("OUF_JAVA_TRUST_EXACT_SOURCE_SET_REQUIRED")
sources=[]
for path,digest in zip(sys.argv[1:],expected):
    with pathlib.Path(path).open("rb") as stream:raw=stream.read(131073)
    if len(raw)>131072 or hashlib.sha256(raw).hexdigest()!=digest:raise SystemExit("OUF_JAVA_TRUST_SOURCE_HASH_MISMATCH")
    sources.append(raw)
p=sys.argv[1];sys.argv=[p]
exec(compile(sources[0],p,"exec"),{"__name__":"__main__","__file__":p,"__sources__":dict(zip(("custody","reader","merge"),sources[1:]))})
' "$OUF_TRUST_DIR/prepare_target_trust.py" "$OUF_TRUST_DIR/custody.py" "$OUF_TRUST_DIR/reader.py" "$OUF_TRUST_DIR/merge.py" | tee "$OUF_TRUST_DIR/result.txt"
)
