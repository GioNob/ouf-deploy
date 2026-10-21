#!/usr/bin/env bash
# One source-bound R10 lease activation; existing R9 evidence is preserved.
(
  set -euo pipefail
  umask 077
  OUF_PHASE=DOWNLOAD_EXACT_R10_COMPONENTS
  OUF_R10_DIR=not_created
  trap 'OUF_CODE=$?; printf "OUF_FINITE_R10_APPLY_EXIT=%s PHASE=%s OUTPUT=%s/result.txt\n" "$OUF_CODE" "$OUF_PHASE" "$OUF_R10_DIR"' EXIT
  OUF_GH="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
  if [ ! -x "$OUF_GH" ]; then OUF_GH="$(command -v gh || true)"; fi
  if [ -z "$OUF_GH" ] || [ ! -x "$OUF_GH" ]; then
    printf 'OUF_FINITE_R10_DELIVERY=EXISTING_GH_NOT_FOUND\n'
    exit 1
  fi
  OUF_R10_DIR="$(mktemp -d "$HOME/ouf-finite-r10-apply.XXXXXXXX")"
  while read -r OUF_REMOTE OUF_LOCAL OUF_SHA; do
    "$OUF_GH" api -H 'Accept: application/vnd.github.raw' \
      "repos/GioNob/ouf-deploy/contents/$OUF_REMOTE?ref=cd8f43d38a302af318d35890b7c83cd96fe14607" > "$OUF_R10_DIR/$OUF_LOCAL"
    printf '%s  %s\n' "$OUF_SHA" "$OUF_R10_DIR/$OUF_LOCAL" | sha256sum -c -
  done <<'OUF_COMPONENTS'
tools/semantic_lease_recovery/activate_finite_r10.py activate_finite_r10.py 40822d277af67ec7145fb811cc2076e7845072418f1c25e306e1c0c9e14499e7
tools/semantic_lease_recovery/activation_core.py activation_core.py 06d14a340db6d35a795115fd921f901e1cd0de74c06174562107270b08fc7c2a
tools/semantic_lease_recovery/reader.py reader.py 4ddfda694150771fc8059ce22080a44c1d42db80c4f85b6b42f85c46442536d2
tools/semantic_lease_recovery/dns.py dns.py f1491cca148c488bbee8089dabcada0361781962d7b2858ad2fc4549cea3696f
tools/semantic_lease_recovery/materialize_southbound_lease_refresh.py materialize_southbound_lease_refresh.py c3160940cf79678cb8e44c036cb0d947016f885ab09acfe6cce571833db5b079
tools/semantic_lease_recovery/nft_seconds_backend.py nft.py 04cd115c756158ce2c04f32608380d7a40f4577d85785dfe46571825876545c1
tools/semantic_lease_recovery/adaptive_supervisor.py supervisor.py 08a354cfbea6a31ed1ea21dd80ddab0d0f983e3a0143a6f656124cf843d5635c
OUF_COMPONENTS
  OUF_PHASE=APPLY_SOURCE_BOUND_R10_ONCE
  sudo /usr/bin/python3 -I -B -c '
import hashlib,pathlib,sys
p=pathlib.Path(sys.argv[1])
with p.open("rb") as stream:
    raw=stream.read(131073)
if len(raw)>131072 or hashlib.sha256(raw).hexdigest()!="40822d277af67ec7145fb811cc2076e7845072418f1c25e306e1c0c9e14499e7":
    raise SystemExit("OUF_FINITE_R10_ENTRYPOINT_HASH_MISMATCH")
sys.argv=[str(p),"--apply","OUF_FINITE_LEASE_R10_DELEGATED_RECOVERY_20261010T204700_CEST"]
exec(compile(raw,str(p),"exec"),{"__name__":"__main__","__file__":str(p),"__verified_source_bytes__":raw})
' "$OUF_R10_DIR/activate_finite_r10.py" | tee "$OUF_R10_DIR/result.txt"
)
