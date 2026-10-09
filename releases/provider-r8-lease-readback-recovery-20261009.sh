#!/usr/bin/env bash
# One explicit approved lease activation; no automatic replay.
(
  set -euo pipefail
  umask 077
  OUF_PHASE=REQUIRE_EXPLICIT_LEASE_APPROVAL
  OUF_LEASE_DIR=not_created
  OUF_APPROVAL_REF=PENDING_EXPLICIT_R8_LEASE_READBACK_RECOVERY
  trap 'OUF_CODE=$?; printf "OUF_R8_LEASE_EXIT=%s PHASE=%s OUTPUT=%s/result-readback-recovery.txt\n" "$OUF_CODE" "$OUF_PHASE" "$OUF_LEASE_DIR"' EXIT
  case "$OUF_APPROVAL_REF" in PENDING*) printf 'OUF_R8_LEASE_DELIVERY=AWAITING_EXPLICIT_APPROVAL\n'; exit 1;; esac
  OUF_GH="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
  if [ ! -x "$OUF_GH" ]; then OUF_GH="$(command -v gh || true)"; fi
  if [ -z "$OUF_GH" ] || [ ! -x "$OUF_GH" ]; then
    printf 'OUF_R8_LEASE_DELIVERY=EXISTING_GH_NOT_FOUND\n'
    exit 1
  fi
  OUF_PHASE=DOWNLOAD_CORRECTED_ENTRYPOINT_REUSE_VERIFIED_CORE_AND_COMPILER
  OUF_LEASE_DIR=/home/oufadmin/ouf-r8-lease.8XKYoqHc
  test -d "$OUF_LEASE_DIR"
  printf 'OUF_R8_LEASE_DOWNLOAD=%s\n' "$OUF_LEASE_DIR"
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' \
    'repos/GioNob/ouf-deploy/contents/tools/semantic_lease_activation/activate_r8_lease.py?ref=1d77ecf777aad58bbb7a7f7bff3fd31b9bf5c32f' \
    > "$OUF_LEASE_DIR/activate_r8_lease_readback_recovery.py"
  printf '%s  %s\n' '97b41378fc8bf7339e09968871371107ced63842dea226af874c819d546d92f2' "$OUF_LEASE_DIR/activate_r8_lease_readback_recovery.py" | sha256sum -c -
  printf '%s  %s\n' '51259c988eae4b506f2696ad3f5bf6e954eca9c4396cb36da75e0845ff49e50b' "$OUF_LEASE_DIR/activation_core.py" | sha256sum -c -
  printf '%s  %s\n' 'c3160940cf79678cb8e44c036cb0d947016f885ab09acfe6cce571833db5b079' "$OUF_LEASE_DIR/materialize_southbound_lease_refresh.py" | sha256sum -c -
  OUF_PHASE=ACTIVATE_EXPLICIT_TWO_FLOW_LEASE_ONCE
  sudo /usr/bin/python3 -I -B -c '
import hashlib, pathlib, sys
p = pathlib.Path(sys.argv[1])
with p.open("rb") as stream:
    raw = stream.read(131073)
if len(raw) > 131072 or hashlib.sha256(raw).hexdigest() != "97b41378fc8bf7339e09968871371107ced63842dea226af874c819d546d92f2":
    raise SystemExit("OUF_R8_LEASE_ENTRYPOINT_HASH_MISMATCH")
sys.argv = [str(p), "--apply", sys.argv[2]]
exec(compile(raw, str(p), "exec"), {"__name__": "__main__", "__file__": str(p), "__verified_source_bytes__": raw})
' "$OUF_LEASE_DIR/activate_r8_lease_readback_recovery.py" "$OUF_APPROVAL_REF" | tee "$OUF_LEASE_DIR/result-readback-recovery.txt"
)
