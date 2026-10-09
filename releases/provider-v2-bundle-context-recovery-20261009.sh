#!/usr/bin/env bash
# Accepted one-shot R4; an independent shell keeps errexit effective.
set -euo pipefail
phase=VERIFY_RETAINED_BRIDGES
trap 'rc=$?; printf "OUF_R4_RECOVERY_EXIT=%s PHASE=%s\n" "$rc" "$phase"' EXIT
gh_bin="$(command -v gh || true)"
if [[ -z "$gh_bin" ]]; then
  gh_bin="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
fi
[[ -x "$gh_bin" ]]
prior='/home/oufadmin/ouf-reviewed-recovery.qGpE9is0/execute.py'
r3='/home/oufadmin/ouf-r3-recovery.3ssUuaKX/execute.py'
printf '%s  %s\n' 'e3253513c4220a0a506c117e0a535145d14f76fcba3f58fe292ee894c46bfcd4' "$prior" | sha256sum -c -
printf '%s  %s\n' '5ff0a5ac9de85132371026584124f26ad57301601d16882c06974a9c21356328' "$r3" | sha256sum -c -
phase=DOWNLOAD_APPROVED_R4
work="$(mktemp -d "$HOME/ouf-r4-recovery.XXXXXXXX")"
printf 'OUF_R4_RECOVERY_DOWNLOAD=%s\n' "$work"
"$gh_bin" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_target_review/execute_bundle_context_recovery.py?ref=796e23f6e3f6e4c8c6ac64bace2230e9bfbf7abe' --jq '.content' | base64 --decode > "$work/execute.py"
phase=VERIFY_APPROVED_R4_DIGEST
printf '%s  %s\n' '262f03825cc8beb4c8823c5882d9549d4220a8ffeb90e4601d8fc5671e610fce' "$work/execute.py" | sha256sum -c -
phase=EXECUTE_APPROVED_ROOT_R4
sudo /usr/bin/python3.13 -I -B - "$work/execute.py" 'OUF_PROVIDER_V2_BUNDLE_CONTEXT_RECOVERY_HUMAN_APPROVAL_20261009_102223' "$prior" "$r3" <<'OUF_R4_VERIFIED_EXECUTION'
import hashlib, os, sys
fd = os.open(sys.argv[1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
try:
    raw = os.read(fd, 131073)
finally:
    os.close(fd)
if hashlib.sha256(raw).hexdigest() != '262f03825cc8beb4c8823c5882d9549d4220a8ffeb90e4601d8fc5671e610fce':
    raise SystemExit('R4_OPERATOR_HASH_DRIFT')
sys.argv = sys.argv[1:]
exec(compile(raw, sys.argv[0], 'exec'), {'__name__': '__main__', '__file__': sys.argv[0]})
OUF_R4_VERIFIED_EXECUTION
