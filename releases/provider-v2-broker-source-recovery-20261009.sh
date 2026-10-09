#!/usr/bin/env bash
# Accepted one-shot R5; an independent shell keeps errexit effective.
set -euo pipefail
phase=VERIFY_RETAINED_BRIDGES
trap 'rc=$?; printf "OUF_R5_RECOVERY_EXIT=%s PHASE=%s\n" "$rc" "$phase"' EXIT
gh_bin="$(command -v gh || true)"
if [[ -z "$gh_bin" ]]; then
  gh_bin="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
fi
[[ -x "$gh_bin" ]]
prior='/home/oufadmin/ouf-reviewed-recovery.qGpE9is0/execute.py'
r3='/home/oufadmin/ouf-r3-recovery.3ssUuaKX/execute.py'
printf '%s  %s\n' 'e3253513c4220a0a506c117e0a535145d14f76fcba3f58fe292ee894c46bfcd4' "$prior" | sha256sum -c -
printf '%s  %s\n' '5ff0a5ac9de85132371026584124f26ad57301601d16882c06974a9c21356328' "$r3" | sha256sum -c -
phase=DOWNLOAD_APPROVED_R5
work="$(mktemp -d "$HOME/ouf-r5-recovery.XXXXXXXX")"
printf 'OUF_R5_RECOVERY_DOWNLOAD=%s\n' "$work"
"$gh_bin" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_target_review/execute_broker_source_recovery.py?ref=530d8a11875c6ff18ca1f6831d28de639e0fe3c5' --jq '.content' | base64 --decode > "$work/execute.py"
phase=VERIFY_APPROVED_R5_DIGEST
printf '%s  %s\n' 'e675c3fdcf9640882abaa025a428800bcd088d03f612452673e8406ac29a1ba0' "$work/execute.py" | sha256sum -c -
phase=DOWNLOAD_SEALED_SOURCE_REPAIR
"$gh_bin" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_transaction_profiles/repair_broker_sources.py?ref=3c9f0df83b3e78e9343019a8c01983d815eb1347' --jq '.content' | base64 --decode > "$work/repair.py"
phase=VERIFY_SEALED_SOURCE_REPAIR
printf '%s  %s\n' 'c1479f6cb24bb376b83a6d61f61a80760dc7cf3ae9bc8c5ae9a7e7af6e5b3c8f' "$work/repair.py" | sha256sum -c -
phase=EXECUTE_APPROVED_ROOT_R5
sudo /usr/bin/python3.13 -I -B - "$work/execute.py" 'OUF_PROVIDER_V2_BROKER_SOURCE_RECOVERY_HUMAN_APPROVAL_20261009_130246' "$prior" "$r3" "$work/repair.py" <<'OUF_R5_VERIFIED_EXECUTION'
import hashlib, os, sys
fd = os.open(sys.argv[1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
try:
    raw = os.read(fd, 131073)
finally:
    os.close(fd)
if hashlib.sha256(raw).hexdigest() != 'e675c3fdcf9640882abaa025a428800bcd088d03f612452673e8406ac29a1ba0':
    raise SystemExit('R5_OPERATOR_HASH_DRIFT')
sys.argv = sys.argv[1:]
exec(compile(raw, sys.argv[0], 'exec'), {'__name__': '__main__', '__file__': sys.argv[0]})
OUF_R5_VERIFIED_EXECUTION
