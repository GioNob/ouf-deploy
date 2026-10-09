#!/usr/bin/env bash
# Approved one-use R6: human acknowledgment 2026-10-09 16:51:18 Europe/Rome.
set -euo pipefail
phase=VERIFY_RETAINED_BRIDGES
trap 'rc=$?; printf "OUF_R6_RECOVERY_EXIT=%s PHASE=%s\n" "$rc" "$phase"' EXIT
gh_bin="$(command -v gh || true)"
if [[ -z "$gh_bin" ]]; then
  gh_bin="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
fi
[[ -x "$gh_bin" ]]
prior='/home/oufadmin/ouf-reviewed-recovery.qGpE9is0/execute.py'
r3='/home/oufadmin/ouf-r3-recovery.3ssUuaKX/execute.py'
printf '%s  %s\n' 'e3253513c4220a0a506c117e0a535145d14f76fcba3f58fe292ee894c46bfcd4' "$prior" | sha256sum -c -
printf '%s  %s\n' '5ff0a5ac9de85132371026584124f26ad57301601d16882c06974a9c21356328' "$r3" | sha256sum -c -
work="$(mktemp -d "$HOME/ouf-r6-recovery.XXXXXXXX")"
printf 'OUF_R6_RECOVERY_DOWNLOAD=%s\n' "$work"
phase=DOWNLOAD_REVIEWED_R6
"$gh_bin" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_target_review/execute_post_terminal_admission_recovery.py?ref=a6d7c31e11d9f65bfa4b79082f234e1496048bf9' --jq '.content' | base64 --decode > "$work/execute.py"
printf '%s  %s\n' 'c803914d9e1dccf374efb67e681de43d1eceb65bcb83b04f5dfa8db4d2aaf7e5' "$work/execute.py" | sha256sum -c -
phase=DOWNLOAD_EXISTING_R5_SOURCE_TRANSFORMATION
"$gh_bin" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_transaction_profiles/repair_broker_sources.py?ref=3c9f0df83b3e78e9343019a8c01983d815eb1347' --jq '.content' | base64 --decode > "$work/repair.py"
printf '%s  %s\n' 'c1479f6cb24bb376b83a6d61f61a80760dc7cf3ae9bc8c5ae9a7e7af6e5b3c8f' "$work/repair.py" | sha256sum -c -
phase=DOWNLOAD_CORRECTED_POST_TERMINAL_PREFLIGHT
"$gh_bin" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_target_review/read_post_terminal_admission_preflight.py?ref=3f96742c9182d70c818fba33d1b752873f895634' --jq '.content' | base64 --decode > "$work/preflight.py"
printf '%s  %s\n' '025e3280abf18ee53e20acea2006f63ffd2ba4d80a8549924772d3372c56b958' "$work/preflight.py" | sha256sum -c -
phase=EXECUTE_SCOPED_SINGLE_R6_ADMISSION
sudo /usr/bin/python3.13 -I -B - "$work/execute.py" 'OUF_PROVIDER_V2_POST_TERMINAL_ADMISSION_APPROVED_20261009T165118_CEST_R6' "$prior" "$r3" "$work/repair.py" "$work/preflight.py" <<'OUF_R6_VERIFIED_EXECUTION'
import hashlib,os,sys
fd=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
try:raw=os.read(fd,131073)
finally:os.close(fd)
if hashlib.sha256(raw).hexdigest()!='c803914d9e1dccf374efb67e681de43d1eceb65bcb83b04f5dfa8db4d2aaf7e5':
    raise SystemExit('R6_OPERATOR_HASH_DRIFT')
sys.argv=sys.argv[1:]
exec(compile(raw,sys.argv[0],'exec'),{'__name__':'__main__','__file__':sys.argv[0]})
OUF_R6_VERIFIED_EXECUTION
