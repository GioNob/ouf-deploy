#!/usr/bin/env bash
# One-use alias recovery approved 2026-10-09 16:07:45 Europe/Rome; ends 17:20:18.
set -euo pipefail
phase=VERIFY_EXISTING_TERMINAL_REVIEW
trap 'rc=$?; printf "OUF_TERMINAL_ALIAS_RECOVERY_EXIT=%s PHASE=%s\n" "$rc" "$phase"' EXIT
gh_bin="$(command -v gh || true)"
if [[ -z "$gh_bin" ]]; then
  gh_bin="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
fi
[[ -x "$gh_bin" ]]
review='/home/oufadmin/ouf-terminal-review.aA1bun9h/read.py'
printf '%s  %s\n' '4269551bed61bb437697cc6d38fb4f782264ba1dfb2bb6109347676fe2f95e27' "$review" | sha256sum -c -
work="$(mktemp -d "$HOME/ouf-terminal-alias-recovery.XXXXXXXX")"
printf 'OUF_TERMINAL_ALIAS_RECOVERY_DOWNLOAD=%s\n' "$work"
phase=DOWNLOAD_APPROVED_RECOVERY_EXECUTOR
"$gh_bin" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_target_review/execute_terminal_alias_recovery.py?ref=f2219975695cc695c4798e3044756f08219a3b36' --jq '.content' | base64 --decode > "$work/execute.py"
printf '%s  %s\n' '454ba9195caa1e9ea8732ca4cd2f302bdcea5126e42d3951f642e2c184382118' "$work/execute.py" | sha256sum -c -
phase=DOWNLOAD_REVIEWED_ALIAS_DELETE_GATE
"$gh_bin" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_target_review/terminal_task_delete_alias_gate.py?ref=ccdbe282927a771b6547b3ecc3ec70d602358252' --jq '.content' | base64 --decode > "$work/gate.py"
printf '%s  %s\n' 'a23f71e7fbe29fc3df4f138f41d35b4b5a3c63f14f1f15bc1c9e3d62644c9cfe' "$work/gate.py" | sha256sum -c -
phase=DOWNLOAD_REVIEWED_ARGUMENT_READER
"$gh_bin" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_target_review/read_terminal_gate_arguments.py?ref=3449e50d26cdaae0dcab2d6352c77c46c6368897' --jq '.content' | base64 --decode > "$work/arguments.py"
printf '%s  %s\n' 'd81fe4518b452c130b1c8c0fef14ffff6cc7a09ab3c92e29d28441786e52b5c7' "$work/arguments.py" | sha256sum -c -
phase=EXECUTE_EXPLICITLY_APPROVED_SINGLE_ALIAS_RECOVERY
sudo /usr/bin/python3.13 -I -B - "$work/execute.py" 'OUF_TERMINAL_ALIAS_RECOVERY_HUMAN_APPROVAL_20261009_160745' "$review" "$work/gate.py" "$work/arguments.py" <<'OUF_VERIFIED_ALIAS_EXECUTION'
import hashlib,os,sys
fd=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
try:raw=os.read(fd,131073)
finally:os.close(fd)
if hashlib.sha256(raw).hexdigest()!='454ba9195caa1e9ea8732ca4cd2f302bdcea5126e42d3951f642e2c184382118':
    raise SystemExit('ALIAS_RECOVERY_OPERATOR_HASH_DRIFT')
sys.argv=sys.argv[1:]
exec(compile(raw,sys.argv[0],'exec'),{'__name__':'__main__','__file__':sys.argv[0]})
OUF_VERIFIED_ALIAS_EXECUTION
