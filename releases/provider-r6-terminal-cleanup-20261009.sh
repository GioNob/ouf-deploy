#!/usr/bin/env bash
# Exact R6 residual-task cleanup approved 2026-10-09 17:43:56 Europe/Rome.
set -euo pipefail
phase=VERIFY_EXISTING_R6_TERMINAL_REVIEW
trap 'rc=$?; printf "OUF_R6_CLEANUP_EXIT=%s PHASE=%s\n" "$rc" "$phase"' EXIT
ouf_gh="$(command -v gh || true)"
if [[ -z "$ouf_gh" ]]; then
  ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
fi
[[ -x "$ouf_gh" ]]
review='/home/oufadmin/ouf-r6-terminal-read.ZkjE4b0I/read.py'
printf '%s  %s\n' '21c10d32b9acbc80a044a14e87501d060bd273e3aa87b32ce9337b8ef1da66cb' "$review" | sha256sum -c -
ouf_work="$(mktemp -d "$HOME/ouf-r6-cleanup.XXXXXXXX")"
printf 'OUF_R6_CLEANUP_DOWNLOAD=%s\n' "$ouf_work"
phase=DOWNLOAD_APPROVED_R6_CLEANUP
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_target_review/execute_r6_terminal_cleanup.py?ref=7876ecba663ca25a5d7f8322413cd89950fee04a' --jq '.content' | base64 --decode > "$ouf_work/execute.py"
printf '%s  %s\n' '1904926c751851b599e7eab33063d7b9a94d34388b363d4853c831c8834cddaa' "$ouf_work/execute.py" | sha256sum -c -
phase=DOWNLOAD_EXISTING_ALIAS_DELETE_ONLY_GATE
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_target_review/terminal_task_delete_alias_gate.py?ref=827f0ef05d6d8b646c052778c58c260440493e92' --jq '.content' | base64 --decode > "$ouf_work/gate.py"
printf '%s  %s\n' 'a23f71e7fbe29fc3df4f138f41d35b4b5a3c63f14f1f15bc1c9e3d62644c9cfe' "$ouf_work/gate.py" | sha256sum -c -
phase=DOWNLOAD_EXISTING_RETAINED_ARGUMENT_RECONSTRUCTOR
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_target_review/read_terminal_gate_arguments.py?ref=827f0ef05d6d8b646c052778c58c260440493e92' --jq '.content' | base64 --decode > "$ouf_work/arguments.py"
printf '%s  %s\n' 'd81fe4518b452c130b1c8c0fef14ffff6cc7a09ab3c92e29d28441786e52b5c7' "$ouf_work/arguments.py" | sha256sum -c -
phase=EXECUTE_EXPLICITLY_APPROVED_R6_CLEANUP_ONCE
sudo /usr/bin/python3.13 -I -B - "$ouf_work/execute.py" 'OUF_R6_TERMINAL_CLEANUP_APPROVED_20261009T174356_CEST' "$review" "$ouf_work/gate.py" "$ouf_work/arguments.py" <<'OUF_VERIFIED_R6_CLEANUP'
import hashlib,os,sys
fd=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
try:raw=os.read(fd,131073)
finally:os.close(fd)
if hashlib.sha256(raw).hexdigest()!='1904926c751851b599e7eab33063d7b9a94d34388b363d4853c831c8834cddaa':
    raise SystemExit('R6_CLEANUP_OPERATOR_HASH_DRIFT')
sys.argv=sys.argv[1:]
exec(compile(raw,sys.argv[0],'exec'),{'__name__':'__main__','__file__':sys.argv[0]})
OUF_VERIFIED_R6_CLEANUP
