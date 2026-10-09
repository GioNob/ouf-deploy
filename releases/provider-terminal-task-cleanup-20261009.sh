#!/usr/bin/env bash
# Review template remains inert until the explicit scoped approval is recorded.
set -euo pipefail
phase=VERIFY_EXISTING_TERMINAL_REVIEW
trap 'rc=$?; printf "OUF_TERMINAL_CLEANUP_EXIT=%s PHASE=%s\n" "$rc" "$phase"' EXIT
gh_bin="$(command -v gh || true)"
if [[ -z "$gh_bin" ]]; then
  gh_bin="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
fi
[[ -x "$gh_bin" ]]
review='/home/oufadmin/ouf-terminal-review.aA1bun9h/read.py'
printf '%s  %s\n' '4269551bed61bb437697cc6d38fb4f782264ba1dfb2bb6109347676fe2f95e27' "$review" | sha256sum -c -
work="$(mktemp -d "$HOME/ouf-terminal-cleanup.XXXXXXXX")"
printf 'OUF_TERMINAL_CLEANUP_DOWNLOAD=%s\n' "$work"
phase=DOWNLOAD_REVIEWED_EXECUTOR
"$gh_bin" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_target_review/execute_terminal_task_cleanup.py?ref=99ec4aa387acadd8b9928ecd9af268c1069527ae' --jq '.content' | base64 --decode > "$work/execute.py"
printf '%s  %s\n' '953e337f5a40b9ef22549e236ceff2a022090329d415b01a1bc960017b796a02' "$work/execute.py" | sha256sum -c -
phase=DOWNLOAD_REVIEWED_DELETE_ONLY_GATE
"$gh_bin" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_target_review/terminal_task_delete_gate.py?ref=99ec4aa387acadd8b9928ecd9af268c1069527ae' --jq '.content' | base64 --decode > "$work/gate.py"
printf '%s  %s\n' 'b30fb108a72f6aaa008789a6af8b9801ca23dce3dd5f6bd62eb799496cf07027' "$work/gate.py" | sha256sum -c -
phase=EXECUTE_EXPLICITLY_APPROVED_TERMINAL_MAINTENANCE
sudo /usr/bin/python3.13 -I -B - "$work/execute.py" 'PENDING_TERMINAL_TASK_CLEANUP_APPROVAL' "$review" "$work/gate.py" <<'OUF_VERIFIED_TERMINAL_EXECUTION'
import hashlib,os,sys
fd=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
try:raw=os.read(fd,131073)
finally:os.close(fd)
if hashlib.sha256(raw).hexdigest()!='953e337f5a40b9ef22549e236ceff2a022090329d415b01a1bc960017b796a02':
    raise SystemExit('TERMINAL_OPERATOR_HASH_DRIFT')
sys.argv=sys.argv[1:]
exec(compile(raw,sys.argv[0],'exec'),{'__name__':'__main__','__file__':sys.argv[0]})
OUF_VERIFIED_TERMINAL_EXECUTION
