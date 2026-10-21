#!/usr/bin/env bash
# One accepted R3 launch. Own shell: fail immediately before root on any error.
set -euo pipefail
trap 'rc=$?; printf "OUF_R3_RECOVERY_EXIT=%s\n" "$rc"' EXIT
gh_bin="$(command -v gh || true)"
if [[ -z "$gh_bin" ]]; then
  gh_bin="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
fi
[[ -x "$gh_bin" ]]
prior='/home/oufadmin/ouf-reviewed-recovery.qGpE9is0/execute.py'
printf '%s  %s\n' 'e3253513c4220a0a506c117e0a535145d14f76fcba3f58fe292ee894c46bfcd4' "$prior" | sha256sum -c -
work="$(mktemp -d "$HOME/ouf-r3-recovery.XXXXXXXX")"
printf 'OUF_R3_RECOVERY_DOWNLOAD=%s\n' "$work"
"$gh_bin" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_target_review/execute_post_signature_recovery.py?ref=14a0da47544e4f56313e25b521c27b3ea7481b60' --jq '.content' | base64 --decode > "$work/execute.py"
printf '%s  %s\n' '5ff0a5ac9de85132371026584124f26ad57301601d16882c06974a9c21356328' "$work/execute.py" | sha256sum -c -
sudo /usr/bin/python3.13 -I -B - "$work/execute.py" 'OUF_PROVIDER_V2_POST_SIGNATURE_RECOVERY_HUMAN_APPROVAL_20261009_093008' "$prior" <<'OUF_R3_VERIFIED_EXECUTION'
import hashlib, os, sys
fd = os.open(sys.argv[1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
try:
    raw = os.read(fd, 131073)
finally:
    os.close(fd)
if hashlib.sha256(raw).hexdigest() != '5ff0a5ac9de85132371026584124f26ad57301601d16882c06974a9c21356328':
    raise SystemExit('R3_OPERATOR_HASH_DRIFT')
sys.argv = [sys.argv[1], sys.argv[2], sys.argv[3]]
exec(compile(raw, sys.argv[0], 'exec'), {'__name__': '__main__', '__file__': sys.argv[0]})
OUF_R3_VERIFIED_EXECUTION
