#!/usr/bin/env bash
# Inert delivery until the exact R8 scope receives fresh human approval.
set -u
set -o pipefail
umask 077
OUF_R8_COMMIT=378c882379502f5b9809e0f24f6a3a64cdacef56
OUF_R8_APPROVAL=OUF_PROVIDER_PREPARED_MOUNTPOINT_APPROVED_20261009T203804_CEST_R8
OUF_R8_EXECUTOR_SHA=89cba73a29f3e4def5af40f991720766b51a379c6a441c502d2240f4d17f9214
OUF_R8_PHASE=REQUIRE_RECORDED_APPROVAL
OUF_R8_WORK_ROOT=${OUF_R8_WORK_ROOT:-"$HOME"}
main() {
  if [[ "$OUF_R8_APPROVAL" == PENDING_* ]]; then
    echo 'OUF_R8_DELIVERY=NOT_AUTHORIZED REASON=HUMAN_APPROVAL_PENDING'
    return 79
  fi
  OUF_R8_GH="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
  [[ -x "$OUF_R8_GH" ]] || { echo 'OUF_R8_DELIVERY=EXISTING_GH_NOT_EXECUTABLE'; return 1; }
  OUF_R8_DOWNLOAD="$(mktemp -d "$OUF_R8_WORK_ROOT/ouf-r8-recovery.XXXXXXXX")" || return 1
  echo "OUF_R8_DOWNLOAD=$OUF_R8_DOWNLOAD"
  OUF_R8_PHASE=VERIFY_PINNED_DELIVERY_BEFORE_SUDO
  download() {
    local remote_path="$1" filename="$2" expected="$3"
    "$OUF_R8_GH" api "repos/GioNob/ouf-deploy/contents/$remote_path?ref=$OUF_R8_COMMIT" --jq .content > "$OUF_R8_DOWNLOAD/$filename.base64" || return 1
    base64 --decode "$OUF_R8_DOWNLOAD/$filename.base64" > "$OUF_R8_DOWNLOAD/$filename" || return 1
    printf '%s  %s\n' "$expected" "$OUF_R8_DOWNLOAD/$filename" | sha256sum -c - || return 1
  }
  download tools/semantic_target_review/execute_prepared_mountpoint_recovery.py execute.py "$OUF_R8_EXECUTOR_SHA" || return 1
  download tools/semantic_transaction_profiles/prepare_mountpoint_acceptance.py prepare_mountpoint_acceptance.py 143112ab4051ca166f6d7609c107787f2be3ce35ce7946002dfec755ff1fdd98 || return 1
  download evidence/provider-r8-mountpoint-recovery-scope-20261009.json scope.json 24f6c5a25893e1757bb903b74b90155e39d19864d377ed3a31a94e80bfce1a86 || return 1
  OUF_R8_PHASE=EXECUTE_EXPLICITLY_APPROVED_R8_ONCE
  sudo /usr/bin/python3.13 -I -B -c '
import hashlib,os,stat,sys
path,wanted,approval,directory=sys.argv[1:]
fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
try:
    info=os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_size>131072:raise SystemExit("BOUNDED_REVIEWED_EXECUTOR_REQUIRED")
    raw=os.read(fd,131073)
finally:os.close(fd)
if hashlib.sha256(raw).hexdigest()!=wanted:raise SystemExit("REVIEWED_EXECUTOR_HASH_DRIFT")
sys.argv=[path,approval,directory]
exec(compile(raw,path,"exec"),{"__name__":"__main__","__file__":path})
' "$OUF_R8_DOWNLOAD/execute.py" "$OUF_R8_EXECUTOR_SHA" "$OUF_R8_APPROVAL" "$OUF_R8_DOWNLOAD"
}
main
OUF_R8_RECOVERY_EXIT=$?
printf 'OUF_R8_RECOVERY_EXIT=%s PHASE=%s\n' "$OUF_R8_RECOVERY_EXIT" "$OUF_R8_PHASE"
exit "$OUF_R8_RECOVERY_EXIT"
