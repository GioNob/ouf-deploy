#!/usr/bin/env bash
# Delivery only. Inert until the exact audited recovery is approved.
set -u
set -o pipefail
umask 077
OUF_AUDIT_COMMIT=f869679b7bf81d930a925508e0fee48eab25612d
OUF_AUDIT_APPROVAL=OUF_PROVIDER_AUDITED_RECOVERY_APPROVED_20261009T191942_CEST_R7
OUF_AUDIT_EXECUTOR_SHA=6ce5addae1df8a418bc3dfead347c5d6acbd51d5607c436260aadef741cbcfc0
OUF_AUDIT_PHASE=REQUIRE_RECORDED_APPROVAL
OUF_AUDIT_WORK_ROOT=${OUF_AUDIT_WORK_ROOT:-"$HOME"}
main() {
  if [[ "$OUF_AUDIT_APPROVAL" == PENDING_* ]]; then
    echo 'OUF_AUDITED_RECOVERY_LAUNCH=NOT_AUTHORIZED REASON=HUMAN_APPROVAL_PENDING'
    return 79
  fi
  command -v gh >/dev/null 2>&1 || { echo 'OUF_AUDITED_RECOVERY_LAUNCH=BLOCKED REASON=GH_REQUIRED'; return 1; }
  OUF_AUDIT_DOWNLOAD=$(mktemp -d "$OUF_AUDIT_WORK_ROOT/ouf-audited-recovery.XXXXXXXX") || return 1
  echo "OUF_AUDITED_RECOVERY_DOWNLOAD=$OUF_AUDIT_DOWNLOAD"
  OUF_AUDIT_PHASE=VERIFY_PINNED_DELIVERY_BEFORE_SUDO
  download() {
    local remote_path="$1" filename="$2" expected="$3"
    gh api "repos/GioNob/ouf-deploy/contents/$remote_path?ref=$OUF_AUDIT_COMMIT" --jq .content > "$OUF_AUDIT_DOWNLOAD/$filename.base64" || return 1
    base64 --decode "$OUF_AUDIT_DOWNLOAD/$filename.base64" > "$OUF_AUDIT_DOWNLOAD/$filename" || return 1
    printf '%s  %s\n' "$expected" "$OUF_AUDIT_DOWNLOAD/$filename" | sha256sum -c - || return 1
  }
  download tools/semantic_target_review/execute_audited_provider_recovery.py execute.py 6ce5addae1df8a418bc3dfead347c5d6acbd51d5607c436260aadef741cbcfc0 || return 1
  download tools/semantic_transaction_profiles/provider_transaction_intake.py provider_transaction_intake.py f81d8ec23d551acb2419aaefa0c2a4531de4de6219758e263496c228cfa4570d || return 1
  download tools/semantic_transaction_profiles/publish_provider_transaction.py publish_provider_transaction.py 7777f33432bbfadd56f89fd2ed0122ce1c14e41d797498d94fa7bdb3324d0080 || return 1
  download tools/semantic_transaction_profiles/guarded_runtime_switch.py guarded_runtime_switch.py 1492237e1c1ce85da5c9220ea3f6f024b24dc4d217ff5bf6e5b43c14fff225bd || return 1
  download tools/semantic_transaction_profiles/authenticated_runtime_switch.py authenticated_runtime_switch.py ce5625aa645b3da470e84b8544adfa82d5bca8665bb88d8e2d49fd3701548d83 || return 1
  download tools/semantic_transaction_profiles/repair_broker_sources.py repair_broker_sources.py c1479f6cb24bb376b83a6d61f61a80760dc7cf3ae9bc8c5ae9a7e7af6e5b3c8f || return 1
  download tools/semantic_transaction_profiles/repair_admission_transport.py repair_admission_transport.py a5bece68adb2f710fd082d25fad3b09cadd202d31e8bbd2c13f19b5f19d187f5 || return 1
  download tools/semantic_transaction_profiles/build_audited_source_package.py build_audited_source_package.py 785ca8e275e0590b6e63aef904cee65c62e74c72cdf17a128abdaad144880ba7 || return 1
  download evidence/provider-audited-recovery-scope-20261009.json scope.json deb00aad4fd5070f72d45c4b6650444c08baf9054357b3a9eb98b7e2cbb205af || return 1
  OUF_AUDIT_PHASE=EXECUTE_APPROVED_AUDITED_RECOVERY_ONCE
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
' "$OUF_AUDIT_DOWNLOAD/execute.py" "$OUF_AUDIT_EXECUTOR_SHA" "$OUF_AUDIT_APPROVAL" "$OUF_AUDIT_DOWNLOAD"
}
main
OUF_AUDITED_RECOVERY_EXIT=$?
echo "OUF_AUDITED_RECOVERY_EXIT=$OUF_AUDITED_RECOVERY_EXIT PHASE=$OUF_AUDIT_PHASE"
exit "$OUF_AUDITED_RECOVERY_EXIT"
