#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
operator_uid=$(id -u)
if [[ $operator_uid == 0 ]]; then printf '%s\n' 'STOP: eseguire come oufadmin, non root.'; exit 2; fi
delivery=$(mktemp -d "${HOME}/ouf-onboarding-profile-v36-apply-delivery.XXXXXXXX")
chmod 0700 "$delivery"
delivery_log="$delivery/bootstrap.log"
trap 'delivery_exit=$?; trap - EXIT; printf "DeliveryExit=%s\nDeliveryDirectory=%s\nDeliveryLog=%s\n" "$delivery_exit" "$delivery" "$delivery_log" | tee -a "$delivery_log"; exit "$delivery_exit"' EXIT
code_commit=e5410467a410188a3b7ee7ae3264c7b0782f7b4a
manifest_sha=a46b19156c35cb915b0842e52a72a97bac691c0cd64676aaaa704eb285793cc2
code_root=/usr/local/lib/ouf-onboarding-profile-recovery-update-a46b19156c35cb91
printf '%s' '{"auth_preexec.py":"95da7f53be88ac0e602e03acbdf6940a719e96a6fedb207693d23f59f0b31015","auth_producer.py":"dbfb365087fb532a0df66f66b6d72be7e04e2df4f31116631beb0b20a9f6f50f","auth_protocol.py":"cd5aa30c8c806942c53a306e76a641b876e07a12fbbc3c0d106ecf6b94e87a0d","authentication.py":"7cb06f7976791abfc1ffac0e9660f3cdf603347f4514cd2bab7f55c6574e251d","authority.py":"6f3517ba8feb57c007832848b54eb9d7b63d4a5cf1e007a7286c427d4efe3f80","backup.py":"2ba21542461887d206ee153599618357e7d061ea0c6524a635ebe57a62a5b2a9","configuration.py":"d3bb5a29d4e0e626cd34c797326e868050c3c16421901357faa8c73b48e83018","context.py":"2333fecb92a20ca2d6d041087045f07f604aeab50fd66240483a63350bd66b36","database.py":"973e7f786fbf81fa9856361276e1eeb4b38a9e4b46ea521b84f73f3232c9741e","engine_creation.py":"9d6149a0b3331666496583ebbaa9f43ed05d3039e7097861f3bd147f917ab3fb","entry.py":"a61b4e0e6dd416d65bf786e224150885b48237994dcdaf55f5bbb3f0acc8b873","image_custody.py":"5d0fc0edb1ebd9386326eadbbee08f2cf0a9fd1e122940c0661b5ac5e3655ed8","migration-fence.json":"77b9aa85288b405db00a7af5d0287e83e02bfbc49794d4cc32406bfcb742bf57","plan_helper.py":"09b892a89f7cd7fa31fbc891822445ed09554e9362e397bb9b12b98316e1d8dd","ports.py":"6d42d305815acc9f1735ca40e829a32c22d82f67e48d19ae8cc07b35e7c20f10","quarantine.py":"592639a3ea2dba5788653e7f00f3fe4fbaeadd823287136a5a122c164c696d42","recovery_journal.py":"8050144514a60ba19e71650bb8320887fe1be763a333058c21d6e2c3a789a162","retained_mac.py":"cb5dbbee4a80ce71860dfe5d32362a662d98898c58fd82009e69c5eb6ac1f7ce","runtime_binding.py":"291daecc2b541a7c7410cd9f7c22ec7fccc82568ae67b21b78148f939035c7de","signing.py":"81ad864e90b3efe17d65534ad4b1ccc187e60954f4f5d6244968d7809303a38f","state_fence.py":"3acf0e82bf75333a65bd6ec613851b051d6ad20eeab52b848af60b24d9d79173","terminal.py":"3e698faea1e933b9ce04ad7ed204ed44b60863ad8fac620385c37a10179bfbf5","transport.py":"3fc1f9243f739f47403ee8f6e8eec0d9a731160e9530b75e4a4c44055d8596dd"}' > "$delivery/sources.json"
printf '%s  %s\n' "$manifest_sha" "$delivery/sources.json" | sha256sum -c - | tee -a "$delivery_log"
transport_started=$SECONDS
while read -r name path checksum; do
  remaining=$((300 - SECONDS + transport_started))
  if (( remaining <= 0 )); then printf '%s\n' 'STOP: download finito; conservare log e non rilanciare.'; exit 2; fi
  transfer_limit=60
  if (( remaining < transfer_limit )); then transfer_limit=$remaining; fi
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 3 --connect-timeout 15 --max-time "$transfer_limit" --max-filesize 131072 \
    "https://raw.githubusercontent.com/GioNob/ouf-deploy/${code_commit}/${path}" -o "$delivery/$name"
  printf '%s  %s\n' "$checksum" "$delivery/$name" | sha256sum -c - | tee -a "$delivery_log"
done <<'SOURCES'
entry.py scripts/apply-onboarding-profile-recovery-update-20261027.py a61b4e0e6dd416d65bf786e224150885b48237994dcdaf55f5bbb3f0acc8b873
authority.py tools/onboarding_profile_recovery_update/authority.py 6f3517ba8feb57c007832848b54eb9d7b63d4a5cf1e007a7286c427d4efe3f80
context.py tools/onboarding_profile_recovery_update/context.py 2333fecb92a20ca2d6d041087045f07f604aeab50fd66240483a63350bd66b36
transport.py tools/onboarding_profile_recovery_update/transport.py 3fc1f9243f739f47403ee8f6e8eec0d9a731160e9530b75e4a4c44055d8596dd
ports.py tools/onboarding_profile_recovery_update/ports.py 6d42d305815acc9f1735ca40e829a32c22d82f67e48d19ae8cc07b35e7c20f10
quarantine.py tools/onboarding_profile_recovery_update/quarantine.py 592639a3ea2dba5788653e7f00f3fe4fbaeadd823287136a5a122c164c696d42
state_fence.py tools/onboarding_profile_recovery_update/state_fence.py 3acf0e82bf75333a65bd6ec613851b051d6ad20eeab52b848af60b24d9d79173
database.py tools/onboarding_profile_recovery_update/database.py 973e7f786fbf81fa9856361276e1eeb4b38a9e4b46ea521b84f73f3232c9741e
backup.py tools/onboarding_profile_recovery_update/backup.py 2ba21542461887d206ee153599618357e7d061ea0c6524a635ebe57a62a5b2a9
recovery_journal.py tools/acquisition_read_native/recovery_journal.py 8050144514a60ba19e71650bb8320887fe1be763a333058c21d6e2c3a789a162
engine_creation.py tools/acquisition_read_native/engine_creation.py 9d6149a0b3331666496583ebbaa9f43ed05d3039e7097861f3bd147f917ab3fb
plan_helper.py tools/acquisition_read_native/plan_helper.py 09b892a89f7cd7fa31fbc891822445ed09554e9362e397bb9b12b98316e1d8dd
image_custody.py tools/acquisition_read_native/image_custody.py 5d0fc0edb1ebd9386326eadbbee08f2cf0a9fd1e122940c0661b5ac5e3655ed8
retained_mac.py tools/acquisition_read_native/retained_mac.py cb5dbbee4a80ce71860dfe5d32362a662d98898c58fd82009e69c5eb6ac1f7ce
migration-fence.json releases/onboarding-profile-recovery-migration-fence-20261027.json 77b9aa85288b405db00a7af5d0287e83e02bfbc49794d4cc32406bfcb742bf57
terminal.py tools/human_terminal_line_review.py 3e698faea1e933b9ce04ad7ed204ed44b60863ad8fac620385c37a10179bfbf5
configuration.py tools/source_revision_update/configuration.py d3bb5a29d4e0e626cd34c797326e868050c3c16421901357faa8c73b48e83018
authentication.py tools/acquisition_read_native/vendor/semantic_provider_deployment_authentication.py 7cb06f7976791abfc1ffac0e9660f3cdf603347f4514cd2bab7f55c6574e251d
signing.py tools/acquisition_read_native/vendor/semantic_provider_deployment_signing.py 81ad864e90b3efe17d65534ad4b1ccc187e60954f4f5d6244968d7809303a38f
auth_protocol.py tools/acquisition_read_native/vendor/semantic_provider_deployment_protocol.py cd5aa30c8c806942c53a306e76a641b876e07a12fbbc3c0d106ecf6b94e87a0d
auth_preexec.py tools/acquisition_read_native/vendor/semantic_provider_preexec.py 95da7f53be88ac0e602e03acbdf6940a719e96a6fedb207693d23f59f0b31015
auth_producer.py tools/acquisition_read_native/vendor/semantic_provider_deployment_producer.py dbfb365087fb532a0df66f66b6d72be7e04e2df4f31116631beb0b20a9f6f50f
runtime_binding.py tools/acquisition_read_native/vendor/runtime_binding_source.py 291daecc2b541a7c7410cd9f7c22ec7fccc82568ae67b21b78148f939035c7de
SOURCES
sudo /usr/bin/python3 -I -S -B - "$delivery" "$operator_uid" "$manifest_sha" <<'PY' 2>&1 | tee -a "$delivery_log"
import hashlib,json,os,stat,sys
from pathlib import Path
source,owner,expected=Path(sys.argv[1]),int(sys.argv[2]),sys.argv[3]
def require(ok,code):
    if not ok:raise SystemExit(code)
require(os.geteuid()==os.getegid()==0 and owner>0 and expected=='a46b19156c35cb915b0842e52a72a97bac691c0cd64676aaaa704eb285793cc2','ROOT_PINNED_CODE_COPY_REQUIRED')
require(not os.path.lexists('/etc/ouf/deploy-snapshots/onboarding-profile-recovery-v36-apply-564038c5d487f0a4-v1'),'ONBOARDING_UPDATE_SCOPE_CONSUMED_NO_REPLAY')
target=Path('/usr/local/lib/ouf-onboarding-profile-recovery-update-a46b19156c35cb91')
for parent in(target.parent,*target.parent.parents):
    s=parent.lstat();require(stat.S_ISDIR(s.st_mode)and s.st_uid==s.st_gid==0 and not s.st_mode&0o022,'ROOT_CODE_ANCESTRY_REQUIRED')
require(not os.path.lexists(target),'ONBOARDING_CODE_SCOPE_EXISTS_STOP_RECONCILE')
frame=lambda s:tuple(getattr(s,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def read(name):
    path=source/name;fd=os.open(path,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW)
    try:
        before=os.fstat(fd);require(stat.S_ISREG(before.st_mode)and before.st_uid==owner and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o600 and 0<before.st_size<=131072,'BOUNDED_OWNER_DOWNLOADED_SOURCE_REQUIRED')
        raw=os.read(fd,131073);require(len(raw)==before.st_size and frame(before)==frame(os.fstat(fd))==frame(path.lstat()),'DOWNLOADED_SOURCE_CHANGED');return raw
    finally:os.close(fd)
raw=read('sources.json');require(hashlib.sha256(raw).hexdigest()==expected,'SOURCE_MANIFEST_BYTES_CHANGED')
def unique(rows):
    out={}
    for k,v in rows:require(k not in out,'DUPLICATE_SOURCE_KEY');out[k]=v
    return out
manifest=json.loads(raw,object_pairs_hook=unique)
required={'entry.py','authority.py','context.py','transport.py','ports.py','quarantine.py','state_fence.py','database.py','backup.py','recovery_journal.py','engine_creation.py','plan_helper.py','image_custody.py','retained_mac.py','migration-fence.json','terminal.py','configuration.py','authentication.py','signing.py','auth_protocol.py','auth_preexec.py','auth_producer.py','runtime_binding.py'}
require(type(manifest)is dict and set(manifest)==required,'EXACT_ONBOARDING_SOURCE_CLOSURE_REQUIRED')
content={'sources.json':raw}
for name,digest in manifest.items():
    value=read(name);require(hashlib.sha256(value).hexdigest()==digest,'EXACT_DOWNLOADED_SOURCE_DIGEST_REQUIRED');content[name]=value
target.mkdir(mode=0o700);target.chmod(0o700)
for name,value in content.items():
    fd=os.open(target/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
    with os.fdopen(fd,'wb')as out:
        os.fchmod(out.fileno(),0o400);out.write(value);out.flush();os.fsync(out.fileno())
for parent in(target,target.parent):
    fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
for name,value in content.items():
    fd=os.open(target/name,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        s=os.fstat(fd);require(s.st_uid==s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o400 and os.read(fd,131073)==value,'ROOT_CODE_CHECKSUM_OR_MODE_REQUIRED')
    finally:os.close(fd)
print('ProtectedCode='+str(target/'entry.py'))
print('SourceClosure=OK (23 fonti e manifest root0400; checksum eseguiti root)')
PY
printf '%s\n' 'NUOVA manutenzione SOLO Onboarding V35->V36: verifica metadata e configurazione correnti, poi review privata e APPROVO fresco nel terminale. Backup quiescente verificato; nessun nuovo budget di profiling o job. Nessun consenso passato dal wrapper.' | tee -a "$delivery_log"
# Interactive sudo stays directly attached to the terminal. Runtime logs itself.
set +e
sudo /usr/bin/python3 -I -S -B "$code_root/entry.py"
runtime_exit=$?
set -e
printf 'Exit=%s\nDirectory=%s\nLog=%s\n' "$runtime_exit" "$delivery" "$code_root/operator.log" | tee -a "$delivery_log"
exit "$runtime_exit"

