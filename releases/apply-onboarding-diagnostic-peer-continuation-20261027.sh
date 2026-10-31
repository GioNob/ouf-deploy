#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
operator_uid=$(id -u)
if [[ $operator_uid == 0 ]]; then printf '%s\n' 'STOP: eseguire come oufadmin, non root.'; exit 2; fi
delivery=$(mktemp -d "${HOME}/ouf-onboarding-peer-continuation-delivery.XXXXXXXX")
chmod 0700 "$delivery"
delivery_log="$delivery/bootstrap.log"
trap 'delivery_exit=$?; trap - EXIT; printf "DeliveryExit=%s\nDeliveryDirectory=%s\nDeliveryLog=%s\n" "$delivery_exit" "$delivery" "$delivery_log" | tee -a "$delivery_log"; exit "$delivery_exit"' EXIT
code_commit=0e5be010ee37479a49500afb70bbf13b26b40e8a
manifest_sha=d65d48b2da52ef456b0db3cf1807e907983da87fd2100597cb0185c7714bdbce
code_root=/usr/local/lib/ouf-onboarding-diagnostic-update-d65d48b2da52ef45
printf '%s' '{"auth_preexec.py":"95da7f53be88ac0e602e03acbdf6940a719e96a6fedb207693d23f59f0b31015","auth_producer.py":"dbfb365087fb532a0df66f66b6d72be7e04e2df4f31116631beb0b20a9f6f50f","auth_protocol.py":"cd5aa30c8c806942c53a306e76a641b876e07a12fbbc3c0d106ecf6b94e87a0d","authentication.py":"7cb06f7976791abfc1ffac0e9660f3cdf603347f4514cd2bab7f55c6574e251d","authority.py":"12f3ac78dbc34e67e2fd3817470d823460bc2de0f28a56bfc2fe952066830bdc","context.py":"2a3a03501a271226b14f1089ee7ecbbc29316ca6c02a2703e542cb75a46d1a52","database.py":"85e34d9788fb9f0d213ec3f06a8c6ea59acbca612a9f1a97dcbc1afaa4d0335b","engine_creation.py":"9d6149a0b3331666496583ebbaa9f43ed05d3039e7097861f3bd147f917ab3fb","entry.py":"d919a1e52915a29567d45c69804edd49e6a0542f52ae06f9f665c6eeecabc3aa","image_custody.py":"5d0fc0edb1ebd9386326eadbbee08f2cf0a9fd1e122940c0661b5ac5e3655ed8","migration-fence.json":"9b25299a8939dc5354d5ab688ebf1816576b531e4ed672bf944ca4d67fe50c11","plan_helper.py":"09b892a89f7cd7fa31fbc891822445ed09554e9362e397bb9b12b98316e1d8dd","ports.py":"2fb56388c3a9ce219ce3e15eccdfcbaeffdf5c0708596d4566fda90854087554","quarantine.py":"592639a3ea2dba5788653e7f00f3fe4fbaeadd823287136a5a122c164c696d42","recovery_journal.py":"8050144514a60ba19e71650bb8320887fe1be763a333058c21d6e2c3a789a162","retained_mac.py":"cb5dbbee4a80ce71860dfe5d32362a662d98898c58fd82009e69c5eb6ac1f7ce","runtime_binding.py":"291daecc2b541a7c7410cd9f7c22ec7fccc82568ae67b21b78148f939035c7de","signing.py":"81ad864e90b3efe17d65534ad4b1ccc187e60954f4f5d6244968d7809303a38f","state_fence.py":"79fd075e3a8e3682116df641fdab74decebe480523ae42b31efc17e5c891d597","terminal.py":"3e698faea1e933b9ce04ad7ed204ed44b60863ad8fac620385c37a10179bfbf5","transport.py":"3fc1f9243f739f47403ee8f6e8eec0d9a731160e9530b75e4a4c44055d8596dd"}' > "$delivery/sources.json"
printf '%s  %s\n' "$manifest_sha" "$delivery/sources.json" | sha256sum -c - | tee -a "$delivery_log"
while read -r name path checksum; do
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 3 --connect-timeout 15 --max-time 60 --max-filesize 131072 \
    "https://raw.githubusercontent.com/GioNob/ouf-deploy/${code_commit}/${path}" -o "$delivery/$name"
  printf '%s  %s\n' "$checksum" "$delivery/$name" | sha256sum -c - | tee -a "$delivery_log"
done <<'SOURCES'
entry.py scripts/apply-onboarding-diagnostic-update-20261027.py d919a1e52915a29567d45c69804edd49e6a0542f52ae06f9f665c6eeecabc3aa
authority.py tools/onboarding_diagnostic_update/authority.py 12f3ac78dbc34e67e2fd3817470d823460bc2de0f28a56bfc2fe952066830bdc
context.py tools/onboarding_diagnostic_update/context.py 2a3a03501a271226b14f1089ee7ecbbc29316ca6c02a2703e542cb75a46d1a52
transport.py tools/onboarding_diagnostic_update/transport.py 3fc1f9243f739f47403ee8f6e8eec0d9a731160e9530b75e4a4c44055d8596dd
ports.py tools/onboarding_diagnostic_update/ports.py 2fb56388c3a9ce219ce3e15eccdfcbaeffdf5c0708596d4566fda90854087554
quarantine.py tools/onboarding_diagnostic_update/quarantine.py 592639a3ea2dba5788653e7f00f3fe4fbaeadd823287136a5a122c164c696d42
state_fence.py tools/onboarding_diagnostic_update/state_fence.py 79fd075e3a8e3682116df641fdab74decebe480523ae42b31efc17e5c891d597
database.py tools/onboarding_diagnostic_update/database.py 85e34d9788fb9f0d213ec3f06a8c6ea59acbca612a9f1a97dcbc1afaa4d0335b
recovery_journal.py tools/acquisition_read_native/recovery_journal.py 8050144514a60ba19e71650bb8320887fe1be763a333058c21d6e2c3a789a162
engine_creation.py tools/acquisition_read_native/engine_creation.py 9d6149a0b3331666496583ebbaa9f43ed05d3039e7097861f3bd147f917ab3fb
plan_helper.py tools/acquisition_read_native/plan_helper.py 09b892a89f7cd7fa31fbc891822445ed09554e9362e397bb9b12b98316e1d8dd
image_custody.py tools/acquisition_read_native/image_custody.py 5d0fc0edb1ebd9386326eadbbee08f2cf0a9fd1e122940c0661b5ac5e3655ed8
retained_mac.py tools/acquisition_read_native/retained_mac.py cb5dbbee4a80ce71860dfe5d32362a662d98898c58fd82009e69c5eb6ac1f7ce
migration-fence.json releases/onboarding-diagnostic-migration-fence-20261027.json 9b25299a8939dc5354d5ab688ebf1816576b531e4ed672bf944ca4d67fe50c11
terminal.py tools/human_terminal_line_review.py 3e698faea1e933b9ce04ad7ed204ed44b60863ad8fac620385c37a10179bfbf5
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
require(os.geteuid()==os.getegid()==0 and owner>0 and expected=='d65d48b2da52ef456b0db3cf1807e907983da87fd2100597cb0185c7714bdbce','ROOT_PINNED_CODE_COPY_REQUIRED')
require(not os.path.lexists('/etc/ouf/deploy-snapshots/onboarding-diagnostic-update-c22586172070809d-v1/retained-peer-credentials-continuation-v1'),'ONBOARDING_UPDATE_SCOPE_CONSUMED_NO_REPLAY')
target=Path('/usr/local/lib/ouf-onboarding-diagnostic-update-d65d48b2da52ef45')
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
required={'auth_preexec.py','auth_producer.py','auth_protocol.py','authentication.py','authority.py','context.py','database.py','engine_creation.py','entry.py','image_custody.py','migration-fence.json','plan_helper.py','ports.py','quarantine.py','recovery_journal.py','retained_mac.py','runtime_binding.py','signing.py','state_fence.py','terminal.py','transport.py'}
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
print('SourceClosure=OK (21 fonti e manifest root0400; checksum eseguiti root)')
PY
printf '%s\n' 'CONTINUAZIONE del SOLO Onboarding dopo STOP riconciliato senza effetti. Tre metadataread originali cumulativi, profilo storico intatto e peer corrente verificato. Review privata e APPROVO fresco nel terminale; nessun consenso passato dal wrapper.' | tee -a "$delivery_log"
# Interactive sudo stays directly attached to the terminal. Runtime logs itself.
set +e
sudo /usr/bin/python3 -I -S -B "$code_root/entry.py"
runtime_exit=$?
set -e
printf 'Exit=%s\nDirectory=%s\nLog=%s\n' "$runtime_exit" "$delivery" "$code_root/operator.log" | tee -a "$delivery_log"
exit "$runtime_exit"

