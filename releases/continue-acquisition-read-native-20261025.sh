#!/usr/bin/env bash
set -euo pipefail
umask 077
directory=$(mktemp -d "$HOME/ouf-acquisition-continuation.XXXXXXXX")
log="$directory/operator.log"
source_commit=a21f5bda87ee7ed2e499338d842cd207ba956b3c
manifest_hash=dc2af88dfe0f1db2d54a0c3ed1a84a868f1b3b8e7ae5b1d6531d3aa27ec233b0
code_root=/etc/ouf/deploy-snapshots/acquisition-read-continuation-code-dc2af88dfe0f1db2
set +e
(
  set -euo pipefail
  for entry in \
    'scripts/continue-acquisition-unapproved-review-20261025.py continuation.py 3b17447956b9740648cf1b087eb296503951ac3642e5d79e8908d7f44c676816' \
    'scripts/apply-acquisition-read-native-20261025.py apply.py ce3166d88b66c4b0a5328e4aa02f50eb46def643a8941a6f8ca01b529c0794a1' \
    'scripts/prepare-acquisition-read-native-execution-20261025.py native_prepare.py f60ab449bb694465d520bfe40d1b992279df7391c8191c341fc43a6e10b11de1' \
    'tools/acquisition_read_native/vendor/runtime_binding_source.py runtime_binding.py 291daecc2b541a7c7410cd9f7c22ec7fccc82568ae67b21b78148f939035c7de' \
    'tools/acquisition_read_native/protocol.py protocol.py 9914db49db03f70244f6ead48b0b1c6f753e7646f43baf5852011ca790d4d723' \
    'tools/acquisition_read_native/transport.py transport.py 775b8d57f46c6f6a1dfb84bae5681a4751fb2a6d4cdac74324e6bac7773ec539' \
    'tools/acquisition_read_native/ports.py ports.py 12f5ecc5f945211b89abfbbea06387fac45b170cb1a6ac0d2780f523438895ed' \
    'tools/acquisition_read_native/quarantine.py quarantine.py 3f52e3cbb733cc024dee465bef1059c2553db5b3a5279a3e34c6baf3d2d1b55f' \
    'tools/acquisition_read_native/recovery_journal.py recovery_journal.py 637c61b270062868d88bec487489b8c5ddcfd367b97413f8a59fe6b82816bc85' \
    'tools/acquisition_read_native/engine_creation.py engine_creation.py 9d6149a0b3331666496583ebbaa9f43ed05d3039e7097861f3bd147f917ab3fb' \
    'tools/acquisition_read_native/plan_helper.py plan_helper.py 09b892a89f7cd7fa31fbc891822445ed09554e9362e397bb9b12b98316e1d8dd' \
    'tools/acquisition_read_native/image_custody.py image_custody.py 5d0fc0edb1ebd9386326eadbbee08f2cf0a9fd1e122940c0661b5ac5e3655ed8' \
    'tools/acquisition_read_native/vendor/semantic_provider_deployment_authentication.py authentication.py 7cb06f7976791abfc1ffac0e9660f3cdf603347f4514cd2bab7f55c6574e251d' \
    'tools/acquisition_read_native/vendor/semantic_provider_deployment_signing.py signing.py 81ad864e90b3efe17d65534ad4b1ccc187e60954f4f5d6244968d7809303a38f' \
    'tools/acquisition_read_native/vendor/semantic_provider_deployment_protocol.py auth_protocol.py cd5aa30c8c806942c53a306e76a641b876e07a12fbbc3c0d106ecf6b94e87a0d' \
    'tools/acquisition_read_native/vendor/semantic_provider_preexec.py auth_preexec.py 95da7f53be88ac0e602e03acbdf6940a719e96a6fedb207693d23f59f0b31015' \
    'tools/acquisition_read_native/vendor/semantic_provider_deployment_producer.py auth_producer.py dbfb365087fb532a0df66f66b6d72be7e04e2df4f31116631beb0b20a9f6f50f'
  do
    read -r path filename checksum <<<"$entry"
    curl --fail --location --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 60 --retry 0 \
      "https://raw.githubusercontent.com/GioNob/ouf-deploy/$source_commit/$path" --output "$directory/$filename"
    printf '%s  %s\n' "$checksum" "$directory/$filename" | sha256sum --check -
  done
  sudo python3 -I -S -B - "$directory" "$code_root" <<'ROOT_COPY'
import hashlib,json,os,stat,sys
from pathlib import Path
source,target=map(Path,sys.argv[1:])
expected={"continuation.py":"3b17447956b9740648cf1b087eb296503951ac3642e5d79e8908d7f44c676816","apply.py":"ce3166d88b66c4b0a5328e4aa02f50eb46def643a8941a6f8ca01b529c0794a1","native_prepare.py":"f60ab449bb694465d520bfe40d1b992279df7391c8191c341fc43a6e10b11de1","runtime_binding.py":"291daecc2b541a7c7410cd9f7c22ec7fccc82568ae67b21b78148f939035c7de","protocol.py":"9914db49db03f70244f6ead48b0b1c6f753e7646f43baf5852011ca790d4d723","transport.py":"775b8d57f46c6f6a1dfb84bae5681a4751fb2a6d4cdac74324e6bac7773ec539","ports.py":"12f5ecc5f945211b89abfbbea06387fac45b170cb1a6ac0d2780f523438895ed","quarantine.py":"3f52e3cbb733cc024dee465bef1059c2553db5b3a5279a3e34c6baf3d2d1b55f","recovery_journal.py":"637c61b270062868d88bec487489b8c5ddcfd367b97413f8a59fe6b82816bc85","engine_creation.py":"9d6149a0b3331666496583ebbaa9f43ed05d3039e7097861f3bd147f917ab3fb","plan_helper.py":"09b892a89f7cd7fa31fbc891822445ed09554e9362e397bb9b12b98316e1d8dd","image_custody.py":"5d0fc0edb1ebd9386326eadbbee08f2cf0a9fd1e122940c0661b5ac5e3655ed8","authentication.py":"7cb06f7976791abfc1ffac0e9660f3cdf603347f4514cd2bab7f55c6574e251d","signing.py":"81ad864e90b3efe17d65534ad4b1ccc187e60954f4f5d6244968d7809303a38f","auth_protocol.py":"cd5aa30c8c806942c53a306e76a641b876e07a12fbbc3c0d106ecf6b94e87a0d","auth_preexec.py":"95da7f53be88ac0e602e03acbdf6940a719e96a6fedb207693d23f59f0b31015","auth_producer.py":"dbfb365087fb532a0df66f66b6d72be7e04e2df4f31116631beb0b20a9f6f50f"}
manifest_hash='dc2af88dfe0f1db2d54a0c3ed1a84a868f1b3b8e7ae5b1d6531d3aa27ec233b0'
def require(ok,reason):
    if not ok:raise SystemExit(reason)
def frame(s):return tuple(getattr(s,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
require(os.geteuid()==os.getegid()==0 and str(target)=='/etc/ouf/deploy-snapshots/acquisition-read-continuation-code-dc2af88dfe0f1db2','ROOT_EXACT_APPLY_SOURCE_TARGET_REQUIRED')
for parent in(target.parent,*target.parent.parents):
    s=parent.lstat();require(stat.S_ISDIR(s.st_mode)and s.st_uid==s.st_gid==0 and not s.st_mode&0o022,'ROOT_SOURCE_ANCESTRY_REQUIRED')
require(not os.path.lexists(target),'SOURCE_TARGET_EXISTS_STOP_RECONCILE')
values={}
for name,checksum in expected.items():
    path=source/name;fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd);require(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and 0<before.st_size<=131072,'BOUNDED_APPLY_SOURCE_REQUIRED');raw=os.read(fd,before.st_size+1)
        require(len(raw)==before.st_size and hashlib.sha256(raw).hexdigest()==checksum and frame(before)==frame(os.fstat(fd))==frame(path.lstat()),'EXACT_UNCHANGED_APPLY_SOURCE_REQUIRED');values[name]=raw
    finally:os.close(fd)
manifest=json.dumps(expected,sort_keys=True,separators=(',',':')).encode()
require(hashlib.sha256(manifest).hexdigest()==manifest_hash,'CLOSED_SOURCE_MANIFEST_REQUIRED')
values['sources.json']=manifest
target.mkdir(mode=0o700)
for name,raw in values.items():
    fd=os.open(target/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
    try:
        with os.fdopen(os.dup(fd),'wb')as out:out.write(raw);out.flush();os.fsync(out.fileno())
    finally:os.close(fd)
for path in(target,target.parent):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
ROOT_COPY
  printf '%s  %s\n' "$manifest_hash" "$code_root/sources.json" | sudo sha256sum --check -
  sudo python3 -I -S -B "$code_root/continuation.py"
) 2>&1 | tee "$log"
rc=${PIPESTATUS[0]}
set -e
printf 'Exit=%s\nDirectory=%s\nLog=%s\n' "$rc" "$directory" "$log"
exit "$rc"
