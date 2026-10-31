#!/usr/bin/env bash
set -euo pipefail
umask 077
directory=$(mktemp -d "$HOME/ouf-acquisition-native-inputs.XXXXXXXX")
log="$directory/operator.log"
source_commit=805b65477ce62387cafcdb5f233b2dbd894a2cad
main_hash=f60ab449bb694465d520bfe40d1b992279df7391c8191c341fc43a6e10b11de1
code_root=/etc/ouf/deploy-snapshots/acquisition-native-input-code-f60ab449bb694465
set +e
(
  set -euo pipefail
  for entry in \
    'scripts/prepare-acquisition-read-native-execution-20261025.py prepare.py f60ab449bb694465d520bfe40d1b992279df7391c8191c341fc43a6e10b11de1' \
    'tools/acquisition_read_native/plan_helper.py plan_helper.py 09b892a89f7cd7fa31fbc891822445ed09554e9362e397bb9b12b98316e1d8dd' \
    'tools/acquisition_read_native/image_custody.py image_custody.py 5d0fc0edb1ebd9386326eadbbee08f2cf0a9fd1e122940c0661b5ac5e3655ed8'
  do
    read -r path filename checksum <<<"$entry"
    curl --fail --location --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 60 --retry 0 \
      "https://raw.githubusercontent.com/GioNob/ouf-deploy/$source_commit/$path" --output "$directory/$filename"
    printf '%s  %s\n' "$checksum" "$directory/$filename" | sha256sum --check -
  done
  sudo python3 -I -S -B - "$directory" "$code_root" <<'ROOT_COPY'
import hashlib,os,stat,sys
from pathlib import Path
source,target=map(Path,sys.argv[1:]);expected={'prepare.py':'f60ab449bb694465d520bfe40d1b992279df7391c8191c341fc43a6e10b11de1','plan_helper.py':'09b892a89f7cd7fa31fbc891822445ed09554e9362e397bb9b12b98316e1d8dd','image_custody.py':'5d0fc0edb1ebd9386326eadbbee08f2cf0a9fd1e122940c0661b5ac5e3655ed8'}
def require(ok,reason):
    if not ok:raise SystemExit(reason)
def frame(s):return tuple(getattr(s,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
require(os.geteuid()==os.getegid()==0 and str(target)=='/etc/ouf/deploy-snapshots/acquisition-native-input-code-f60ab449bb694465','ROOT_EXACT_NATIVE_SOURCE_TARGET_REQUIRED')
for parent in(target.parent,*target.parent.parents):
    s=parent.lstat();require(stat.S_ISDIR(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022,'ROOT_SOURCE_ANCESTRY_REQUIRED')
require(not os.path.lexists(target),'SOURCE_TARGET_EXISTS_STOP_RECONCILE');values={}
for name,checksum in expected.items():
    path=source/name;fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        s=os.fstat(fd);require(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and 0<s.st_size<=65536,'BOUNDED_SOURCE_FILE_REQUIRED');raw=os.read(fd,s.st_size+1)
        require(len(raw)==s.st_size and hashlib.sha256(raw).hexdigest()==checksum and frame(s)==frame(os.fstat(fd))==frame(path.lstat()),'EXACT_UNCHANGED_SOURCE_REQUIRED');values[name]=raw
    finally:os.close(fd)
target.mkdir(mode=0o700)
for name,raw in values.items():
    fd=os.open(target/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
    try:
        with os.fdopen(os.dup(fd),'wb')as out:out.write(raw);out.flush();os.fsync(out.fileno())
    finally:os.close(fd)
fd=os.open(target,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
try:os.fsync(fd)
finally:os.close(fd)
ROOT_COPY
  printf '%s  %s\n' "$main_hash" "$code_root/prepare.py" | sudo sha256sum --check -
  sudo python3 -I -S -B "$code_root/prepare.py"
) 2>&1 | tee "$log"
rc=${PIPESTATUS[0]}
set -e
printf 'Exit=%s\nDirectory=%s\nLog=%s\n' "$rc" "$directory" "$log"
exit "$rc"
