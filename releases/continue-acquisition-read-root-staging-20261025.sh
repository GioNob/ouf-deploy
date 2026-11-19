#!/usr/bin/env bash
set -euo pipefail
umask 077
directory=/home/oufadmin/ouf-acquisition-packages.RecOgcbn
download_directory=/home/oufadmin/ouf-deploy-runner/_work/ouf-deploy/ouf-acquisition-read-transport-2f9a2336572e1bbc
source_hash=f2301a02b01730c41d5db85ac96d2da9eaabf94319e4d73020296848e4040bdf
code_root=/etc/ouf/deploy-snapshots/acquisition-package-code-f2301a02b01730c4
if [[ ! -d "$directory" || -L "$directory" || ! -d "$download_directory" || -L "$download_directory" ]]; then
  printf 'Status=STOP_RECONCILE\nReasonCode=RETAINED_DELIVERY_DIRECTORIES_REQUIRED\nRootStagingInvoked=false\n'
  exit 2
fi
log=$(mktemp "$directory/root-staging-continuation.XXXXXXXX.log")
set +e
(
  set -euo pipefail
  printf '%s  %s\n' "$source_hash" "$directory/stage.py" | sha256sum --check -
  python3 -I -S -B - "$download_directory" <<'PYMETA'
import os,stat,sys
from pathlib import Path
root=Path(sys.argv[1])
expected={'ingestion': 140853808, 'udp': 122368069, 'mcp': 9616803, 'gateway': 84613}
for role,size in expected.items():
    path=root/(role+'.zip');value=path.lstat()
    if not(stat.S_ISREG(value.st_mode)and value.st_nlink==1 and value.st_uid==os.geteuid()and value.st_size==size):
        raise SystemExit('EXACT_REGULAR_RUNNER_ARCHIVE_REQUIRED')
PYMETA
  printf '%s  %s\n' 'db1db79a1d4f5efd37004bc9ddb84789269b361a8278f991a21ddabdbc331ac9' "$download_directory/ingestion.zip" | sha256sum --check -
  printf '%s  %s\n' 'c38246d7bc5a6fdb16482b06fc19521f1c58ca652dac1f7ea69fe29f513c2412' "$download_directory/udp.zip" | sha256sum --check -
  printf '%s  %s\n' '9a4d629d729f30853ca9902e40c9c2474f6e9ea538fcb306eb3b955db106e860' "$download_directory/mcp.zip" | sha256sum --check -
  printf '%s  %s\n' 'dfcf3426786b5f371346ea5f4c5c64d8f1e47409000b784d23ccb47028c6e01d' "$download_directory/gateway.zip" | sha256sum --check -
  sudo python3 -I -S -B - "$directory/stage.py" "$code_root" "$source_hash" <<'PY'
import hashlib,os,stat,sys
from pathlib import Path
source,destination,expected=Path(sys.argv[1]),Path(sys.argv[2]),sys.argv[3]
def require(ok,code):
    if not ok:raise SystemExit(code)
require(os.geteuid()==os.getegid()==0,'ROOT_COPY_REQUIRED')
require(str(destination)=='/etc/ouf/deploy-snapshots/acquisition-package-code-'+expected[:16],'EXACT_NEW_CODE_ROOT_REQUIRED')
for parent in(destination.parent,*destination.parent.parents):
    s=parent.lstat();require(stat.S_ISDIR(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022,'ROOT_CODE_ANCESTRY_REQUIRED')
fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
try:
    before=os.fstat(fd);require(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and 0<before.st_size<=65536,'BOUNDED_SOURCE_REQUIRED')
    raw=os.read(fd,before.st_size+1)
    require(len(raw)==before.st_size and hashlib.sha256(raw).hexdigest()==expected,'PINNED_SOURCE_HASH_REQUIRED')
    after=os.fstat(fd)
    require(all(getattr(before,k)==getattr(after,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')),'SOURCE_CHANGED_DURING_COPY')
finally:os.close(fd)
require(not os.path.lexists(destination),'CODE_ROOT_EXISTS_STOP_RECONCILE')
destination.mkdir(mode=0o700)
out=os.open(destination/'stage.py',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
try:
    with os.fdopen(os.dup(out),'wb')as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
finally:os.close(out)
parent=os.open(destination,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
try:os.fsync(parent)
finally:os.close(parent)
PY
  printf '%s  %s\n' "$source_hash" "$code_root/stage.py" | sudo sha256sum --check -
  sudo python3 -I -S -B "$code_root/stage.py" "$download_directory"
) 2>&1 | tee "$log"
result=${PIPESTATUS[0]}
set -e
printf 'Exit=%s\nDirectory=%s\nLog=%s\nPriorOperatorLog=%s\n' "$result" "$directory" "$log" "$directory/operator.log"
exit "$result"
