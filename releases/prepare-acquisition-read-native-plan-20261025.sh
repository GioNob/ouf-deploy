#!/usr/bin/env bash
set -euo pipefail
umask 077
directory=$(mktemp -d "$HOME/ouf-acquisition-plan.XXXXXXXX")
log="$directory/operator.log"
source_commit=294552df5db303e4da299682ef8b3c4094f97d6f
source_hash=6ca60a5e25deaf9c7a718e6ee7fe01dad75b3fb45455129f131309bc988c5acd
code_root=/etc/ouf/deploy-snapshots/acquisition-plan-code-6ca60a5e25deaf9c
set +e
(
  set -euo pipefail
  curl --fail --location --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 60 --retry 0 \
    "https://raw.githubusercontent.com/GioNob/ouf-deploy/$source_commit/scripts/prepare-acquisition-read-native-plan-20261025.py" \
    --output "$directory/prepare.py"
  printf '%s  %s\n' "$source_hash" "$directory/prepare.py" | sha256sum --check -
  sudo python3 -I -S -B - "$directory/prepare.py" "$code_root" "$source_hash" <<'PY'
import hashlib,os,stat,sys
from pathlib import Path
source,destination,expected=Path(sys.argv[1]),Path(sys.argv[2]),sys.argv[3]
def require(ok,code):
    if not ok:raise SystemExit(code)
require(os.geteuid()==os.getegid()==0,'ROOT_COPY_REQUIRED')
require(str(destination)=='/etc/ouf/deploy-snapshots/acquisition-plan-code-'+expected[:16],'EXACT_NEW_CODE_ROOT_REQUIRED')
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
out=os.open(destination/'prepare.py',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
try:
    with os.fdopen(os.dup(out),'wb')as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
finally:os.close(out)
parent=os.open(destination,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
try:os.fsync(parent)
finally:os.close(parent)
PY
  printf '%s  %s\n' "$source_hash" "$code_root/prepare.py" | sudo sha256sum --check -
  sudo python3 -I -S -B "$code_root/prepare.py"
) 2>&1 | tee "$log"
result=${PIPESTATUS[0]}
set -e
printf 'Exit=%s\nDirectory=%s\nLog=%s\n' "$result" "$directory" "$log"
exit "$result"
