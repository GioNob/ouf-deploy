#!/usr/bin/env bash
set -euo pipefail
umask 077
directory=$(mktemp -d "$HOME/ouf-acquisition-old-mcp-guard.XXXXXXXX")
log="$directory/operator.log"
code_root=/etc/ouf/deploy-snapshots/acquisition-old-mcp-guard-code-34a0567d5774e061
set +e
(
  set -euo pipefail
  curl --fail --location --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 60 --retry 0 \
    'https://raw.githubusercontent.com/GioNob/ouf-deploy/3de2eff5506917519e3837f36ae05dffa9af1d36/scripts/read-acquisition-old-mcp-guard-20261025.py' \
    --output "$directory/read.py"
  printf '%s  %s\n' '34a0567d5774e0610e8a3afa87dfcbc1097a22b7027dd80451b607b5fc72744d' "$directory/read.py" | sha256sum --check -
  sudo python3 -I -S -B - "$directory/read.py" "$code_root" <<'ROOT_COPY'
import hashlib,os,stat,sys
from pathlib import Path
source,target=map(Path,sys.argv[1:])
def require(ok,reason):
    if not ok:raise SystemExit(reason)
def frame(v):return tuple(getattr(v,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
require(os.geteuid()==os.getegid()==0 and str(target)=='/etc/ouf/deploy-snapshots/acquisition-old-mcp-guard-code-34a0567d5774e061','EXACT_ROOT_READER_CODE_TARGET_REQUIRED')
for parent in(target.parent,*target.parent.parents):
    s=parent.lstat();require(stat.S_ISDIR(s.st_mode)and s.st_uid==s.st_gid==0 and not s.st_mode&0o022,'ROOT_READER_CODE_ANCESTRY_REQUIRED')
require(not os.path.lexists(target),'READER_CODE_SCOPE_EXISTS_STOP_RECONCILE')
fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
try:
    before=os.fstat(fd);require(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and 0<before.st_size<=131072,'BOUNDED_REGULAR_READER_SOURCE_REQUIRED');raw=os.read(fd,before.st_size+1)
    require(len(raw)==before.st_size and hashlib.sha256(raw).hexdigest()=='34a0567d5774e0610e8a3afa87dfcbc1097a22b7027dd80451b607b5fc72744d'and frame(before)==frame(os.fstat(fd))==frame(source.lstat()),'EXACT_UNCHANGED_READER_SOURCE_REQUIRED')
finally:os.close(fd)
target.mkdir(mode=0o700)
fd=os.open(target/'read.py',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
try:
    with os.fdopen(os.dup(fd),'wb')as out:out.write(raw);out.flush();os.fsync(out.fileno())
finally:os.close(fd)
for path in(target,target.parent):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
ROOT_COPY
  printf '%s  %s\n' '34a0567d5774e0610e8a3afa87dfcbc1097a22b7027dd80451b607b5fc72744d' "$code_root/read.py" | sudo sha256sum --check -
  sudo python3 -I -S -B "$code_root/read.py"
) 2>&1 | tee "$log"
rc=${PIPESTATUS[0]}
set -e
printf 'Exit=%s\nDirectory=%s\nLog=%s\n' "$rc" "$directory" "$log"
exit "$rc"
