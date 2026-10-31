#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
operator_uid=$(id -u)
if [[ $operator_uid == 0 ]]; then printf '%s\n' 'STOP: eseguire come oufadmin, non root.'; exit 2; fi
delivery=$(mktemp -d "$HOME/ouf-mcp-host-policy-read-delivery.XXXXXXXX")
chmod 0700 "$delivery"
log="$delivery/bootstrap.log"
trap 'rc=$?; trap - EXIT; printf "DeliveryExit=%s\nDeliveryDirectory=%s\nDeliveryLog=%s\n" "$rc" "$delivery" "$log" | tee -a "$log"; exit "$rc"' EXIT
digest=e558c0c2ff2b80b1db91d24323e2c57af8126ab8fc1193fd245b6f2cf46d37ad
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 3 --connect-timeout 15 --max-time 60 --max-filesize 131072 \
  'https://raw.githubusercontent.com/GioNob/ouf-deploy/736a8d26bea92cef1af707f686da536970273529/scripts/read-mcp-host-policy-stop-20261026.py' -o "$delivery/read.py"
printf '%s  %s\n' "$digest" "$delivery/read.py" | sha256sum -c - | tee -a "$log"
sudo /usr/bin/python3 -I -S -B - "$delivery/read.py" "$operator_uid" <<'PY' 2>&1 | tee -a "$log"
import hashlib,os,stat,sys
from pathlib import Path
def require(ok,code):
    if not ok:raise SystemExit(code)
require(os.geteuid()==os.getegid()==0,'ROOT_COPY_REQUIRED')
target=Path('/usr/local/lib/ouf-mcp-host-policy-stop-read-e558c0c2ff2b80b1')
for parent in(target.parent,*target.parent.parents):
    s=parent.lstat();require(stat.S_ISDIR(s.st_mode)and s.st_uid==s.st_gid==0 and not s.st_mode&0o022,'ROOT_COPY_ANCESTRY_REQUIRED')
require(not os.path.lexists(target)and not os.path.lexists('/etc/ouf/deploy-snapshots/mcp-host-policy-stop-read-ff06ec1a-v1'),'RETAINED_READ_SCOPE_CONSUMED_NO_REPLAY')
source=Path(sys.argv[1]);fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
frame=lambda s:tuple(getattr(s,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
try:
    s=os.fstat(fd);require(stat.S_ISREG(s.st_mode)and s.st_uid==int(sys.argv[2])>0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and 0<s.st_size<=131072,'BOUNDED_OPERATOR_SOURCE_REQUIRED')
    raw=os.read(fd,131073);require(len(raw)==s.st_size and frame(s)==frame(os.fstat(fd))==frame(source.lstat())and hashlib.sha256(raw).hexdigest()=='e558c0c2ff2b80b1db91d24323e2c57af8126ab8fc1193fd245b6f2cf46d37ad','EXACT_ROOT_VERIFIED_READ_SOURCE_REQUIRED')
finally:os.close(fd)
target.mkdir(mode=0o700);target.chmod(0o700);path=target/'read.py'
fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
with os.fdopen(fd,'wb')as out:os.fchmod(out.fileno(),0o400);out.write(raw);out.flush();os.fsync(out.fileno())
for folder in(target,target.parent):
    fd=os.open(folder,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
try:
    s=os.fstat(fd);require(s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o400 and s.st_nlink==1 and os.read(fd,131073)==raw,'PROTECTED_READ_SOURCE_CHECKSUM_REQUIRED')
finally:os.close(fd)
print('ProtectedCode='+str(path));print('SourceChecksum=OK (root0400; checksum eseguito root)')
PY
printf '%s\n' 'Sola lettura di nove file conservati. Nessun Engine/OAuth/chiave/credenziale; nessun APPROVO o effetto runtime.' | tee -a "$log"
set +e
sudo /usr/bin/python3 -I -S -B /usr/local/lib/ouf-mcp-host-policy-stop-read-e558c0c2ff2b80b1/read.py 2>&1 | tee -a "$log"
rc=$?
set -e
printf 'Exit=%s\nDirectory=%s\nLog=%s\n' "$rc" /etc/ouf/deploy-snapshots/mcp-host-policy-stop-read-ff06ec1a-v1 "$log" | tee -a "$log"
exit "$rc"
