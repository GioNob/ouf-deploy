#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
ouf_reader_uid=$(id -u)
if [[ "$ouf_reader_uid" == 0 ]]; then printf '%s\n' 'STOP: eseguire come oufadmin, non root.'; exit 2; fi
ouf_reader_delivery=$(mktemp -d "$HOME/ouf-onboarding-transport-stop-read-delivery.XXXXXXXX")
chmod 0700 "$ouf_reader_delivery"
ouf_reader_log="$ouf_reader_delivery/bootstrap.log"
trap 'ouf_reader_exit=$?; trap - EXIT; printf "DeliveryExit=%s\nDeliveryDirectory=%s\nDeliveryLog=%s\n" "$ouf_reader_exit" "$ouf_reader_delivery" "$ouf_reader_log" | tee -a "$ouf_reader_log"; exit "$ouf_reader_exit"' EXIT
ouf_reader_sha=cd89338de4dcdbb55930981f05a446c3b5184648945b9f5e6f8060ca215e932a
ouf_reader_code=/usr/local/lib/ouf-onboarding-transport-stop-read-cd89338de4dcdbb5
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 3 --connect-timeout 15 --max-time 60 --max-filesize 65536 \
  'https://raw.githubusercontent.com/GioNob/ouf-deploy/b1618031d8c1d7ab10efd9c9742bc5c1b96131e8/scripts/read-onboarding-diagnostic-transport-stop-20261027.py' \
  -o "$ouf_reader_delivery/read.py"
printf '%s  %s\n' "$ouf_reader_sha" "$ouf_reader_delivery/read.py" | sha256sum -c - | tee -a "$ouf_reader_log"
sudo /usr/bin/python3 -I -S -B - "$ouf_reader_delivery/read.py" "$ouf_reader_uid" <<'PY' 2>&1 | tee -a "$ouf_reader_log"
import hashlib,os,stat,sys
from pathlib import Path
source=Path(sys.argv[1]);owner=int(sys.argv[2]);expected='cd89338de4dcdbb55930981f05a446c3b5184648945b9f5e6f8060ca215e932a'
target=Path('/usr/local/lib/ouf-onboarding-transport-stop-read-cd89338de4dcdbb5')
def require(ok,reason):
 if not ok:raise SystemExit(reason)
require(os.geteuid()==os.getegid()==0 and owner>0,'ROOT_READER_CODE_COPY_REQUIRED')
require(not os.path.lexists('/etc/ouf/deploy-snapshots/onboarding-diagnostic-transport-stop-read-c2258617-v1'),'RETAINED_READ_SCOPE_CONSUMED_NO_REPLAY')
for p in(target.parent,*target.parent.parents):
 s=p.lstat();require(stat.S_ISDIR(s.st_mode)and s.st_uid==s.st_gid==0 and not s.st_mode&0o022,'ROOT_READER_CODE_ANCESTRY_REQUIRED')
require(not os.path.lexists(target),'READER_CODE_SCOPE_EXISTS_STOP_RECONCILE')
frame=lambda s:tuple(getattr(s,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
fd=os.open(source,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW)
try:
 s=os.fstat(fd);require(stat.S_ISREG(s.st_mode)and s.st_uid==owner and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and 0<s.st_size<=65536,'BOUNDED_OWNER_READER_DOWNLOAD_REQUIRED')
 raw=os.read(fd,65537);require(len(raw)==s.st_size and frame(s)==frame(os.fstat(fd))==frame(source.lstat())and hashlib.sha256(raw).hexdigest()==expected,'EXACT_READER_SOURCE_BYTES_REQUIRED')
finally:os.close(fd)
target.mkdir(mode=0o700);target.chmod(0o700);fd=os.open(target/'read.py',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
with os.fdopen(fd,'wb')as out:os.fchmod(out.fileno(),0o400);out.write(raw);out.flush();os.fsync(out.fileno())
for p in(target,target.parent):
 fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
fd=os.open(target/'read.py',os.O_RDONLY|os.O_NOFOLLOW)
try:
 s=os.fstat(fd);require(s.st_uid==s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o400 and hashlib.sha256(os.read(fd,65537)).hexdigest()==expected,'ROOT_READER_CHECKSUM_AND_MODE_REQUIRED')
finally:os.close(fd)
print('ProtectedCode='+str(target/'read.py'))
print('SourceChecksum=OK (root0400; checksum eseguito root)')
PY
printf '%s\n' 'SOLA lettura prove conservate:7metadata+21fonti e manifesto. Zero Engine/SQL/OAuth/configurazione/credenziali/chiavi/lifecycle; nessun APPROVO. Massimo60s/8MiB. Nessun vecchio file modificato. Se STOP conservare e non rilanciare.' | tee -a "$ouf_reader_log"
set +e
sudo /usr/bin/python3 -I -S -B "$ouf_reader_code/read.py" 2>&1 | tee -a "$ouf_reader_log"
ouf_reader_exit=${PIPESTATUS[0]}
set -e
printf 'Exit=%s\nDirectory=%s\nLog=%s\n' "$ouf_reader_exit" "$ouf_reader_delivery" '/etc/ouf/deploy-snapshots/onboarding-diagnostic-transport-stop-read-c2258617-v1/operator.log' | tee -a "$ouf_reader_log"
exit "$ouf_reader_exit"
