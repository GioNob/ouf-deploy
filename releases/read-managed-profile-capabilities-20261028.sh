#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
operator_uid=$(id -u)
if [[ $operator_uid == 0 ]]; then printf '%s\n' 'STOP: eseguire come oufadmin, non root.'; exit 2; fi
delivery=$(mktemp -d "${HOME}/ouf-managed-profile-capability-delivery.XXXXXXXX")
chmod 0700 "$delivery"
delivery_log="$delivery/bootstrap.log"
trap 'delivery_exit=$?; trap - EXIT; printf "DeliveryExit=%s\nDeliveryDirectory=%s\nDeliveryLog=%s\n" "$delivery_exit" "$delivery" "$delivery_log" | tee -a "$delivery_log"; exit "$delivery_exit"' EXIT
code_commit=8543017ea2c7f2272f31ae465d49a96d04101c49
code_sha=1243cdffacb4e559534219d29884b9d57d58ab12de9e4edb3d69abe6e22be1bd
code_root=/usr/local/lib/ouf-managed-profile-capability-read-1243cdffacb4e559
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 3 --connect-timeout 15 --max-time 60 --max-filesize 32768 \
  "https://raw.githubusercontent.com/GioNob/ouf-deploy/${code_commit}/scripts/read-managed-profile-capabilities-20261028.py" -o "$delivery/read.py"
printf '%s  %s\n' "$code_sha" "$delivery/read.py" | sha256sum -c - | tee -a "$delivery_log"
sudo /usr/bin/python3 -I -S -B - "$delivery/read.py" "$operator_uid" <<'PY' 2>&1 | tee -a "$delivery_log"
import hashlib,os,pwd,stat,sys
from pathlib import Path
source=Path(sys.argv[1]);owner=int(sys.argv[2]);expected='1243cdffacb4e559534219d29884b9d57d58ab12de9e4edb3d69abe6e22be1bd'
def require(ok,code):
    if not ok:raise SystemExit(code)
require(os.geteuid()==os.getegid()==0 and owner>0 and owner==pwd.getpwnam('oufadmin').pw_uid,'ROOT_POLICY_READER_COPY_REQUIRED')
scope=Path('/etc/ouf/deploy-snapshots/managed-profile-capability-read-policy56-20261028-v1')
require(not os.path.lexists(scope),'POLICY_READ_SCOPE_CONSUMED_NO_REPLAY')
target=Path('/usr/local/lib/ouf-managed-profile-capability-read-1243cdffacb4e559')
for parent in(target.parent,*target.parent.parents):
    s=parent.lstat();require(stat.S_ISDIR(s.st_mode)and s.st_uid==s.st_gid==0 and not s.st_mode&0o022,'ROOT_READER_ANCESTRY_REQUIRED')
require(not os.path.lexists(target),'READER_DELIVERY_CONSUMED_NO_REPLAY')
frame=lambda s:tuple(getattr(s,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
fd=os.open(source,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW)
try:
    before=os.fstat(fd);require(stat.S_ISREG(before.st_mode)and before.st_uid==owner and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o600 and 0<before.st_size<=32768,'BOUNDED_OWNER_DOWNLOADED_READER_REQUIRED')
    raw=os.read(fd,32769);require(len(raw)==before.st_size and frame(before)==frame(os.fstat(fd))==frame(source.lstat())and hashlib.sha256(raw).hexdigest()==expected,'EXACT_READER_CUSTODY_AND_BYTES_REQUIRED')
finally:os.close(fd)
target.mkdir(mode=0o700);target.chmod(0o700)
fd=os.open(target/'read.py',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
with os.fdopen(fd,'wb')as out:
    os.fchmod(out.fileno(),0o400);out.write(raw);out.flush();os.fsync(out.fileno())
for folder in(target,target.parent):
    fd=os.open(folder,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
fd=os.open(target/'read.py',os.O_RDONLY|os.O_NOFOLLOW)
try:
    s=os.fstat(fd);require(s.st_uid==s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o400 and hashlib.sha256(os.read(fd,32769)).hexdigest()==expected,'ROOT400_READER_CHECKSUM_REQUIRED')
finally:os.close(fd)
print('ProtectedCode='+str(target/'read.py'))
print('SourceChecksum=OK (root0400; verifica eseguita root)')
PY
printf '%s\n' 'NUOVA sola lettura capability Farmacie: policy56 e cataloghi, massimo52GET/16MB/600s; zero Engine/SQL/file credenziali/chiavi/mutazioni/grant/budget/resume/profiling. Login HUMAN ouf-admin; nessun APPROVO. Se STOP conservare, non rilanciare.' | tee -a "$delivery_log"
set +e
sudo /usr/bin/python3 -I -S -B "$code_root/read.py"
read_exit=$?
set -e
printf 'Exit=%s\nDirectory=%s\nLog=%s\n' "$read_exit" "$delivery" "$code_root/operator.log" | tee -a "$delivery_log"
exit "$read_exit"
