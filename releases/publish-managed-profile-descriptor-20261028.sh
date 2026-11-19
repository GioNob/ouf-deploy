#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
operator_uid=$(id -u)
if [[ $operator_uid == 0 ]]; then printf '%s\n' 'STOP: eseguire come oufadmin, non root.'; exit 2; fi
delivery=$(mktemp -d "${HOME}/ouf-managed-profile-descriptor-publish-delivery.XXXXXXXX")
chmod 0700 "$delivery"
delivery_log="$delivery/bootstrap.log"
trap 'delivery_exit=$?; trap - EXIT; printf "DeliveryExit=%s\nDeliveryDirectory=%s\nDeliveryLog=%s\n" "$delivery_exit" "$delivery" "$delivery_log" | tee -a "$delivery_log"; exit "$delivery_exit"' EXIT
code_commit=9d7d83b3fc18950e2516e79cff30930d198c36d5
code_sha=cba55b90eb3763a924db0ef0f27675272b854b9dbdb053f724c867effd6d07f6
code_root=/usr/local/lib/ouf-managed-profile-descriptor-publish-cba55b90eb3763a9
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 3 --connect-timeout 15 --max-time 60 --max-filesize 65536 \
  "https://raw.githubusercontent.com/GioNob/ouf-deploy/${code_commit}/scripts/publish-managed-profile-descriptor-20261028.py" -o "$delivery/publish.py"
printf '%s  %s\n' "$code_sha" "$delivery/publish.py" | sha256sum -c - | tee -a "$delivery_log"
sudo /usr/bin/python3 -I -S -B - "$delivery/publish.py" "$operator_uid" <<'PY' 2>&1 | tee -a "$delivery_log"
import hashlib,os,pwd,stat,sys
from pathlib import Path
source=Path(sys.argv[1]);owner=int(sys.argv[2]);expected='cba55b90eb3763a924db0ef0f27675272b854b9dbdb053f724c867effd6d07f6'
def require(ok,code):
    if not ok:raise SystemExit(code)
require(os.geteuid()==os.getegid()==0 and owner>0 and owner==pwd.getpwnam('oufadmin').pw_uid,'ROOT_DESCRIPTOR_PUBLISHER_COPY_REQUIRED')
scope=Path('/etc/ouf/deploy-snapshots/managed-profile-descriptor-publication-policy56-20261028-v1')
require(not os.path.lexists(scope),'DESCRIPTOR_PUBLICATION_SCOPE_CONSUMED_NO_REPLAY')
target=Path('/usr/local/lib/ouf-managed-profile-descriptor-publish-cba55b90eb3763a9')
for parent in(target.parent,*target.parent.parents):
    s=parent.lstat();require(stat.S_ISDIR(s.st_mode)and s.st_uid==s.st_gid==0 and not s.st_mode&0o022,'ROOT_PUBLISHER_ANCESTRY_REQUIRED')
require(not os.path.lexists(target),'PUBLISHER_DELIVERY_CONSUMED_NO_REPLAY')
frame=lambda s:tuple(getattr(s,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
fd=os.open(source,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW)
try:
    before=os.fstat(fd);require(stat.S_ISREG(before.st_mode)and before.st_uid==owner and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o600 and 0<before.st_size<=65536,'BOUNDED_OWNER_DOWNLOADED_PUBLISHER_REQUIRED')
    raw=os.read(fd,65537);require(len(raw)==before.st_size and frame(before)==frame(os.fstat(fd))==frame(source.lstat())and hashlib.sha256(raw).hexdigest()==expected,'EXACT_PUBLISHER_CUSTODY_AND_BYTES_REQUIRED')
finally:os.close(fd)
target.mkdir(mode=0o700);target.chmod(0o700)
fd=os.open(target/'publish.py',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
with os.fdopen(fd,'wb')as out:
    os.fchmod(out.fileno(),0o400);out.write(raw);out.flush();os.fsync(out.fileno())
for folder in(target,target.parent):
    fd=os.open(folder,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
fd=os.open(target/'publish.py',os.O_RDONLY|os.O_NOFOLLOW)
try:
    s=os.fstat(fd);require(s.st_uid==s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o400 and hashlib.sha256(os.read(fd,65537)).hexdigest()==expected,'ROOT400_PUBLISHER_CHECKSUM_REQUIRED')
finally:os.close(fd)
print('ProtectedCode='+str(target/'publish.py'))
print('SourceChecksum=OK (root0400; verifica eseguita root)')
PY
printf '%s\n' 'NUOVA review amministrativa HUMAN: SOLO descriptor quarantine.release COMMAND/HUMAN, ACTIVE56→57; tutti i grant invariati. Max1registrazione+1draft+2preview+1publish/160GET/32MiB; login600s, review-esecuzione900s entro token e totale1800s. Zero Engine/SQL/credenziali/chiavi/grant/budget/resume/job/upload/acquisizioni/Registry. APPROVO solo su review fresca nel vero terminale; se STOP conservare e non rilanciare.' | tee -a "$delivery_log"
set +e
sudo /usr/bin/python3 -I -S -B "$code_root/publish.py"
publish_exit=$?
set -e
printf 'Exit=%s\nDirectory=%s\nLog=%s\n' "$publish_exit" "$delivery" "$code_root/operator.log" | tee -a "$delivery_log"
exit "$publish_exit"
