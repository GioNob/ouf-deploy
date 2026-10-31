#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
operator_uid=$(id -u)
if [[ $operator_uid == 0 ]]; then printf '%s\n' 'STOP: eseguire come oufadmin, non root.'; exit 2; fi
delivery=$(mktemp -d "${HOME}/ouf-mcp-image-plan-delivery.XXXXXXXX")
chmod 0700 "$delivery"
delivery_log="$delivery/bootstrap.log"
trap 'delivery_exit=$?; trap - EXIT; printf "DeliveryExit=%s\nDeliveryDirectory=%s\nDeliveryLog=%s\n" "$delivery_exit" "$delivery" "$delivery_log" | tee -a "$delivery_log"; exit "$delivery_exit"' EXIT
code_commit=a82727760244183c1733b8d7619909a2821839ac
while read -r name path checksum; do
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 3 --connect-timeout 15 --max-time 60 \
    "https://raw.githubusercontent.com/GioNob/ouf-deploy/${code_commit}/${path}" -o "$delivery/$name"
  printf '%s  %s\n' "$checksum" "$delivery/$name" | sha256sum -c - | tee -a "$delivery_log"
done <<'SOURCES'
prepare.py scripts/prepare-mcp-denial-image-plan-20261026.py 96cb2f55d3000d5408265f09a2bd615d902964398e97ba631a72b84a14379059
plan_helper.py tools/acquisition_read_native/plan_helper.py 09b892a89f7cd7fa31fbc891822445ed09554e9362e397bb9b12b98316e1d8dd
retained_mac.py tools/acquisition_read_native/retained_mac.py cb5dbbee4a80ce71860dfe5d32362a662d98898c58fd82009e69c5eb6ac1f7ce
image_custody.py tools/acquisition_read_native/image_custody.py 5d0fc0edb1ebd9386326eadbbee08f2cf0a9fd1e122940c0661b5ac5e3655ed8
SOURCES
# Exact public copy of the already qualified CI ZIP; no gh, GitHub login or token.
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 3 --connect-timeout 15 --max-time 120 --max-filesize 9617218 \
  "https://raw.githubusercontent.com/GioNob/ouf-deploy/5938c4b18124ab2be962b3d2979bddcac60c659d/releases/artifacts/mcp-denial-9a374dd0/candidate.zip" -o "$delivery/candidate.zip"
printf '%s  %s\n' 6c31a1b5698942ddbb47b96ec1b49860c690c44aac8106beb1ca4b1ed7bba56a "$delivery/candidate.zip" | sha256sum -c - | tee -a "$delivery_log"
sudo /usr/bin/python3 -I -S -B - "$delivery" "$operator_uid" <<'PY' 2>&1 | tee -a "$delivery_log"
import hashlib,os,stat,sys
from pathlib import Path
source,owner=Path(sys.argv[1]),int(sys.argv[2])
def require(ok,code):
    if not ok:raise SystemExit(code)
require(os.geteuid()==os.getegid()==0 and owner>0,'ROOT_CODE_CUSTODY_REQUIRED')
require(not os.path.lexists('/etc/ouf/deploy-snapshots/mcp-denial-image-plan-fb4b7c9ae832e779-v1'),'IMAGE_PLAN_SCOPE_CONSUMED_NO_REPLAY')
for part in('/','/usr','/usr/local','/usr/local/lib'):
    s=os.lstat(part);require(stat.S_ISDIR(s.st_mode)and s.st_uid==s.st_gid==0 and not s.st_mode&0o022,'ROOT_CODE_ANCESTRY_REQUIRED')
manifest={'prepare.py':'96cb2f55d3000d5408265f09a2bd615d902964398e97ba631a72b84a14379059',
          'plan_helper.py':'09b892a89f7cd7fa31fbc891822445ed09554e9362e397bb9b12b98316e1d8dd',
          'retained_mac.py':'cb5dbbee4a80ce71860dfe5d32362a662d98898c58fd82009e69c5eb6ac1f7ce',
          'image_custody.py':'5d0fc0edb1ebd9386326eadbbee08f2cf0a9fd1e122940c0661b5ac5e3655ed8'}
raws={}
frame=lambda s:tuple(getattr(s,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
for name,expected in manifest.items():
    path=source/name;fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd);require(stat.S_ISREG(before.st_mode)and before.st_uid==owner and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o600 and 0<before.st_size<=65536,'BOUNDED_DOWNLOADED_CODE_REQUIRED')
        raw=os.read(fd,65537);require(frame(before)==frame(os.fstat(fd))==frame(path.lstat())and len(raw)==before.st_size and hashlib.sha256(raw).hexdigest()==expected,'EXACT_DOWNLOADED_CODE_REQUIRED');raws[name]=raw
    finally:os.close(fd)
target=Path('/usr/local/lib/ouf-mcp-denial-image-plan-96cb2f55d3000d54')
require(not os.path.lexists(target),'CODE_SCOPE_EXISTS_STOP_RECONCILE');target.mkdir(mode=0o700);target.chmod(0o700)
for name,raw in raws.items():
    fd=os.open(target/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
    with os.fdopen(fd,'wb')as out:
        os.fchmod(out.fileno(),0o400);out.write(raw);out.flush();os.fsync(out.fileno())
for part in(target,target.parent):
    fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
for name,expected in manifest.items():
    fd=os.open(target/name,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        s=os.fstat(fd);require(stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o400 and hashlib.sha256(os.read(fd,65537)).hexdigest()==expected,'ROOT_COPIED_CODE_CHECKSUM_REQUIRED')
    finally:os.close(fd)
print('ProtectedCode='+str(target/'prepare.py'))
print('CodeClosure=OK (4 file root0400; checksum eseguiti root)')
PY
printf '%s\n' 'Solo deposito immagine CI e piano privato. Nessun APPROVO/login OUF, import Engine, stop, restart o aggiornamento runtime.' | tee -a "$delivery_log"
set +e
sudo /usr/bin/python3 -I -S -B /usr/local/lib/ouf-mcp-denial-image-plan-96cb2f55d3000d54/prepare.py "$delivery/candidate.zip" 2>&1 | tee -a "$delivery_log"
prepare_exit=${PIPESTATUS[0]}
set -e
printf 'Exit=%s\nDirectory=%s\nLog=%s\n' "$prepare_exit" "$delivery" "$delivery_log" | tee -a "$delivery_log"
exit "$prepare_exit"
