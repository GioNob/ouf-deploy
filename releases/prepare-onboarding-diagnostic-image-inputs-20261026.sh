#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
operator_uid=$(id -u)
if [[ $operator_uid == 0 ]]; then printf '%s\n' 'STOP: eseguire come oufadmin, non root.'; exit 2; fi
delivery=$(mktemp -d "${HOME}/ouf-onboarding-diagnostic-image-delivery.XXXXXXXX")
chmod 0700 "$delivery"
delivery_log="$delivery/bootstrap.log"
trap 'delivery_exit=$?; trap - EXIT; printf "DeliveryExit=%s\nDeliveryDirectory=%s\nDeliveryLog=%s\n" "$delivery_exit" "$delivery" "$delivery_log" | tee -a "$delivery_log"; exit "$delivery_exit"' EXIT
code_commit=4d57aeb0a62ccc6ca7d5d197d3c7e07cddcd56fe
while read -r name path checksum; do
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 3 --connect-timeout 15 --max-time 60 \
    "https://raw.githubusercontent.com/GioNob/ouf-deploy/${code_commit}/${path}" -o "$delivery/$name"
  printf '%s  %s\n' "$checksum" "$delivery/$name" | sha256sum -c - | tee -a "$delivery_log"
done <<'SOURCES'
prepare.py scripts/prepare-onboarding-diagnostic-image-inputs-20261026.py 95f3b324f21196f336968198eb4e4263597130ee42f780e30aab58caa057c406
image_custody.py tools/acquisition_read_native/image_custody.py 5d0fc0edb1ebd9386326eadbbee08f2cf0a9fd1e122940c0661b5ac5e3655ed8
SOURCES
image_delivery=edb4f01826c9ecd89a9b84cc522f7cbbfd7092bc
transport_started=$SECONDS
while read -r part size checksum; do
  if (( SECONDS - transport_started >= 600 )); then printf '%s\n' 'STOP: finestra download finita; conservare log, non rilanciare.'; exit 2; fi
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 3 --connect-timeout 15 --max-time 120 --max-filesize "$size" \
    "https://raw.githubusercontent.com/GioNob/ouf-source-onboarding/${image_delivery}/image/$part" -o "$delivery/$part"
  printf '%s  %s\n' "$checksum" "$delivery/$part" | sha256sum -c - | tee -a "$delivery_log"
  cat "$delivery/$part" >> "$delivery/candidate.zip"
done <<'PARTS'
candidate.zip.part00 25165824 0c2fd3670db88a72efa3d716625c5b1de948b1abe565ef72d8a137651d643987
candidate.zip.part01 25165824 abca21c46237bb535a901ebcdf605c4f0876886ed72ce400c1b4091e63268dd8
candidate.zip.part02 25165824 21fdfdd14a12c4ff8c11b531ff6f6759d2f4a49a717bb63104edaba4bf6eb3de
candidate.zip.part03 25165824 968488caddd2c25e6b4a3d5c5a78ddc4862bd7e8d5088597f3c87e9b1e274168
candidate.zip.part04 25165824 07b0594409b4ca456294eb6673a57404ca7bcd961b33383cdb4aad6af75cb52d
candidate.zip.part05 25165824 d7219deb955a033c5db973dffe4f3e197970b875b32c3ba7eecd9b24986becba
candidate.zip.part06 25165824 f07dec0cd5444cb9d854a074b99482ae5faf19c0842f1d46edd91dce5d15891e
candidate.zip.part07 25165824 a11b87e025e90b889f1897aba0ec8209154c24fb57cbeece2a2ba4b571a8b00d
candidate.zip.part08 9561379 d1279d2f1b3481f2cb71677996a019ef216ba4f5c555ca37c9c7316c77ed86f0
PARTS
printf '%s  %s\n' 318a6370e4bedb6d17d5d5d8a9bbdf959ee7051196a51a425d334a324afc71a6 "$delivery/candidate.zip" | sha256sum -c - | tee -a "$delivery_log"

sudo /usr/bin/python3 -I -S -B - "$delivery" "$operator_uid" <<'PY' 2>&1 | tee -a "$delivery_log"
import hashlib,os,stat,sys
from pathlib import Path
source,owner=Path(sys.argv[1]),int(sys.argv[2])
def require(ok,code):
    if not ok:raise SystemExit(code)
require(os.geteuid()==os.getegid()==0 and owner>0,'ROOT_CODE_CUSTODY_REQUIRED')
require(not os.path.lexists('/etc/ouf/deploy-snapshots/onboarding-diagnostic-image-inputs-5909d1003e88231c-v1'),'IMAGE_PLAN_SCOPE_CONSUMED_NO_REPLAY')
for part in('/','/usr','/usr/local','/usr/local/lib'):
    s=os.lstat(part);require(stat.S_ISDIR(s.st_mode)and s.st_uid==s.st_gid==0 and not s.st_mode&0o022,'ROOT_CODE_ANCESTRY_REQUIRED')
manifest={'prepare.py':'95f3b324f21196f336968198eb4e4263597130ee42f780e30aab58caa057c406','image_custody.py':'5d0fc0edb1ebd9386326eadbbee08f2cf0a9fd1e122940c0661b5ac5e3655ed8'}
raws={}
frame=lambda s:tuple(getattr(s,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
for name,expected in manifest.items():
    path=source/name;fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd);require(stat.S_ISREG(before.st_mode)and before.st_uid==owner and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o600 and 0<before.st_size<=65536,'BOUNDED_DOWNLOADED_CODE_REQUIRED')
        raw=os.read(fd,65537);require(frame(before)==frame(os.fstat(fd))==frame(path.lstat())and len(raw)==before.st_size and hashlib.sha256(raw).hexdigest()==expected,'EXACT_DOWNLOADED_CODE_REQUIRED');raws[name]=raw
    finally:os.close(fd)
target=Path('/usr/local/lib/ouf-onboarding-diagnostic-image-inputs-95f3b324f21196f3')
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
print('CodeClosure=OK (2 file root0400; checksum eseguiti root)')
PY
printf '%s\n' 'Solo deposito immagine CI verificata e input privati. Zero Engine/SQL/OAuth/credenziali/chiavi/import/lifecycle. Nessun APPROVO. Download massimo720s, preparazione massimo300s; servono2GiB liberi. NON APPLY. Se STOP conservare prove e non rilanciare.' | tee -a "$delivery_log"
set +e
sudo /usr/bin/python3 -I -S -B /usr/local/lib/ouf-onboarding-diagnostic-image-inputs-95f3b324f21196f3/prepare.py "$delivery/candidate.zip" 2>&1 | tee -a "$delivery_log"
prepare_exit=${PIPESTATUS[0]}
set -e
printf 'Exit=%s\nDirectory=%s\nLog=%s\n' "$prepare_exit" "$delivery" "$delivery_log" | tee -a "$delivery_log"
exit "$prepare_exit"

