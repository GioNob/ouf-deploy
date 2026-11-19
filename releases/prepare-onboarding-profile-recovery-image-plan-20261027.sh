#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
operator_uid=$(id -u)
if [[ $operator_uid == 0 ]]; then printf '%s\n' 'STOP: eseguire come oufadmin, non root.'; exit 2; fi
delivery=$(mktemp -d "${HOME}/ouf-onboarding-profile-recovery-image-plan-delivery.XXXXXXXX")
chmod 0700 "$delivery"
delivery_log="$delivery/bootstrap.log"
trap 'delivery_exit=$?; trap - EXIT; printf "DeliveryExit=%s\nDeliveryDirectory=%s\nDeliveryLog=%s\n" "$delivery_exit" "$delivery" "$delivery_log" | tee -a "$delivery_log"; exit "$delivery_exit"' EXIT
code_commit=238cbe770b362fb114dbb3687131a55191ec35ae
while read -r name path checksum; do
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 3 --connect-timeout 15 --max-time 60 \
    "https://raw.githubusercontent.com/GioNob/ouf-deploy/${code_commit}/${path}" -o "$delivery/$name"
  printf '%s  %s\n' "$checksum" "$delivery/$name" | sha256sum -c - | tee -a "$delivery_log"
done <<'SOURCES'
prepare.py scripts/prepare-onboarding-profile-recovery-image-plan-20261027.py 874d38f18022906f09b74500d780d0bd0998bd0be521818fac24f296435e50e1
image_custody.py tools/acquisition_read_native/image_custody.py 5d0fc0edb1ebd9386326eadbbee08f2cf0a9fd1e122940c0661b5ac5e3655ed8
plan_helper.py tools/acquisition_read_native/plan_helper.py 09b892a89f7cd7fa31fbc891822445ed09554e9362e397bb9b12b98316e1d8dd
retained_mac.py tools/acquisition_read_native/retained_mac.py cb5dbbee4a80ce71860dfe5d32362a662d98898c58fd82009e69c5eb6ac1f7ce
case.json releases/onboarding-profile-recovery-image-custody-20261027.json bf9a2477a808e38d3b960ce085fadda20a1f196857c4fc70a5a6fee153e6ffbb
SOURCES
image_delivery=5aba35d98a27801657b6a53bbecb175a438b0201
transport_started=$SECONDS
while read -r part size checksum; do
  if (( SECONDS - transport_started >= 600 )); then printf '%s\n' 'STOP: finestra download finita; conservare log, non rilanciare.'; exit 2; fi
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 3 --connect-timeout 15 --max-time 120 --max-filesize "$size" \
    "https://raw.githubusercontent.com/GioNob/ouf-source-onboarding/${image_delivery}/image/$part" -o "$delivery/$part"
  printf '%s  %s\n' "$checksum" "$delivery/$part" | sha256sum -c - | tee -a "$delivery_log"
  cat "$delivery/$part" >> "$delivery/candidate.zip"
done <<'PARTS'
candidate.zip.part00 25165824 e60760be16c8466ca1867102a1bf2a5853893e3a8fb409f835f246067b33114b
candidate.zip.part01 25165824 d1e2e987b794ce15e0d0eda29a3d55c628b1271c30feafa92f92094e8aae25ea
candidate.zip.part02 25165824 c42128ba75d5eeccd8f0555598162e99178141c99817316239badd4505535f6d
candidate.zip.part03 25165824 9b5dd98eced3b2c71630b5bca4391e393514537e6f1343fcc95aa868f29ae97f
candidate.zip.part04 25165824 d2788d0a67eb127e8d68621c92a276121f2b774b65b89ba0588c8d545c5f028d
candidate.zip.part05 25165824 ca62ddd6729619103a2331a11e5d8f3456660b22e837ceee61a5760ec9da1a38
candidate.zip.part06 25165824 318a905bd9e66028e2671a8c316ec422445c83e834bdca7e7cc3147bcd1a7f62
candidate.zip.part07 25165824 be7167bf7da1c285f0f1720db92ff5f8ba598358552b1b11b1c0a2c3e6f6bec6
candidate.zip.part08 11579183 d11c7db0e2ae4e6573685f2b6ad3c9dfa2f19fd605fd2a8616afe09c3435c686
PARTS
printf '%s  %s\n' afc1da28317b06845c8a37d81c529e931cb3d11415f13b9842fb3633a0e8d3d0 "$delivery/candidate.zip" | sha256sum -c - | tee -a "$delivery_log"

sudo /usr/bin/python3 -I -S -B - "$delivery" "$operator_uid" <<'PY' 2>&1 | tee -a "$delivery_log"
import hashlib,os,stat,sys
from pathlib import Path
source,owner=Path(sys.argv[1]),int(sys.argv[2])
def require(ok,code):
    if not ok:raise SystemExit(code)
require(os.geteuid()==os.getegid()==0 and owner>0,'ROOT_CODE_CUSTODY_REQUIRED')
require(not os.path.lexists('/etc/ouf/deploy-snapshots/onboarding-profile-recovery-image-plan-1ce0ce1cd2719556-v1'),'IMAGE_PLAN_SCOPE_CONSUMED_NO_REPLAY')
for part in('/','/usr','/usr/local','/usr/local/lib'):
    s=os.lstat(part);require(stat.S_ISDIR(s.st_mode)and s.st_uid==s.st_gid==0 and not s.st_mode&0o022,'ROOT_CODE_ANCESTRY_REQUIRED')
manifest={"prepare.py":"874d38f18022906f09b74500d780d0bd0998bd0be521818fac24f296435e50e1","image_custody.py":"5d0fc0edb1ebd9386326eadbbee08f2cf0a9fd1e122940c0661b5ac5e3655ed8","plan_helper.py":"09b892a89f7cd7fa31fbc891822445ed09554e9362e397bb9b12b98316e1d8dd","retained_mac.py":"cb5dbbee4a80ce71860dfe5d32362a662d98898c58fd82009e69c5eb6ac1f7ce","case.json":"bf9a2477a808e38d3b960ce085fadda20a1f196857c4fc70a5a6fee153e6ffbb"}
raws={}
frame=lambda s:tuple(getattr(s,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
for name,expected in manifest.items():
    path=source/name;fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd);require(stat.S_ISREG(before.st_mode)and before.st_uid==owner and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o600 and 0<before.st_size<=65536,'BOUNDED_DOWNLOADED_CODE_REQUIRED')
        raw=os.read(fd,65537);require(frame(before)==frame(os.fstat(fd))==frame(path.lstat())and len(raw)==before.st_size and hashlib.sha256(raw).hexdigest()==expected,'EXACT_DOWNLOADED_CODE_REQUIRED');raws[name]=raw
    finally:os.close(fd)
target=Path('/usr/local/lib/ouf-onboarding-profile-recovery-image-plan-874d38f18022906f')
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
print('CodeClosure=OK (5 file root0400; checksum eseguiti root)')
PY
printf '%s\n' 'Solo preparazione immagine CI verificata e piano privato condizionale V36 da TRE metadata conservati. Zero Engine/SQL/OAuth/credenziali/chiavi/import/lifecycle. Nessuna migrazione o nuovo budget/job; contatori preservati. Nessun APPROVO. Download massimo720s, preparazione massimo300s; servono2GiB liberi. NON APPLY. Se STOP conservare prove e non rilanciare.' | tee -a "$delivery_log"
set +e
sudo /usr/bin/python3 -I -S -B /usr/local/lib/ouf-onboarding-profile-recovery-image-plan-874d38f18022906f/prepare.py "$delivery/candidate.zip" 2>&1 | tee -a "$delivery_log"
prepare_exit=${PIPESTATUS[0]}
set -e
printf 'Exit=%s\nDirectory=%s\nLog=%s\n' "$prepare_exit" "$delivery" "$delivery_log" | tee -a "$delivery_log"
exit "$prepare_exit"

