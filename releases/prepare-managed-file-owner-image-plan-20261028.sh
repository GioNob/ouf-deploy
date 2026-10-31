#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
operator_uid=$(id -u)
if [[ $operator_uid == 0 ]]; then printf '%s\n' 'STOP: eseguire come oufadmin, non root.'; exit 2; fi
delivery=$(mktemp -d "$HOME/ouf-managed-file-owner-image-plan-delivery.XXXXXXXX")
chmod 0700 "$delivery"
delivery_log="$delivery/bootstrap.log"
trap 'delivery_exit=$?; trap - EXIT; printf "DeliveryExit=%s\nDeliveryDirectory=%s\nDeliveryLog=%s\n" "$delivery_exit" "$delivery" "$delivery_log" | tee -a "$delivery_log"; exit "$delivery_exit"' EXIT
code_commit=816b5cc6a06f8c3a6c092bf815fe183bebec9494
code_root=/usr/local/lib/ouf-managed-file-owner-image-plan-83465836310ad2bd
paths=(scripts/prepare-managed-file-owner-image-plan.py
  tools/managed_file_owner_recovery/image_plan.py
  tools/managed_csv_recovery/image_plan.py
  scripts/download-managed-file-owner-image.py
  tools/acquisition_read_native/image_custody.py
  tools/acquisition_read_native/plan_helper.py
  tools/acquisition_read_native/retained_mac.py
  scripts/stage_managed_file_owner_image.py
  releases/managed-file-owner-v38-image-plan-case-20261028.json
  releases/managed-file-owner-v38-image-custody-20261028.json)
names=(entry.py image_plan.py common_image_plan.py download.py image_custody.py plan_helper.py retained_mac.py stage_image.py case.json onboarding-custody.json)
for index in 0 1 2 3 4 5 6 7 8 9; do
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 3 --connect-timeout 15 --max-time 60 --max-filesize 131072 \
    "https://raw.githubusercontent.com/GioNob/ouf-deploy/$code_commit/${paths[$index]}" -o "$delivery/${names[$index]}"
done
sudo /usr/bin/python3 -I -S -B - "$delivery" "$operator_uid" <<'PY' 2>&1 | tee -a "$delivery_log"
import hashlib,json,os,pwd,stat,sys
folder,owner=sys.argv[1],int(sys.argv[2]);directory='/usr/local/lib/ouf-managed-file-owner-image-plan-83465836310ad2bd';scope='/etc/ouf/deploy-snapshots/managed-file-owner-v38-image-plan-8a4c8475-20261028-v1'
specs=[{"name":"entry.py","path":"scripts/prepare-managed-file-owner-image-plan.py","sha256":"eba155574b113974b3699cd16b5a0dc0c49a8d8832f1285830583d240747f343"},{"name":"image_plan.py","path":"tools/managed_file_owner_recovery/image_plan.py","sha256":"1f5a4de5df532503c5ee10e5d635f1350ca1d691d8b0dee320b6e8515c3441d1"},{"name":"common_image_plan.py","path":"tools/managed_csv_recovery/image_plan.py","sha256":"d95720bd315b2f7e08378ecc60250088b4173601705297ca65a904f9316a3375"},{"name":"download.py","path":"scripts/download-managed-file-owner-image.py","sha256":"a17c0c4c76302e2182f2c2701fa20bfe3a3f1462b36c710133fc038276a5f2eb"},{"name":"image_custody.py","path":"tools/acquisition_read_native/image_custody.py","sha256":"5d0fc0edb1ebd9386326eadbbee08f2cf0a9fd1e122940c0661b5ac5e3655ed8"},{"name":"plan_helper.py","path":"tools/acquisition_read_native/plan_helper.py","sha256":"09b892a89f7cd7fa31fbc891822445ed09554e9362e397bb9b12b98316e1d8dd"},{"name":"retained_mac.py","path":"tools/acquisition_read_native/retained_mac.py","sha256":"cb5dbbee4a80ce71860dfe5d32362a662d98898c58fd82009e69c5eb6ac1f7ce"},{"name":"stage_image.py","path":"scripts/stage_managed_file_owner_image.py","sha256":"9c036afc5256c6f845d545439ee8c677e720b0b2036dc3ed0b5b0fac78109955"},{"name":"case.json","path":"releases/managed-file-owner-v38-image-plan-case-20261028.json","sha256":"6afc3ee56a4c81a7bf45ffcaa9c64af28bd36e22ba6c156cd3b05fbbce98ce2f"},{"name":"onboarding-custody.json","path":"releases/managed-file-owner-v38-image-custody-20261028.json","sha256":"e86a73dd52682e40c040ce3db4634afd2f6802694198c77433ca33e3a49eb9ba"}]
if os.geteuid()!=0 or owner!=pwd.getpwnam('oufadmin').pw_uid or owner<=0:
    raise SystemExit('STOP: identita operatore/root non valida')
if os.path.lexists(scope)or os.path.lexists(directory):
    raise SystemExit('STOP: preparazione consumata; conservare prove, nessun rilancio')
for path in ('/','/usr','/usr/local','/usr/local/lib'):
    row=os.lstat(path)
    if not stat.S_ISDIR(row.st_mode)or row.st_uid!=0 or row.st_gid!=0 or row.st_mode&0o022:
        raise SystemExit('STOP: custodia codice root non valida')
frame=lambda row:(row.st_dev,row.st_ino,row.st_uid,row.st_gid,row.st_mode,row.st_nlink,row.st_size,row.st_mtime_ns,row.st_ctime_ns)
raws={}
for spec in specs:
    path=os.path.join(folder,spec['name']);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        if not stat.S_ISREG(before.st_mode)or before.st_uid!=owner or before.st_nlink!=1 or stat.S_IMODE(before.st_mode)!=0o600 or not 0<before.st_size<=131072:
            raise SystemExit('STOP: fonte scaricata non valida')
        raw=os.read(fd,131073)
        if frame(before)!=frame(os.fstat(fd))or frame(before)!=frame(os.lstat(path))or len(raw)!=before.st_size or hashlib.sha256(raw).hexdigest()!=spec['sha256']:
            raise SystemExit('STOP: checksum/custodia fonte non validi')
        raws[spec['name']]=raw
    finally:os.close(fd)
case=json.loads(raws['case.json'])
if case['outputRoot']!=scope or case['captureHash']!='8a4c84756a663c3eb3a6b6c615d5efccf0c67b3c6ac2281ff9633c9a93de6224'or case['targetApplyAuthorized'] is not False:
    raise SystemExit('STOP: caso esatto di sola preparazione richiesto')
os.mkdir(directory,0o700)
for spec in specs:
    target=os.path.join(directory,spec['name']);fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
    with os.fdopen(fd,'wb')as out:
        os.fchmod(out.fileno(),0o400);out.write(raws[spec['name']]);out.flush();os.fsync(out.fileno())
    fd=os.open(target,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        row=os.fstat(fd)
        if row.st_uid!=row.st_gid or row.st_uid!=0 or stat.S_IMODE(row.st_mode)!=0o400 or hashlib.sha256(os.read(fd,131073)).hexdigest()!=spec['sha256']:
            raise SystemExit('STOP: copia root non verificata')
    finally:os.close(fd)
    print(target+': OK (root0400; checksum ROOT)')
for path in (directory,'/usr/local/lib'):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
print('ProtectedCode='+directory+'/entry.py')
PY
printf '%s\n' 'Trasferimento finito del SOLO ZIP CI V38 originale immutabile; nessun rebuild/import. Dati pubblici, nessun token GitHub o OUF.' | tee -a "$delivery_log"
/usr/bin/python3 -I -S -B "$delivery/download.py" "$delivery" 2>&1 | tee -a "$delivery_log"
sudo /usr/bin/python3 -I -S -B - "$delivery" "$operator_uid" <<'PY' 2>&1 | tee -a "$delivery_log"
import hashlib,json,os,pwd,signal,stat,sys
folder,owner=sys.argv[1],int(sys.argv[2]);directory='/usr/local/lib/ouf-managed-file-owner-image-plan-83465836310ad2bd'
if os.geteuid()!=0 or owner!=pwd.getpwnam('oufadmin').pw_uid:
    raise SystemExit('STOP: identita operatore/root non valida')
signal.signal(signal.SIGALRM,lambda *_:(_ for _ in()).throw(SystemExit('STOP: copia ZIP fuori finestra')));signal.alarm(180)
frame=lambda row:(row.st_dev,row.st_ino,row.st_uid,row.st_gid,row.st_mode,row.st_nlink,row.st_size,row.st_mtime_ns,row.st_ctime_ns)
for role in ('onboarding',):
    with open(directory+'/'+role+'-custody.json','rb')as stream:receipt=json.load(stream)
    source=folder+'/'+role+'.zip';fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        if not stat.S_ISREG(before.st_mode)or before.st_uid!=owner or before.st_nlink!=1 or stat.S_IMODE(before.st_mode)!=0o600 or before.st_size!=receipt['artifactZipBytes']:
            raise SystemExit('STOP: ZIP scaricato non valido')
        checksum=hashlib.sha256();target=directory+'/'+role+'.zip'
        outfd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
        with os.fdopen(outfd,'wb')as out:
            os.fchmod(out.fileno(),0o400)
            while block:=os.read(fd,1048576):out.write(block);checksum.update(block)
            out.flush();os.fsync(out.fileno())
        if frame(before)!=frame(os.fstat(fd))or frame(before)!=frame(os.lstat(source))or checksum.hexdigest()!=receipt['artifactZipSha256']:
            raise SystemExit('STOP: custodia ZIP non valida')
        with open(target,'rb')as stream:
            actual=hashlib.sha256()
            for block in iter(lambda:stream.read(1048576),b''):actual.update(block)
        if actual.hexdigest()!=receipt['artifactZipSha256']:
            raise SystemExit('STOP: checksum ZIP root non valido')
        print(target+': OK (root0400; ZIP originale verificato)')
    finally:os.close(fd)
fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
try:os.fsync(fd)
finally:os.close(fd)
signal.alarm(0)
PY
printf '%s\n' 'NUOVO scope:3metadata della cattura8a4c8475,1ZIP CI esatto e1archivio nativo. Piano solo CONDIZIONALE SOLO Onboarding36-38,12peer invariati. Zero Engine/SQL/IAM/OAuth/configfile/credenziali/chiavi/import/lifecycle/ownership/grant/budget/resume/acquisizioni.300s preparazione; nessuna authority/APPLY. STOP conserva e consuma,nonrilanciare.' | tee -a "$delivery_log"
set +e
sudo /usr/bin/python3 -I -S -B "$code_root/entry.py" "$code_root/onboarding.zip" 2>&1 | tee -a "$delivery_log"
prepare_exit=${PIPESTATUS[0]}
set -e
printf 'Exit=%s\nDirectory=%s\nLog=%s\n' "$prepare_exit" "$delivery" "$delivery_log" | tee -a "$delivery_log"
exit "$prepare_exit"
