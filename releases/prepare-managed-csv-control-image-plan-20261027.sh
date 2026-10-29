#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
operator_uid=$(id -u)
if [[ $operator_uid == 0 ]]; then printf '%s\n' 'STOP: eseguire come oufadmin, non root.'; exit 2; fi
delivery=$(mktemp -d "$HOME/ouf-managed-csv-control-image-plan-delivery.XXXXXXXX")
chmod 0700 "$delivery"
delivery_log="$delivery/bootstrap.log"
trap 'delivery_exit=$?; trap - EXIT; printf "DeliveryExit=%s\nDeliveryDirectory=%s\nDeliveryLog=%s\n" "$delivery_exit" "$delivery" "$delivery_log" | tee -a "$delivery_log"; exit "$delivery_exit"' EXIT
code_commit=704a2adefe260196fa2487b8b08c06f77953af6d
code_root=/usr/local/lib/ouf-managed-csv-control-image-plan-2d42559b5e4418b7
paths=(scripts/prepare-managed-csv-control-image-plan.py
  tools/managed_csv_recovery/image_plan.py
  scripts/download-managed-csv-control-images.py
  tools/acquisition_read_native/image_custody.py
  tools/acquisition_read_native/plan_helper.py
  tools/acquisition_read_native/retained_mac.py
  scripts/stage_managed_profile_control_image.py
  releases/managed-csv-control-image-plan-case-20261027.json
  releases/managed-profile-control-onboarding-image-custody-20261027.json
  releases/managed-profile-control-mcp-image-custody-20261027.json)
names=(entry.py image_plan.py download.py image_custody.py plan_helper.py retained_mac.py stage_image.py case.json onboarding-custody.json mcp-custody.json)
for index in 0 1 2 3 4 5 6 7 8 9; do
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 3 --connect-timeout 15 --max-time 60 --max-filesize 131072 \
    "https://raw.githubusercontent.com/GioNob/ouf-deploy/$code_commit/${paths[$index]}" -o "$delivery/${names[$index]}"
done
sudo /usr/bin/python3 -I -S -B - "$delivery" "$operator_uid" <<'PY' 2>&1 | tee -a "$delivery_log"
import hashlib,json,os,pwd,stat,sys
folder,owner=sys.argv[1],int(sys.argv[2]);directory='/usr/local/lib/ouf-managed-csv-control-image-plan-2d42559b5e4418b7';scope='/etc/ouf/deploy-snapshots/managed-csv-control-image-plan-14a96f782827c894-v1'
specs=[{"name":"entry.py","path":"scripts/prepare-managed-csv-control-image-plan.py","sha256":"cfae87208111dcbc19497d01cb6667c3c838f52375487b8719aa690f4705d70e"},{"name":"image_plan.py","path":"tools/managed_csv_recovery/image_plan.py","sha256":"d95720bd315b2f7e08378ecc60250088b4173601705297ca65a904f9316a3375"},{"name":"download.py","path":"scripts/download-managed-csv-control-images.py","sha256":"05788878890b894f9e5037ee04ddc373b2b2dbd24eb91081855d3f88cab56be1"},{"name":"image_custody.py","path":"tools/acquisition_read_native/image_custody.py","sha256":"5d0fc0edb1ebd9386326eadbbee08f2cf0a9fd1e122940c0661b5ac5e3655ed8"},{"name":"plan_helper.py","path":"tools/acquisition_read_native/plan_helper.py","sha256":"09b892a89f7cd7fa31fbc891822445ed09554e9362e397bb9b12b98316e1d8dd"},{"name":"retained_mac.py","path":"tools/acquisition_read_native/retained_mac.py","sha256":"cb5dbbee4a80ce71860dfe5d32362a662d98898c58fd82009e69c5eb6ac1f7ce"},{"name":"stage_image.py","path":"scripts/stage_managed_profile_control_image.py","sha256":"63badba653890bb82cde89aabd9277017b52f10f644a6a8cf6918d997fe1d36f"},{"name":"case.json","path":"releases/managed-csv-control-image-plan-case-20261027.json","sha256":"e76d548e58ea3654c48760a7cdefb8cf371bd5a6ddbeeb94916d2c03a36598f6"},{"name":"onboarding-custody.json","path":"releases/managed-profile-control-onboarding-image-custody-20261027.json","sha256":"ef8f32bceb053718761401a3b775c49e76dc9eef1d46f9df80872d52c88f62e6"},{"name":"mcp-custody.json","path":"releases/managed-profile-control-mcp-image-custody-20261027.json","sha256":"c977f4aa3701992c9570d1faa26e65c953313ae91f685a1094a46f89b4ed7a69"}]
if os.geteuid()!=0 or owner!=pwd.getpwnam('oufadmin').pw_uid or owner<=0:
    raise SystemExit('STOP: identita operatore/root non valida')
if os.path.lexists(scope):
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
if case['outputRoot']!=scope or case['captureHash']!='14a96f782827c8948fabd857d9e3958cbe588a38dc9bd0968c342467f09ca9c1'or case['targetApplyAuthorized'] is not False:
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
printf '%s\n' 'Trasferimento finito dei due ZIP CI originali immutabili; nessun rebuild/import. Dati pubblici, nessun token GitHub o OUF.' | tee -a "$delivery_log"
/usr/bin/python3 -I -S -B "$delivery/download.py" "$delivery" 2>&1 | tee -a "$delivery_log"
sudo /usr/bin/python3 -I -S -B - "$delivery" "$operator_uid" <<'PY' 2>&1 | tee -a "$delivery_log"
import hashlib,json,os,pwd,signal,stat,sys
folder,owner=sys.argv[1],int(sys.argv[2]);directory='/usr/local/lib/ouf-managed-csv-control-image-plan-2d42559b5e4418b7'
if os.geteuid()!=0 or owner!=pwd.getpwnam('oufadmin').pw_uid:
    raise SystemExit('STOP: identita operatore/root non valida')
signal.signal(signal.SIGALRM,lambda *_:(_ for _ in()).throw(SystemExit('STOP: copia ZIP fuori finestra')));signal.alarm(180)
frame=lambda row:(row.st_dev,row.st_ino,row.st_uid,row.st_gid,row.st_mode,row.st_nlink,row.st_size,row.st_mtime_ns,row.st_ctime_ns)
for role in ('onboarding','mcp'):
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
printf '%s\n' 'Nuovo scope:3metadata conservati su14a96f,2ZIP esatti e2archivi nativi preparati. Piano solo CONDIZIONALE, nessuna authority/APPLY. Zero Engine/SQL/OAuth/credenziali/chiavi/import/lifecycle/grant/budget/resume/acquisizioni. Limite300s preparazione; seSTOP conservare prove e non rilanciare.' | tee -a "$delivery_log"
set +e
sudo /usr/bin/python3 -I -S -B "$code_root/entry.py" "$code_root/onboarding.zip" "$code_root/mcp.zip" 2>&1 | tee -a "$delivery_log"
prepare_exit=${PIPESTATUS[0]}
set -e
printf 'Exit=%s\nDirectory=%s\nLog=%s\n' "$prepare_exit" "$delivery" "$delivery_log" | tee -a "$delivery_log"
exit "$prepare_exit"
