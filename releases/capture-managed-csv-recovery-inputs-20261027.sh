#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
operator_uid=$(id -u)
if [[ $operator_uid == 0 ]]; then
  printf '%s\n' 'STOP: eseguire come oufadmin, non root.'
  exit 2
fi
delivery=$(mktemp -d "$HOME/ouf-managed-csv-recovery-inputs-delivery.XXXXXXXX")
chmod 0700 "$delivery"
delivery_log="$delivery/bootstrap.log"
trap 'delivery_exit=$?; trap - EXIT; printf "DeliveryExit=%s\nDeliveryDirectory=%s\nDeliveryLog=%s\n" "$delivery_exit" "$delivery" "$delivery_log" | tee -a "$delivery_log"; exit "$delivery_exit"' EXIT
code_commit=4dcffc7e299cda79d70b0a973e6e270ce4f36718
code_root=/usr/local/lib/ouf-managed-csv-recovery-inputs-5c390ebcb75857ef
paths=(
  scripts/capture-managed-csv-recovery-inputs.py
  tools/managed_csv_recovery/retained_inputs.py
  releases/managed-csv-recovery-capture-case-20261027.json
)
names=(capture.py retained_inputs.py case.json)
for index in 0 1 2; do
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 3 --connect-timeout 15 --max-time 60 \
    "https://raw.githubusercontent.com/GioNob/ouf-deploy/$code_commit/${paths[$index]}" -o "$delivery/${names[$index]}"
done
sudo /usr/bin/python3 -I -S -B - "$delivery" "$operator_uid" <<'PY' 2>&1 | tee -a "$delivery_log"
import hashlib,json,os,re,stat,sys
source, owner = sys.argv[1], int(sys.argv[2])
expected = {"capture.py":"93fab0406d3ed730918252ee622dc86cd1082d9a9565bb6a40d58e00321de03b","retained_inputs.py":"5c390ebcb75857ef244b06d104bfbe988af899fc2f7a1e18288320a2c39780ed","case.json":"060db516ab4c5ace800002c8acd50ebe44af8e4198bf5dbc9b8d467af6036e5a"}
directory = '/usr/local/lib/ouf-managed-csv-recovery-inputs-5c390ebcb75857ef'
scope = '/etc/ouf/deploy-snapshots/managed-csv-recovery-control-inputs-20261027-v1'
if os.geteuid()!=0 or owner<=0:
    raise SystemExit('STOP: identita root/operatore non valida')
if os.path.lexists(scope):
    raise SystemExit('STOP: lettura metadata consumata; conservare prove, nessun rilancio')
for path in ('/','/usr','/usr/local','/usr/local/lib'):
    row=os.lstat(path)
    if not stat.S_ISDIR(row.st_mode) or row.st_uid!=0 or row.st_gid!=0 or row.st_mode&0o022:
        raise SystemExit('STOP: custodia codice root non valida')
raws={}
frame=lambda row:(row.st_dev,row.st_ino,row.st_uid,row.st_gid,row.st_mode,row.st_nlink,row.st_size,row.st_mtime_ns,row.st_ctime_ns)
for name,checksum in expected.items():
    path=os.path.join(source,name);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_uid!=owner or before.st_nlink!=1 or stat.S_IMODE(before.st_mode)!=0o600 or not 0<before.st_size<=65536:
            raise SystemExit('STOP: file scaricato non valido')
        raw=os.read(fd,65537)
        if frame(before)!=frame(os.fstat(fd)) or frame(before)!=frame(os.lstat(path)) or len(raw)!=before.st_size or hashlib.sha256(raw).hexdigest()!=checksum:
            raise SystemExit('STOP: checksum/custodia codice non validi')
        raws[name]=raw
    finally:os.close(fd)
case=json.loads(raws['case.json'])
if case['outputRoot']!=scope or case['cohortSize']!=13 or case['targetApplyAuthorized'] is not False:
    raise SystemExit('STOP: caso chiuso di sola lettura richiesto')
os.mkdir(directory,0o700)
for name,raw in raws.items():
    target=os.path.join(directory,name)
    fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
    with os.fdopen(fd,'wb')as out:
        os.fchmod(out.fileno(),0o400);out.write(raw);out.flush();os.fsync(out.fileno())
    fd=os.open(target,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        row=os.fstat(fd)
        if row.st_uid!=row.st_gid or row.st_uid!=0 or stat.S_IMODE(row.st_mode)!=0o400 or row.st_nlink!=1 or hashlib.sha256(os.read(fd,65537)).hexdigest()!=expected[name]:
            raise SystemExit('STOP: copia root non verificata')
    finally:os.close(fd)
    print(target+': OK (root0400; checksum ROOT)')
for path in (directory,'/usr/local/lib'):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
print('ProtectedCode='+directory+'/capture.py')
PY
printf '%s\n' 'Nuova sola lettura: 3 metadata della V36 gia riuscita, massimo27 GET Engine sulla coorte esatta13 e pin dei processi/root. Nessuna SQL, lettura configurazioni/credenziali/chiavi, OAuth, import, APPROVO, lifecycle, grant, budget o resume. Limite90secondi. Esito ambiguo: conservare prove e non rilanciare.' | tee -a "$delivery_log"
set +e
sudo /usr/bin/python3 -I -S -B "$code_root/capture.py" 2>&1 | tee -a "$delivery_log"
capture_exit=${PIPESTATUS[0]}
set -e
printf 'Exit=%s\nDirectory=%s\nLog=%s\n' "$capture_exit" "$delivery" "$delivery_log" | tee -a "$delivery_log"
exit "$capture_exit"
