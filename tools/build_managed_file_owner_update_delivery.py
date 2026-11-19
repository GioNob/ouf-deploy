import hashlib,importlib.util,json
from pathlib import Path
s=importlib.util.spec_from_file_location('bundle','tools/managed_file_owner_update/bundle.py');b=importlib.util.module_from_spec(s);s.loader.exec_module(b)
specs=[{'name':name,'path':path,'sha256':hashlib.sha256(Path(path).read_bytes()).hexdigest()}for name,path in b.FILES.items()]
encoded=lambda v:json.dumps(v,sort_keys=True,separators=(',',':'))
manifest={x['name']:x['sha256']for x in specs};closure=hashlib.sha256(encoded(manifest).encode()).hexdigest();root='/usr/local/lib/ouf-managed-file-owner-v38-update-'+closure[:16]
info={'sourceCommit':'a9b5904c772c6cf93e34545163e72af5e6b4941f','sourceClosureHash':closure,'codeRoot':root,'files':specs,'executionRoot':'/etc/ouf/deploy-snapshots/managed-file-owner-v38-update-b03d681a-20261028-v1'}
Path('releases/managed-file-owner-v38-update-delivery-pins-20261028.json').write_text(encoded(info)+'\n')
shell='''#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
operator_uid=$(id -u)
if [[ $operator_uid == 0 ]]; then printf '%s\\n' 'STOP: eseguire come oufadmin, non root.'; exit 2; fi
if [[ ! -t 0 || ! -t 1 ]]; then printf '%s\\n' 'STOP: serve il terminale SSH interattivo; nessuna pipe per il controller.'; exit 2; fi
delivery=$(mktemp -d "$HOME/ouf-managed-file-owner-v38-update-delivery.XXXXXXXX")
chmod 0700 "$delivery"
delivery_log="$delivery/bootstrap.log"
trap 'delivery_exit=$?; trap - EXIT; printf "DeliveryExit=%s\\nDeliveryDirectory=%s\\nDeliveryLog=%s\\n" "$delivery_exit" "$delivery" "$delivery_log" | tee -a "$delivery_log"; exit "$delivery_exit"' EXIT
code_commit=__COMMIT__
code_root=__ROOT__
paths=(__PATHS__)
names=(__NAMES__)
transfer_started=$SECONDS
for index in __INDICES__; do
  if (( SECONDS-transfer_started >= 180 )); then printf '%s\\n' 'STOP: trasferimento codice fuori finestra.'; exit 2; fi
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 3 --connect-timeout 10 --max-time 20 --max-filesize 131072 \\
    "https://raw.githubusercontent.com/GioNob/ouf-deploy/$code_commit/${paths[$index]}" -o "$delivery/${names[$index]}"
done
sudo /usr/bin/python3 -I -S -B - "$delivery" "$operator_uid" <<'PY' 2>&1 | tee -a "$delivery_log"
import hashlib,json,os,pwd,stat,sys
folder,owner=sys.argv[1],int(sys.argv[2]);directory='__ROOT__';scope='__SCOPE__'
specs=__SPECS__
if os.geteuid()!=os.getegid()or os.geteuid()!=0 or owner!=pwd.getpwnam('oufadmin').pw_uid or owner<=0:
    raise SystemExit('STOP: identita operatore/root non valida')
if os.path.lexists(scope)or os.path.lexists(directory):
    raise SystemExit('STOP: consegna o esecuzione consumata; conservare prove, nessun rilancio')
for path in ('/','/usr','/usr/local','/usr/local/lib'):
    row=os.lstat(path)
    if not stat.S_ISDIR(row.st_mode)or row.st_uid!=row.st_gid or row.st_uid!=0 or row.st_mode&0o022:
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
manifest=json.dumps({s['name']:s['sha256']for s in specs},sort_keys=True,separators=(',',':')).encode()
if hashlib.sha256(manifest).hexdigest()!='__CLOSURE__':raise SystemExit('STOP: chiusura codice non valida')
os.mkdir(directory,0o700)
for name,raw in [*raws.items(),('sources.json',manifest)]:
    target=os.path.join(directory,name);fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
    with os.fdopen(fd,'wb')as out:
        os.fchmod(out.fileno(),0o400);out.write(raw);out.flush();os.fsync(out.fileno())
    fd=os.open(target,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        row=os.fstat(fd)
        if row.st_uid!=row.st_gid or row.st_uid!=0 or row.st_nlink!=1 or stat.S_IMODE(row.st_mode)!=0o400 or hashlib.sha256(os.read(fd,131073)).hexdigest()!=hashlib.sha256(raw).hexdigest():
            raise SystemExit('STOP: copia root non verificata')
    finally:os.close(fd)
    print(target+': OK (root0400; checksum ROOT)')
for path in (directory,'/usr/local/lib'):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
print('ProtectedCode='+directory+'/entry.py')
print('RuntimeLog='+directory+'/operator.log')
PY
printf '%s\\n' 'Nuovo controller SOLO Onboarding36-38,pianob03d681a/05e1398d,12peer invariati. Review fresca prima di firme/7SQL READ ONLY/import/lifecycle;backup quiescente e due migrazioni del solo owner. Attendere review/riga APPROVO sul TTY. Zero ownership/grant/budget/resume/job/upload/acquisizioni. SeSTOP conservare prove e non rilanciare.' | tee -a "$delivery_log"
set +e
# Stdio resta direttamente sul TTY: il Logger root conserva l output; nessuna pipe/consenso nella consegna.
sudo /usr/bin/python3 -I -S -B "$code_root/entry.py"
apply_exit=$?
set -e
printf 'Exit=%s\\nDirectory=%s\\nLog=%s\\nRuntimeLog=%s\\n' "$apply_exit" "$delivery" "$delivery_log" "$code_root/operator.log" | tee -a "$delivery_log"
exit "$apply_exit"
'''
for key,value in {'COMMIT':info['sourceCommit'],'ROOT':root,'SCOPE':info['executionRoot'],'PATHS':'\n  '.join(x['path']for x in specs),'NAMES':' '.join(x['name']for x in specs),'INDICES':' '.join(map(str,range(len(specs)))),'SPECS':json.dumps(specs,separators=(',',':')),'CLOSURE':closure}.items():shell=shell.replace('__'+key+'__',value)
Path('releases/apply-managed-file-owner-v38-20261028.sh').write_text(shell)
info['wrapperSha256']=hashlib.sha256(shell.encode()).hexdigest()
Path('releases/managed-file-owner-v38-update-delivery-pins-20261028.json').write_text(encoded(info)+'\n')
print(json.dumps({'codeRoot':root,'sourceClosureHash':closure,'sourceFiles':len(specs),'wrapperSha256':hashlib.sha256(shell.encode()).hexdigest()}))
