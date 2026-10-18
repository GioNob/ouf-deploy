#!/usr/bin/env bash
# Installation-specific host recovery; invokes the existing sealed guard, never replaces it.
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [ ! -x "$ouf_gh" ]; then ouf_gh="$(command -v gh || true)"; fi
[ -n "$ouf_gh" ] && [ -x "$ouf_gh" ] || { echo 'Client GitHub non disponibile.' >&2; exit 1; }
ouf_case="$(mktemp -d "$HOME/ouf-boot-lock-recovery.XXXXXXXX")"
ouf_source=6b4efc97fe522b4476452401a70afd1077465687
for ouf_pair in 'scripts/read-source-revision-boot-guard.py:reader.py' 'scripts/repair-semantic-boot-lock.py:repair.py' 'releases/source-revision-boot-read-selection-20261018.json:selection.json' 'releases/semantic-boot-lock-recovery-selection-20261018.json:recovery.json'; do
  ouf_path="${ouf_pair%:*}";ouf_name="${ouf_pair#*:}"
  "$ouf_gh" api "repos/GioNob/ouf-deploy/contents/$ouf_path?ref=$ouf_source" --jq .content | base64 --decode > "$ouf_case/$ouf_name"
done
printf '%s\n' 'Tecniche 8/8; funzionali 4/6. Ripristino amministrativo circoscritto del boot.' 'Verifico prima profili, sorgenti, stato e lock assente; installo la creazione del lock al boot.' 'Avvio Docker attraverso la guardia originale: i container esistenti possono ripartire.' 'Nessuna nuova authority OUF, pubblicazione profilo, migrazione o ripresa esplicita di job.' 'Dopo STOP non rilanciare: occorre riconciliare il journal persistente.' "Log: $ouf_case/recovery.log"
sudo /usr/bin/python3 -I -B -S - "$ouf_case" <<'OUF_VERIFIED_BOOT_RECOVERY' | tee "$ouf_case/recovery.log"
import hashlib,json,os,re,signal,stat,sys,traceback,types
from pathlib import Path
def verified(path,expected):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        first=os.fstat(fd)
        if not stat.S_ISREG(first.st_mode)or first.st_nlink!=1 or not 0<=first.st_size<=65536:raise ValueError('DELIVERY_CUSTODY')
        raw=os.read(fd,65537);last=os.fstat(fd)
        pin=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        if len(raw)!=first.st_size or pin(first)!=pin(last)or hashlib.sha256(raw).hexdigest()!=expected:raise ValueError('DELIVERY_CHANGED')
        return raw
    finally:os.close(fd)
try:
    if os.geteuid()!=0 or os.getegid()!=0 or not(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode)or len(sys.argv)!=2:raise ValueError('ISOLATED_ROOT_REQUIRED')
    signal.alarm(300);root=Path(sys.argv[1]);payload={}
    for name,digest in {'reader.py':'c63ee1872d4e78c16bead93c80c0c0fefa694814222a89cf93d23e084b4b63fd',
      'repair.py':'cab86f80059c58f38084d3fc554ea5ae549a993ac8fd7753a47fff698b81ae14',
      'selection.json':'36c47400fc3dc7669b04d6bc18e204a70ca7502f3749d8d92a292ddf4bdc0978',
      'recovery.json':'acc0e51e4782f7700a89049085af7b6e435332e48bd1a70220e65569b78aeb8a'}.items():payload[name]=verified(root/name,digest)
    modules={}
    for name in ('reader','repair'):
        module=types.ModuleType('verified_'+name);module.__file__=str(root/(name+'.py'))
        exec(compile(payload[name+'.py'],'<verified-'+name+'>','exec'),module.__dict__);modules[name]=module
    reader=modules['reader'];recovery=reader.parse(payload['recovery.json'])
    plan=modules['repair'].plan(reader,reader.parse(payload['selection.json']),recovery)
    print(json.dumps({'check':'PREFLIGHT_PASSED','commonLockFile':str(plan['lock']),
      'artifactHashes':{str(p):hashlib.sha256(raw).hexdigest()for p,raw in plan['files'].items()},
      'nativeGuardUnchanged':True,'existingServicesMayAutoResume':True,'runtimeAuthorityIssued':False},sort_keys=True),flush=True)
    result=modules['repair'].apply(reader,plan)
    print(json.dumps(result,sort_keys=True));sys.exit(0 if result['complete']else 2)
except Exception as error:
    result={'check':'STOP','errorClass':type(error).__name__,'exceptionMessagePrinted':False,
      'automaticRetry':False,'reconciliationRequired':True,'runtimeAuthorityIssued':False,
      'completedTechnicalPhases':8,'functionalMilestonesProven':4,
      'frames':[{'file':Path(f.filename).name,'function':f.name,'line':f.lineno}for f in traceback.extract_tb(error.__traceback__)[-4:]]}
    if type(error)is ValueError and re.fullmatch('[A-Z_]{1,80}',str(error)):result['reason']=str(error)
    print(json.dumps(result,sort_keys=True));sys.exit(2)
OUF_VERIFIED_BOOT_RECOVERY
