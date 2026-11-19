#!/usr/bin/env bash
# One explicit corrective successor, preserving the existing stopped incident and native authority.
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [ ! -x "$ouf_gh" ]; then ouf_gh="$(command -v gh || true)"; fi
[ -n "$ouf_gh" ] && [ -x "$ouf_gh" ] || { echo 'Client GitHub non disponibile.' >&2; exit 1; }
ouf_case="$(mktemp -d "$HOME/ouf-boot-journal-resume.XXXXXXXX")"
ouf_source=8ace6a38770cffba55bfc9dc8f2c08db936c31e9
for ouf_pair in 'scripts/read-source-revision-boot-guard.py:reader.py' 'scripts/resume-semantic-boot-journal.py:resume.py' 'releases/source-revision-boot-read-selection-20261018.json:selection.json' 'releases/boot-journal-recovery-selection-20261018.json:recovery.json'; do
  ouf_path="${ouf_pair%:*}";ouf_name="${ouf_pair#*:}"
  "$ouf_gh" api "repos/GioNob/ouf-deploy/contents/$ouf_path?ref=$ouf_source" --jq .content | base64 --decode > "$ouf_case/$ouf_name"
done
printf '%s\n' 'Tecniche 8/8; funzionali 4/6. Riconcilio il tentativo fermato, senza ripetere la creazione del lock.' 'Conservo ProtectSystem=strict; abilito il solo journal atomico e mantengo i file adiacenti in sola lettura.' 'Un solo avvio Docker attraverso la guardia originale; container e processi esistenti possono ripartire.' 'Nessuna nuova authority OUF, migrazione, pubblicazione o ripresa esplicita di job.' 'Dopo STOP non rilanciare: il successore resta nel medesimo incidente persistente.' "Log: $ouf_case/resume.log"
sudo /usr/bin/python3 -I -B -S - "$ouf_case" <<'OUF_VERIFIED_BOOT_JOURNAL_RESUME' | tee "$ouf_case/resume.log"
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
      'resume.py':'ea0e0bb3bf3118fac671bece7de916a63ca5132f0805ecb1bd0d66cea1558670',
      'selection.json':'36c47400fc3dc7669b04d6bc18e204a70ca7502f3749d8d92a292ddf4bdc0978',
      'recovery.json':'4a6136b71053ec72edd63fce561fa80f7ac0c9d620f772369e3577c25d371c97'}.items():payload[name]=verified(root/name,digest)
    modules={}
    for name in ('reader','resume'):
        module=types.ModuleType('verified_'+name);module.__file__=str(root/(name+'.py'))
        exec(compile(payload[name+'.py'],'<verified-'+name+'>','exec'),module.__dict__);modules[name]=module
    reader=modules['reader'];selection=reader.parse(payload['selection.json']);profile=reader.parse(payload['recovery.json'])
    value=modules['resume'].preflight(reader,selection,profile)
    print(json.dumps({'check':'RECONCILED_PREFLIGHT_PASSED','previousContext':str(value['case']),
      'journalDirectory':str(value['journal'].parent),'protectedSiblingCount':len(value['siblings']),
      'managedDropin':str(value['target']),'dropinSha256':hashlib.sha256(value['raw']).hexdigest(),
      'protectSystemStrictRetained':True,'runtimeAuthorityIssued':False,'maximumStartAttempts':1},sort_keys=True),flush=True)
    result=modules['resume'].apply(reader,value);print(json.dumps(result,sort_keys=True));sys.exit(0 if result['complete']else 2)
except Exception as error:
    result={'check':'STOP','errorClass':type(error).__name__,'exceptionMessagePrinted':False,
      'automaticRetry':False,'reconciliationRequired':True,'runtimeAuthorityIssued':False,
      'completedTechnicalPhases':8,'functionalMilestonesProven':4,
      'frames':[{'file':Path(f.filename).name,'function':f.name,'line':f.lineno}for f in traceback.extract_tb(error.__traceback__)[-4:]]}
    if type(error)is ValueError and re.fullmatch('[A-Z_]{1,80}',str(error)):result['reason']=str(error)
    print(json.dumps(result,sort_keys=True));sys.exit(2)
OUF_VERIFIED_BOOT_JOURNAL_RESUME
