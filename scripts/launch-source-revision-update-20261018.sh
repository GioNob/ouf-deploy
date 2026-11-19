#!/usr/bin/env bash
# Installation-specific, one finite release; no automatic retry.
set -euo pipefail
umask 077
ouf_code='/home/oufadmin/ouf-deploy-runner/_work/ouf-deploy/ouf-source-revision-code-39107413248'
[ -d "$ouf_code" ] && [ ! -L "$ouf_code" ] || { echo 'Pacchetto qualificato assente: fermarsi.' >&2; exit 1; }
ouf_stage="$(mktemp -d "$HOME/ouf-source-revision-update.XXXXXXXX")"
echo "Log della sessione: $ouf_stage/run.log"
echo 'Uso la preparazione protetta gia completata; nessuna ripetizione del lavoro precedente.'
echo 'Tecniche8/8; funzionali4/6. Onboarding33->34 e MCP; backup verificato, due rotte additive e relativi permessi nativi.'
echo 'Le immagini sono gia sotto custodia. UDP e Ingestion invariati. Nessuna pubblicazione del profilo o ripresa job.'
echo 'La conferma del ruolo avviene nella THS nativa quando mostrata; il programma attende con controlli limitati.'
echo 'Se HUMAN e scaduto: RIAPRO LOGIN e autenticazione browser; poi APPROVO per la revisione precisa mostrata dal programma.'
echo 'Lascia il terminale aperto. Dopo APPROVO massimo15 minuti. Dopo STOP non rilanciare: conservare il log per riconciliazione.'
sudo /usr/bin/python3 -u -I -B -S - "$ouf_code" <<'ROOTPY' 2>&1 | tee "$ouf_stage/run.log"
import hashlib,json,os,re,stat,sys,tempfile
from pathlib import Path
assert os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site
os.umask(0o077)
source=Path(sys.argv[1])
def read(name,expected,maximum=262144):
 assert re.fullmatch('[A-Za-z0-9_.-]+',name)
 fd=os.open(source/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  before=os.fstat(fd);assert stat.S_ISREG(before.st_mode)and before.st_nlink==1 and 0<before.st_size<=maximum
  raw=bytearray()
  while len(raw)<=maximum:
   part=os.read(fd,min(65536,maximum+1-len(raw)))
   if not part:break
   raw.extend(part)
  pin=lambda s:tuple(getattr(s,k)for k in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
  assert len(raw)==before.st_size and pin(before)==pin(os.fstat(fd))and hashlib.sha256(raw).hexdigest()==expected
  return bytes(raw)
 finally:os.close(fd)
manifest_raw=read('package.json','6d96003f48df54d2c9e13b64a496c87b04e8ec7b13e8a2de10be5a3fc6cdfeb0');package=json.loads(manifest_raw)
assert package['sourceCommit']=='242c9656ce6a0daefc25482484db5450c8ee615b'
files={'package.json':manifest_raw,'execute.py':read('execute.py',package['executorSha256']),
 'runtime.py':read('runtime.py',package['loaderSha256']),'case.json':read('case.json',package['caseSha256'])}
# Only this verified bootstrap's static overlay declaration selects source names.
ns={'__name__':'readiness_stage_metadata'};exec(compile(files['execute.py'],'<verified-bootstrap-stage>','exec'),ns)
assert set(package['sourceHashes'])==set(ns['OVERLAYS'])
for module,(name,path)in ns['OVERLAYS'].items():files[name]=read(name,package['sourceHashes'][module])
parent=Path('/etc/ouf/deploy-snapshots')
for p in(parent,*parent.parents):
 s=p.lstat();assert stat.S_ISDIR(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022
code=Path(tempfile.mkdtemp(prefix='source-revision-executor-code-',dir=parent));code.chmod(0o700)
for name,raw in files.items():
 fd=os.open(code/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  with os.fdopen(os.dup(fd),'wb')as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
 finally:os.close(fd)
fd=os.open(code,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
try:os.fsync(fd)
finally:os.close(fd)
print('OUF_SOURCE_REVISION_EXECUTOR_CODE='+str(code),flush=True)
sys.argv=[str(code/'execute.py'),str(code),'242c9656ce6a0daefc25482484db5450c8ee615b','6d96003f48df54d2c9e13b64a496c87b04e8ec7b13e8a2de10be5a3fc6cdfeb0']
exec(compile(files['execute.py'],'<verified-scoped-readiness-bootstrap>','exec'),{'__name__':'__main__'})
ROOTPY
