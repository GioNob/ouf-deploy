#!/usr/bin/env bash
# Installation-specific PREPARATION ONLY. No deployment, HUMAN login or replay.
set -euo pipefail
umask 077
ouf_postboot_code='/home/oufadmin/ouf-deploy-runner/_work/ouf-deploy/ouf-source-revision-postboot-code-39164421815'
[ -d "$ouf_postboot_code" ] && [ ! -L "$ouf_postboot_code" ] || { echo 'Pacchetto qualificato assente: fermarsi.' >&2; exit 1; }
ouf_postboot_log="$(mktemp -d "$HOME/ouf-source-revision-postboot.XXXXXXXX")"
printf '%s\n' 'Tecniche8/8; funzionali4/6. Preparazione privata postboot, massimo300 secondi.' 'Verifico il recupero host gia completato, gli input originali, le generazioni correnti e il provider vuoto/revocato.' 'Verifico entrambi i contesti f6w3lo6z e q7bq1ex3 (180file); conservo tutto e preparo il successore JSON/sessione qualificato.' 'Nessun login HUMAN, authority, avvio/stop servizi, migrazione, pubblicazione o retry job.' 'Dopo STOP non rilanciare: conservare il log per riconciliazione.' "Log: $ouf_postboot_log/run.log"
sudo /usr/bin/python3 -u -I -B -S - "$ouf_postboot_code" <<'OUF_POSTBOOT_PREPARATION' | tee "$ouf_postboot_log/run.log"
import hashlib,json,os,re,stat,sys
from pathlib import Path

def read(path,expected):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  first=os.fstat(fd)
  if not stat.S_ISREG(first.st_mode) or first.st_nlink!=1 or not 0<first.st_size<=262144:raise ValueError('PREPARATION_DELIVERY_CUSTODY')
  with os.fdopen(os.dup(fd),'rb') as stream:raw=stream.read(262145)
  pin=lambda s:tuple(getattr(s,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
  if len(raw)!=first.st_size or pin(first)!=pin(os.fstat(fd)) or pin(first)!=pin(Path(path).lstat()) or hashlib.sha256(raw).hexdigest()!=expected:raise ValueError('PREPARATION_DELIVERY_CHANGED')
  return raw
 finally:os.close(fd)
try:
 if os.geteuid()!=0 or os.getegid()!=0 or not(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode) or len(sys.argv)!=2:raise ValueError('ISOLATED_ROOT_PREPARATION_REQUIRED')
 code=Path(sys.argv[1]);sha='dc310b977508915af520792d48e1bf970abcdffcf2b4a6d9b33a8c72f77c4ccf'
 manifest=json.loads(read(code/'manifest.json',sha))
 if manifest['sourceCommit']!='6f8493ec372f8ca3e12c8a4e6df19552e28fd383':raise ValueError('EXACT_POSTBOOT_SOURCE_REQUIRED')
 raw=read(code/'run.py',manifest['files']['run.py'])
 sys.argv=[str(code/'run.py'),str(code),sha]
 exec(compile(raw,'<verified-postboot-preparation>','exec'),{'__name__':'__main__'})
except (Exception,KeyboardInterrupt) as error:
 print(json.dumps({'schema':'ouf.postboot-delivery-stop.v1','complete':False,'errorClass':type(error).__name__,'rawErrorPrinted':False,'runtimeAuthorityIssued':False,'automaticRetry':False,'budgetReset':False}),flush=True)
 raise SystemExit(2)
OUF_POSTBOOT_PREPARATION
