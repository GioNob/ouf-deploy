#!/usr/bin/env bash
# Installation-specific finite host-administrator correction; no OUF authority.
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [ ! -x "$ouf_gh" ]; then ouf_gh="$(command -v gh || true)"; fi
[ -n "$ouf_gh" ] && [ -x "$ouf_gh" ] || { echo 'Client GitHub non disponibile.' >&2; exit 1; }
ouf_case="$(mktemp -d "$HOME/ouf-host-network-correction.XXXXXXXX")"
ouf_source=cc293d0b9859abd92a1ff62fdc05dcfef97c3569
for ouf_pair in 'tools/host_network_reconciliation.py:owner.py' 'scripts/reconcile-host-network-20261018.py:bootstrap.py' 'releases/host-network-reconciliation-20261018.json:installation.json' 'releases/host-network-reconciliation-execution-20261018.json:execution.json' 'scripts/read-source-revision-boot-guard.py:guard_reader.py' 'releases/source-revision-boot-read-selection-20261018.json:guard_selection.json' 'scripts/read-preboot-network-contract.py:contracts.py' 'releases/preboot-network-contract-read-selection-20261018.json:contracts_selection.json'; do
  ouf_path="${ouf_pair%:*}";ouf_name="${ouf_pair#*:}"
  "$ouf_gh" api "repos/GioNob/ouf-deploy/contents/$ouf_path?ref=$ouf_source" --jq .content | base64 --decode > "$ouf_case/$ouf_name"
done
(
cd "$ouf_case"
printf '%s\n' '06d11ae791d497c701caa75c7b0d164fa4d44017727e3f977d10af1c04809511  owner.py' \
  '258097c4927b503c7c7dc114dbf194f9c0eb391df17bb6440dc64e92bfccb272  bootstrap.py' \
  '92ef26cbc1341c3d7de15fac7ed8d1856a0bc6d03b859d16e4a86ba2a22f2afb  installation.json' \
  '0f06b63f51d068e74f09477e56493b2197880f76e7929796b11085cbd1427b74  execution.json' \
  'c63ee1872d4e78c16bead93c80c0c0fefa694814222a89cf93d23e084b4b63fd  guard_reader.py' \
  '36c47400fc3dc7669b04d6bc18e204a70ca7502f3749d8d92a292ddf4bdc0978  guard_selection.json' \
  '997b3ba99a474c051efb32cfd69dc706de68ade1d332609f577955f58f0d3c79  contracts.py' \
  'e7d72bfd63b182919f2b34088408950ef39a2b59f89600abca54c397643259af  contracts_selection.json' | sha256sum --check -
)
printf '%s\n' 'Tecniche8/8; funzionali4/6. Correzione amministrativa dei sei endpoint dinamici della rete backend.' 'APISIX:5->15; MinIO:6->16. Keycloak2, PostgreSQL3, Caddy4 e Gateway owner8 mantengono gli indirizzi, ora fissi.' 'Stessi container, immagini, processi, volumi, MAC e alias. Reti di controllo/ingresso preservate.' 'Sono possibili brevi interruzioni di rete anche per database, autenticazione e accesso pubblico.' 'Poi un solo avvio del container UDP installato. Worker esistenti possono riprendere; nessun comando retry job.' 'Riconcilia lo STOP senza effetti del primo controllo; verifica tabelle native vuote e authority revocata anche nello stato BLOCKED.' 'Riconcilia il confronto preboot solo se Dns passa da null a lista effettivamente vuota; ogni altro campo resta identico.' 'Nessuna riscrittura del riferimento storico o dei DNS; il piano conserva i valori attuali.' 'Semantic/provider restano subordinati alla riconciliazione nativa; nessuna nuova authority, migrazione o pubblicazione.' 'Massimo300 secondi e13 scritture Docker. Se STOP/non completo: non rilanciare; conservare il log e riconciliare il medesimo incidente.' "Log: $ouf_case/run.log"
sudo /usr/bin/python3 -I -B -S - "$ouf_case" <<'OUF_VERIFIED_HOST_NETWORK_CORRECTION' | tee "$ouf_case/run.log"
import hashlib,json,os,re,signal,stat,sys,traceback,types
from pathlib import Path

def verified(path,expected):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  first=os.fstat(fd)
  if not stat.S_ISREG(first.st_mode)or first.st_nlink!=1 or not 0<first.st_size<=65536:raise ValueError('DELIVERY_CUSTODY')
  raw=os.read(fd,65537);last=os.fstat(fd);pin=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
  if len(raw)!=first.st_size or pin(first)!=pin(last)or hashlib.sha256(raw).hexdigest()!=expected:raise ValueError('DELIVERY_CHANGED')
  return raw
 finally:os.close(fd)
try:
 if os.geteuid()!=0 or os.getegid()!=0 or not(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode)or len(sys.argv)!=2:raise ValueError('ISOLATED_HOST_ADMINISTRATOR_REQUIRED')
 signal.alarm(300);root=Path(sys.argv[1]);hashes={"guard_selection.json":"36c47400fc3dc7669b04d6bc18e204a70ca7502f3749d8d92a292ddf4bdc0978","contracts_selection.json":"e7d72bfd63b182919f2b34088408950ef39a2b59f89600abca54c397643259af","execution.json":"0f06b63f51d068e74f09477e56493b2197880f76e7929796b11085cbd1427b74","contracts.py":"997b3ba99a474c051efb32cfd69dc706de68ade1d332609f577955f58f0d3c79","bootstrap.py":"258097c4927b503c7c7dc114dbf194f9c0eb391df17bb6440dc64e92bfccb272","guard_reader.py":"c63ee1872d4e78c16bead93c80c0c0fefa694814222a89cf93d23e084b4b63fd","owner.py":"06d11ae791d497c701caa75c7b0d164fa4d44017727e3f977d10af1c04809511","installation.json":"92ef26cbc1341c3d7de15fac7ed8d1856a0bc6d03b859d16e4a86ba2a22f2afb"}
 payload={name:verified(root/name,digest)for name,digest in hashes.items()}
 modules={}
 for name in ('owner','bootstrap','guard_reader','contracts'):
  module=types.ModuleType('verified_host_network_'+name);module.__file__=str(root/(name+'.py'))
  exec(compile(payload[name+'.py'],'<verified-host-network-'+name+'>','exec'),module.__dict__);modules[name]=module
 parse=lambda name:json.loads(payload[name+'.json'],object_pairs_hook=modules['contracts'].unique)
 execution=parse('execution');profile=parse('installation')
 if set(execution)!={'schema','privateParent','incidentPointer','maximumSeconds','maximumEngineWrites','finiteProfileReason'}or execution['schema']!='ouf.host-network-reconciliation-execution.v1' or type(execution['maximumSeconds'])is not int or not 10<=execution['maximumSeconds']<=300 or execution['maximumEngineWrites']!=2*len(profile['moves'])+1:raise ValueError('EXACT_FINITE_EXECUTION_PROFILE_REQUIRED')
 signal.alarm(execution['maximumSeconds'])
 result=modules['bootstrap'].run(modules['owner'],modules['guard_reader'],modules['contracts'],profile,parse('guard_selection'),parse('contracts_selection'),execution['privateParent'],execution['incidentPointer'])
 print(json.dumps(result,sort_keys=True));sys.exit(0 if result['complete']else 2)
except (Exception,KeyboardInterrupt)as error:
 result={'schema':'ouf.host-network-reconciliation-result.v1','check':'STOP','complete':False,'errorClass':type(error).__name__,'exceptionMessagePrinted':False,'reconciliationRequired':True,'automaticRetry':False,'runtimeAuthorityIssued':False,'completedTechnicalPhases':8,'functionalMilestonesProven':4,'frames':[{'file':Path(f.filename).name,'function':f.name,'line':f.lineno}for f in traceback.extract_tb(error.__traceback__)[-4:]]}
 if type(error)is ValueError and re.fullmatch('[A-Z0-9_]{1,128}',str(error)):result['reason']=str(error)
 print(json.dumps(result,sort_keys=True));sys.exit(2)
OUF_VERIFIED_HOST_NETWORK_CORRECTION
