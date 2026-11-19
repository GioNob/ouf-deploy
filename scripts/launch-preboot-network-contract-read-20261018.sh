#!/usr/bin/env bash
# One finite read of sealed preboot contracts; no runtime operation.
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [ ! -x "$ouf_gh" ]; then ouf_gh="$(command -v gh || true)"; fi
[ -n "$ouf_gh" ] && [ -x "$ouf_gh" ] || { echo 'Client GitHub non disponibile.' >&2; exit 1; }
ouf_case="$(mktemp -d "$HOME/ouf-preboot-network-read.XXXXXXXX")"
ouf_source=3b10bb25344bf19c32263fcc579e1cad4cffe6a0
for ouf_pair in 'scripts/read-preboot-network-contract.py:read.py' 'releases/preboot-network-contract-read-selection-20261018.json:selection.json'; do
  ouf_path="${ouf_pair%:*}";ouf_name="${ouf_pair#*:}"
  "$ouf_gh" api "repos/GioNob/ouf-deploy/contents/$ouf_path?ref=$ouf_source" --jq .content | base64 --decode > "$ouf_case/$ouf_name"
done
printf '%s\n' 'Tecniche 8/8; funzionali 4/6. Leggo i contratti di rete sigillati prima del riavvio.' 'Confronto necessario per UDP/APISIX e Semantic/MinIO; nessun indirizzo sostitutivo scelto.' 'Nessun login OUF, grant, riavvio, modifica rete, migrazione, pubblicazione o retry job.' "Log: $ouf_case/read.log"
sudo /usr/bin/python3 -I -B -S - "$ouf_case" <<'OUF_VERIFIED_PREBOOT_NETWORK_READ' | tee "$ouf_case/read.log"
import hashlib,json,os,signal,stat,sys,traceback,types
from pathlib import Path

def verified(path,expected):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  first=os.fstat(fd)
  if not stat.S_ISREG(first.st_mode)or first.st_nlink!=1 or not 0<first.st_size<=65536:raise ValueError('DELIVERY_CUSTODY')
  raw=os.read(fd,65537);last=os.fstat(fd);fingerprint=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
  if len(raw)!=first.st_size or fingerprint(first)!=fingerprint(last)or hashlib.sha256(raw).hexdigest()!=expected:raise ValueError('DELIVERY_CHANGED')
  return raw
 finally:os.close(fd)
try:
 if os.geteuid()!=0 or os.getegid()!=0 or not(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode)or len(sys.argv)!=2:raise ValueError('ISOLATED_ROOT_REQUIRED')
 signal.alarm(90);root=Path(sys.argv[1])
 raw=verified(root/'read.py','997b3ba99a474c051efb32cfd69dc706de68ade1d332609f577955f58f0d3c79')
 selection=verified(root/'selection.json','e7d72bfd63b182919f2b34088408950ef39a2b59f89600abca54c397643259af')
 module=types.ModuleType('verified_preboot_network_read');module.__file__=str(root/'read.py')
 exec(compile(raw,'<verified-preboot-network-read>','exec'),module.__dict__)
 result=module.collect(json.loads(selection,object_pairs_hook=module.unique))
 print(json.dumps(result,sort_keys=True));sys.exit(0 if result['complete']else 2)
except Exception as error:
 print(json.dumps({'check':'STOP','schema':'ouf.preboot-network-contract-read.v1','complete':False,'errorClass':type(error).__name__,'exceptionMessagePrinted':False,'runtimeMutations':0,'runtimeAuthorityIssued':False,'frames':[{'file':Path(f.filename).name,'function':f.name,'line':f.lineno}for f in traceback.extract_tb(error.__traceback__)[-4:]]},sort_keys=True));sys.exit(2)
OUF_VERIFIED_PREBOOT_NETWORK_READ
