#!/usr/bin/env bash
# Distinct finite HUMAN Gateway action: add two READ routes; keep all containers.
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [[ ! -x "$ouf_gh" ]]; then ouf_gh="$(command -v gh || true)"; fi
[[ -n "$ouf_gh" && -x "$ouf_gh" ]] || { echo 'STOP: client GitHub approvato non disponibile; nessun sudo.' >&2; exit 1; }
ouf_commit='8e47f464bca7ff994075917a8be929a9bf42413d'
ouf_delivery="$(mktemp -d "$HOME/ouf-ingestion-gateway-custody.XXXXXXXX")"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/tools/mcp_read_transport_gateway82/entry.py?ref=8e47f464bca7ff994075917a8be929a9bf42413d" --jq .content | base64 --decode > "$ouf_delivery/entry.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/tools/mcp_read_transport_gateway82/authority.py?ref=8e47f464bca7ff994075917a8be929a9bf42413d" --jq .content | base64 --decode > "$ouf_delivery/authority.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/tools/mcp_read_transport_gateway82/owner.py?ref=8e47f464bca7ff994075917a8be929a9bf42413d" --jq .content | base64 --decode > "$ouf_delivery/owner.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/tools/mcp_read_transport_gateway82/native.py?ref=8e47f464bca7ff994075917a8be929a9bf42413d" --jq .content | base64 --decode > "$ouf_delivery/native.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/tools/mcp_read_transport_gateway82/runtime.py?ref=8e47f464bca7ff994075917a8be929a9bf42413d" --jq .content | base64 --decode > "$ouf_delivery/runtime.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/scripts/prepare-mcp-read-transport-gateway82.py?ref=8e47f464bca7ff994075917a8be929a9bf42413d" --jq .content | base64 --decode > "$ouf_delivery/prepare.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/scripts/execute-mcp-read-transport-gateway82.py?ref=8e47f464bca7ff994075917a8be929a9bf42413d" --jq .content | base64 --decode > "$ouf_delivery/bootstrap.py"
printf '%s  %s\n' \
 'c88c16d8f82cab61ede9bfbf1830c3d56489c5c78a83baf3f36d2c0ce50ada87' "$ouf_delivery/entry.py" \
 '04a8c3e08e54b6318083e9c3e7a580194f218d18e6b2f528e4f084b9b2dba495' "$ouf_delivery/authority.py" \
 '9cebe572e89e5b6aada0fc1273b169184d2de17b1ab7739d2fd8661093b24810' "$ouf_delivery/owner.py" \
 'aa4d7d7fa57f529ca9c44736336f48928f6b122d200d8d96c6cc60977b7897a0' "$ouf_delivery/native.py" \
 'f8010f49fcd1651ea5858b2fe56018eb505b2ca5d1be9947264dc10757256c35' "$ouf_delivery/runtime.py" \
 '18c86ce344f9f0f83dd89e79c987930a25063fe6cd7143e2db19f0f3e3301364' "$ouf_delivery/prepare.py" \
 'ff1a7efa8f536e01b2486f9658cd5576189d7c1ba4182b7eb6805a7c12a2f050' "$ouf_delivery/bootstrap.py" | sha256sum --check
printf '%s\n' 'Tecniche8/8; funzionali4/6. Aggiornamento distinto del SOLO MCP; Gateway82 invariato.'  'Sostituzione immagine MCP a79b139 con 1f2c28d gia qualificata; vecchio container conservato fermo.'  'Metadati0440 immutati, nessuna migrazione/PUT Gateway/IAM/grant/policy47/attivazione fonte/job.'  'HUMAN229/256 ultima osservazione; nessun nuovo login, budget o finestra; scadenza15:15:03 italiane.'  'AMMISSIONE:20minuti residui nella finestra originaria, quindi avvio prima14:55:03 del19ottobre2026.'  'Dopo tale limite: NON LANCIARE. Occorre prima una distinta continuazione HUMAN governata.'  'Gate APPROVO + hash sul piano corrente; nessun replay dopo STOP/interruzione.'  "Log privato: $ouf_delivery/run.log"
sudo /usr/bin/python3 -u -I -B -S - "$ouf_delivery" "$ouf_commit" <<'OUF_GATEWAY_CUSTODY_CORRECTED' | tee "$ouf_delivery/run.log"
import ast,hashlib,json,os,re,sys
from pathlib import Path
directory=Path(sys.argv[1]);commit=sys.argv[2]
expected={'entry': 'c88c16d8f82cab61ede9bfbf1830c3d56489c5c78a83baf3f36d2c0ce50ada87', 'authority': '04a8c3e08e54b6318083e9c3e7a580194f218d18e6b2f528e4f084b9b2dba495', 'owner': '9cebe572e89e5b6aada0fc1273b169184d2de17b1ab7739d2fd8661093b24810', 'native': 'aa4d7d7fa57f529ca9c44736336f48928f6b122d200d8d96c6cc60977b7897a0', 'runtime': 'f8010f49fcd1651ea5858b2fe56018eb505b2ca5d1be9947264dc10757256c35', 'prepare': '18c86ce344f9f0f83dd89e79c987930a25063fe6cd7143e2db19f0f3e3301364', 'bootstrap': 'ff1a7efa8f536e01b2486f9658cd5576189d7c1ba4182b7eb6805a7c12a2f050'}
filenames={'entry': 'entry.py', 'authority': 'authority.py', 'owner': 'owner.py', 'native': 'native.py', 'runtime': 'runtime.py', 'prepare': 'prepare.py', 'bootstrap': 'bootstrap.py'}
codes=set()
try:
 if commit!='8e47f464bca7ff994075917a8be929a9bf42413d':raise ValueError()
 delivery={}
 for name,wanted in expected.items():
  fd=os.open(directory/filenames[name],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
  try:
   with os.fdopen(os.dup(fd),'rb')as stream:raw=stream.read(262145)
  finally:os.close(fd)
  if not 0<len(raw)<=262144 or hashlib.sha256(raw).hexdigest()!=wanted:raise ValueError()
  delivery[name]=raw
 codes={n.value for n in ast.walk(ast.parse(delivery['prepare']))if isinstance(n,ast.Constant)and type(n.value)is str and re.fullmatch('[A-Z][A-Z0-9_]{2,159}',n.value)}
 namespace={'__name__':'verified_distinct_gateway_custody_preparation'}
 exec(compile(delivery['prepare'],'<verified-distinct-gateway-read-preparation>','exec'),namespace)
 namespace['main'](delivery,commit)
except (Exception,KeyboardInterrupt)as error:
 print(json.dumps({'schema':'ouf.mcp-read-transport-gateway82-preparation-stop.v1','status':'STOP_RECONCILE',
  'exceptionClass':type(error).__name__,'reasonCode':str(error)if str(error)in codes else'PRIVATE_DETAILS_REDACTED',
  'phase':'PREPARATION','automaticReplayAllowed':False,'budgetReset':False,'runtimeCompletionProven':False}),flush=True)
 raise SystemExit(2)
OUF_GATEWAY_CUSTODY_CORRECTED
