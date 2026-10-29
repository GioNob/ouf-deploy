#!/usr/bin/env bash
# Distinct finite HUMAN Gateway action: add two READ routes; keep all containers.
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [[ ! -x "$ouf_gh" ]]; then ouf_gh="$(command -v gh || true)"; fi
[[ -n "$ouf_gh" && -x "$ouf_gh" ]] || { echo 'STOP: client GitHub approvato non disponibile; nessun sudo.' >&2; exit 1; }
ouf_commit='bab8a2d3d7965b9d2de60f13de475e7afad44b8e'
ouf_delivery="$(mktemp -d "$HOME/ouf-ingestion-gateway-read.XXXXXXXX")"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/tools/ingestion_read_gateway_update/entry.py?ref=bab8a2d3d7965b9d2de60f13de475e7afad44b8e" --jq .content | base64 --decode > "$ouf_delivery/entry.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/tools/ingestion_read_gateway_update/authority.py?ref=bab8a2d3d7965b9d2de60f13de475e7afad44b8e" --jq .content | base64 --decode > "$ouf_delivery/authority.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/tools/ingestion_read_gateway_update/owner.py?ref=bab8a2d3d7965b9d2de60f13de475e7afad44b8e" --jq .content | base64 --decode > "$ouf_delivery/owner.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/tools/ingestion_read_gateway_update/compiler.py?ref=bab8a2d3d7965b9d2de60f13de475e7afad44b8e" --jq .content | base64 --decode > "$ouf_delivery/compiler.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/tools/ingestion_read_gateway_update/runtime.py?ref=bab8a2d3d7965b9d2de60f13de475e7afad44b8e" --jq .content | base64 --decode > "$ouf_delivery/runtime.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/scripts/prepare-ingestion-read-gateway-update.py?ref=bab8a2d3d7965b9d2de60f13de475e7afad44b8e" --jq .content | base64 --decode > "$ouf_delivery/prepare.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/scripts/execute-ingestion-read-gateway-update.py?ref=bab8a2d3d7965b9d2de60f13de475e7afad44b8e" --jq .content | base64 --decode > "$ouf_delivery/bootstrap.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/releases/ingestion-read-gateway-compiler-20261019.json?ref=bab8a2d3d7965b9d2de60f13de475e7afad44b8e" --jq .content | base64 --decode > "$ouf_delivery/gateway-data.json"
printf '%s  %s\n' \
 '29bbf1578f6ffaa99eeb5660e0cbe435e820c823f2fba745d1240552147d170a' "$ouf_delivery/entry.py" \
 'c6b9e72bca84dff94a9c6f2c68d715907710549f48d5721d59e1278a36fb285c' "$ouf_delivery/authority.py" \
 '69e7619875a32ffaee9a287ec9213295a81c978b251367250b0bcca3a6868b60' "$ouf_delivery/owner.py" \
 'a0f93d95a632445501826020f9bbf2337a4e75fd417323064168a27bb1a325eb' "$ouf_delivery/compiler.py" \
 'd331b3bfc64eccd79652c67e123c254e4424b3feca8351de678b77b0dd48c882' "$ouf_delivery/runtime.py" \
 '95647281d9b39a6fad118e199e8ac33392f5f833ff87434f6b966e2f7db49dc0' "$ouf_delivery/prepare.py" \
 '17d703d1dd01ff0fe5686b5a1b22fca1b57cbdb08a94e2642236cee97078ce74' "$ouf_delivery/bootstrap.py" \
 '0b3b199922dc72c0074a675b99640d111a44e70802f5c6252068ea92d227401c' "$ouf_delivery/gateway-data.json" | sha256sum --check
printf '%s\n' 'Tecniche8/8; funzionali4/6. NUOVA azione: SOLO due rotte Gateway READ status/history.' \
 '80rotte preservate,82finali; massimo2PUT e readback, nessun replay dopo STOP/interruzione.' \
 'Nessuna modifica/riavvio container MCP/Gateway/Onboarding/UDP/Ingestion, immagine, migrazione, metadati o IAM/grant/policy47.' \
 'Nessuna attivazione fonte, acquisizione, decisione di dominio o job. Aggiornamento MCP separato dopo readback.' \
 'Riutilizzo HUMAN gia autenticato225/256,31residui alla ricevuta; eventuale refresh nativo conserva il cumulativo.' \
 'Nessun nuovo login o budget; scadenza originale15:15:03 italiane del19ottobre2026.' \
 'Preparazione richiede20minuti residui: avvio prima14:55:03, nessuna proroga.' \
 'Gate APPROVO + hash sul piano corrente: autorizza esclusivamente queste due aggiunte Gateway.' \
 'Un solo lancio. Riporta solo ricevute pubbliche o STOP, senza token o log privati.' \
 "Log privato: $ouf_delivery/run.log"
sudo /usr/bin/python3 -u -I -B -S - "$ouf_delivery" "$ouf_commit" <<'OUF_GATEWAY_TWO_READS' | tee "$ouf_delivery/run.log"
import ast,hashlib,json,os,re,sys
from pathlib import Path
directory=Path(sys.argv[1]);commit=sys.argv[2]
expected={'entry': '29bbf1578f6ffaa99eeb5660e0cbe435e820c823f2fba745d1240552147d170a', 'authority': 'c6b9e72bca84dff94a9c6f2c68d715907710549f48d5721d59e1278a36fb285c', 'owner': '69e7619875a32ffaee9a287ec9213295a81c978b251367250b0bcca3a6868b60', 'compiler': 'a0f93d95a632445501826020f9bbf2337a4e75fd417323064168a27bb1a325eb', 'runtime': 'd331b3bfc64eccd79652c67e123c254e4424b3feca8351de678b77b0dd48c882', 'prepare': '95647281d9b39a6fad118e199e8ac33392f5f833ff87434f6b966e2f7db49dc0', 'bootstrap': '17d703d1dd01ff0fe5686b5a1b22fca1b57cbdb08a94e2642236cee97078ce74', 'gateway-data': '0b3b199922dc72c0074a675b99640d111a44e70802f5c6252068ea92d227401c'}
filenames={'entry': 'entry.py', 'authority': 'authority.py', 'owner': 'owner.py', 'compiler': 'compiler.py', 'runtime': 'runtime.py', 'prepare': 'prepare.py', 'bootstrap': 'bootstrap.py', 'gateway-data': 'gateway-data.json'}
codes=set()
try:
 if commit!='bab8a2d3d7965b9d2de60f13de475e7afad44b8e':raise ValueError()
 delivery={}
 for name,wanted in expected.items():
  fd=os.open(directory/filenames[name],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
  try:
   with os.fdopen(os.dup(fd),'rb')as stream:raw=stream.read(262145)
  finally:os.close(fd)
  if not 0<len(raw)<=262144 or hashlib.sha256(raw).hexdigest()!=wanted:raise ValueError()
  delivery[name]=raw
 codes={n.value for n in ast.walk(ast.parse(delivery['prepare']))if isinstance(n,ast.Constant)and type(n.value)is str and re.fullmatch('[A-Z][A-Z0-9_]{2,159}',n.value)}
 namespace={'__name__':'verified_distinct_gateway_read_preparation'}
 exec(compile(delivery['prepare'],'<verified-distinct-gateway-read-preparation>','exec'),namespace)
 namespace['main'](delivery,commit)
except (Exception,KeyboardInterrupt)as error:
 print(json.dumps({'schema':'ouf.ingestion-read-gateway-preparation-stop.v1','status':'STOP_RECONCILE',
  'exceptionClass':type(error).__name__,'reasonCode':str(error)if str(error)in codes else'PRIVATE_DETAILS_REDACTED',
  'phase':'PREPARATION','automaticReplayAllowed':False,'budgetReset':False,'runtimeCompletionProven':False}),flush=True)
 raise SystemExit(2)
OUF_GATEWAY_TWO_READS
