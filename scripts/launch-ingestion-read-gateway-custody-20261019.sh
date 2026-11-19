#!/usr/bin/env bash
# Distinct finite HUMAN Gateway action: add two READ routes; keep all containers.
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [[ ! -x "$ouf_gh" ]]; then ouf_gh="$(command -v gh || true)"; fi
[[ -n "$ouf_gh" && -x "$ouf_gh" ]] || { echo 'STOP: client GitHub approvato non disponibile; nessun sudo.' >&2; exit 1; }
ouf_commit='77033cd6125b633d5d188541f2ddac8366e07db2'
ouf_delivery="$(mktemp -d "$HOME/ouf-ingestion-gateway-custody.XXXXXXXX")"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/tools/ingestion_read_gateway_custody/entry.py?ref=77033cd6125b633d5d188541f2ddac8366e07db2" --jq .content | base64 --decode > "$ouf_delivery/entry.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/tools/ingestion_read_gateway_custody/authority.py?ref=77033cd6125b633d5d188541f2ddac8366e07db2" --jq .content | base64 --decode > "$ouf_delivery/authority.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/tools/ingestion_read_gateway_custody/owner.py?ref=77033cd6125b633d5d188541f2ddac8366e07db2" --jq .content | base64 --decode > "$ouf_delivery/owner.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/tools/ingestion_read_gateway_custody/runtime.py?ref=77033cd6125b633d5d188541f2ddac8366e07db2" --jq .content | base64 --decode > "$ouf_delivery/runtime.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/scripts/prepare-ingestion-read-gateway-custody.py?ref=77033cd6125b633d5d188541f2ddac8366e07db2" --jq .content | base64 --decode > "$ouf_delivery/prepare.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/scripts/execute-ingestion-read-gateway-custody.py?ref=77033cd6125b633d5d188541f2ddac8366e07db2" --jq .content | base64 --decode > "$ouf_delivery/bootstrap.py"
printf '%s  %s\n' \
 '421b16519961747e364eecabd855749db2066d96bccee1caf272bb2681388116' "$ouf_delivery/entry.py" \
 'c7789dd31d576373fb559657bd8c6abd947924338ac61aad1d804eca130f341b' "$ouf_delivery/authority.py" \
 '94fae0b16c6fedeca6c2094ebe25bdf8db44d2ea25e33d00fbe324b27e09b54c' "$ouf_delivery/owner.py" \
 'ab412eea1f0a8082ac15ed4cfcceaa18c79b1a14cc325d16d25ae392dabbff4e' "$ouf_delivery/runtime.py" \
 '98f5657e92642a12c8d60ca9f763f24cb00b6b8725c3d08b416f7cc30e7b57f1' "$ouf_delivery/prepare.py" \
 'fb4acabd81d628918c05d0932cf619885d725f48453497e695d69a10d97a32ff' "$ouf_delivery/bootstrap.py" | sha256sum --check
printf '%s\n' 'Tecniche8/8; funzionali4/6. NUOVO runtime corretto per metadati0440: SOLO due rotte Gateway READ.' \
 '80rotte preservate,82finali; massimo2PUT e readback, nessun replay dopo STOP/interruzione.' \
 'Nessuna modifica/riavvio container MCP/Gateway/Onboarding/UDP/Ingestion, immagine, migrazione, metadati o IAM/grant/policy47.' \
 'Nessuna attivazione fonte, acquisizione, decisione di dominio o job. Aggiornamento MCP separato dopo readback.' \
 'Predecessore senza stage/PUT e autorita scaduta14:35:59: hash di piano, journal e claim originali restano invariati.'  'Metadati0440 letti con hash/custodia esatti; nessun chmod/chown e nessun allargamento del lettore privato0600.'  'HUMAN227/256all ultima osservazione,29residui; eventuale refresh nativo conserva il cumulativo.' \
 'Nessun nuovo login o budget; scadenza originale15:15:03 italiane del19ottobre2026.' \
 'Preparazione richiede20minuti residui: avvio prima14:55:03, nessuna proroga.' \
 'Gate APPROVO + hash sul piano corrente: autorizza esclusivamente queste due aggiunte Gateway.' \
 'Un solo lancio. Riporta solo ricevute pubbliche o STOP, senza token o log privati.' \
 "Log privato: $ouf_delivery/run.log"
sudo /usr/bin/python3 -u -I -B -S - "$ouf_delivery" "$ouf_commit" <<'OUF_GATEWAY_CUSTODY_CORRECTED' | tee "$ouf_delivery/run.log"
import ast,hashlib,json,os,re,sys
from pathlib import Path
directory=Path(sys.argv[1]);commit=sys.argv[2]
expected={'entry': '421b16519961747e364eecabd855749db2066d96bccee1caf272bb2681388116', 'authority': 'c7789dd31d576373fb559657bd8c6abd947924338ac61aad1d804eca130f341b', 'owner': '94fae0b16c6fedeca6c2094ebe25bdf8db44d2ea25e33d00fbe324b27e09b54c', 'runtime': 'ab412eea1f0a8082ac15ed4cfcceaa18c79b1a14cc325d16d25ae392dabbff4e', 'prepare': '98f5657e92642a12c8d60ca9f763f24cb00b6b8725c3d08b416f7cc30e7b57f1', 'bootstrap': 'fb4acabd81d628918c05d0932cf619885d725f48453497e695d69a10d97a32ff'}
filenames={'entry': 'entry.py', 'authority': 'authority.py', 'owner': 'owner.py', 'runtime': 'runtime.py', 'prepare': 'prepare.py', 'bootstrap': 'bootstrap.py'}
codes=set()
try:
 if commit!='77033cd6125b633d5d188541f2ddac8366e07db2':raise ValueError()
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
 print(json.dumps({'schema':'ouf.ingestion-read-gateway-custody-preparation-stop.v1','status':'STOP_RECONCILE',
  'exceptionClass':type(error).__name__,'reasonCode':str(error)if str(error)in codes else'PRIVATE_DETAILS_REDACTED',
  'phase':'PREPARATION','automaticReplayAllowed':False,'budgetReset':False,'runtimeCompletionProven':False}),flush=True)
 raise SystemExit(2)
OUF_GATEWAY_CUSTODY_CORRECTED
