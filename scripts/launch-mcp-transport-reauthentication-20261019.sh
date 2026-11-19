#!/usr/bin/env bash
# New consent opens one fresh HUMAN login; separate APPROVO gates MCP only.
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [[ ! -x "$ouf_gh" ]]; then ouf_gh="$(command -v gh || true)"; fi
[[ -n "$ouf_gh" && -x "$ouf_gh" ]] || { echo 'STOP: client GitHub approvato non disponibile; nessun sudo.' >&2; exit 1; }
ouf_commit='c9d3ca870c95518c94f754640cd68dc8462c609e'
ouf_delivery="$(mktemp -d "$HOME/ouf-mcp-human-reauthentication.XXXXXXXX")"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/tools/mcp_read_transport_reauthentication/entry.py?ref=c9d3ca870c95518c94f754640cd68dc8462c609e" --jq .content | base64 --decode > "$ouf_delivery/entry.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/tools/mcp_read_transport_reauthentication/authority.py?ref=c9d3ca870c95518c94f754640cd68dc8462c609e" --jq .content | base64 --decode > "$ouf_delivery/authority.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/tools/mcp_read_transport_reauthentication/login.py?ref=c9d3ca870c95518c94f754640cd68dc8462c609e" --jq .content | base64 --decode > "$ouf_delivery/login.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/tools/mcp_read_transport_reauthentication/runtime.py?ref=c9d3ca870c95518c94f754640cd68dc8462c609e" --jq .content | base64 --decode > "$ouf_delivery/runtime.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/scripts/prepare-mcp-ingestion-read-transport-reauthentication.py?ref=c9d3ca870c95518c94f754640cd68dc8462c609e" --jq .content | base64 --decode > "$ouf_delivery/prepare.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/scripts/execute-mcp-ingestion-read-transport.py?ref=f57728d2aa68dc9cf58b86a7f3fad04b45df82dc" --jq .content | base64 --decode > "$ouf_delivery/bootstrap.py"
printf '%s  %s\n' \
 'c95ad3808ec9cd5670248a6ea52797fefe24c150d6f8d8bbcf926802ad81a021' "$ouf_delivery/entry.py" \
 '58d5762d2e4334a08f731b53187d5d6ee60c02e5aa565e4a340427c0f60f03a1' "$ouf_delivery/authority.py" \
 '1b9e2c954f2f38edc02a53a9d18dd707c9a16052b3e68757ca687ac3a8d65e89' "$ouf_delivery/login.py" \
 'd1f6bd770116fabf758c020081a77785e0edc69a4441c846d5da8244d16c9b7b' "$ouf_delivery/runtime.py" \
 'fff697810ee5ab57f513db6ec3682cbcb3bfebac58e6ac2c7527bc63e3518368' "$ouf_delivery/prepare.py" \
 '7ce1e73b83fc433cce966be524600eed5e128ae9e9c36930821184a66638f51c' "$ouf_delivery/bootstrap.py" | sha256sum --check
printf '%s\n' 'Tecniche8/8; funzionali4/6. Azione distinta dopo BLOCKED/REFRESH217.' \
 'Primo gate RIAPRO LOGIN + hash: UNA nuova autenticazione, finestra7200secondi, cumulativo217/256 e39residui.' \
 'Nessun vecchio token/refresh riutilizzato; stessi soggetto, tenant, issuer e7scope. Il provider mantiene tutti i propri controlli.' \
 'Il primo consenso non emette autorita runtime e non cambia servizi, grant/policy47, ruoli o IAM.' \
 'Dopo login verificato: secondo gate APPROVO + hash per il SOLO MCP, con breve indisponibilita.' \
 'Nessuna migrazione, modifica metadati/80rotte, attivazione fonte, acquisizione o job.' \
 'Riutilizzo la stessa immagine privata gia preparata; non rilancio uow4n8lp,1lxoo2ws o mbbleugm.' \
 'Un solo lancio. Dopo STOP/interruzione non ripetere; conservare il log privato.' \
 "Log: $ouf_delivery/run.log"
sudo /usr/bin/python3 -u -I -B -S - "$ouf_delivery" "$ouf_commit" <<'OUF_MCP_REAUTH' | tee "$ouf_delivery/run.log"
import hashlib,json,os,sys
from pathlib import Path
directory=Path(sys.argv[1]);commit=sys.argv[2]
expected={'entry': 'c95ad3808ec9cd5670248a6ea52797fefe24c150d6f8d8bbcf926802ad81a021', 'authority': '58d5762d2e4334a08f731b53187d5d6ee60c02e5aa565e4a340427c0f60f03a1', 'login': '1b9e2c954f2f38edc02a53a9d18dd707c9a16052b3e68757ca687ac3a8d65e89', 'runtime': 'd1f6bd770116fabf758c020081a77785e0edc69a4441c846d5da8244d16c9b7b', 'prepare': 'fff697810ee5ab57f513db6ec3682cbcb3bfebac58e6ac2c7527bc63e3518368', 'bootstrap': '7ce1e73b83fc433cce966be524600eed5e128ae9e9c36930821184a66638f51c'}
try:
 if commit!='c9d3ca870c95518c94f754640cd68dc8462c609e':raise ValueError()
 delivery={}
 for name,wanted in expected.items():
  fd=os.open(directory/(name+'.py'),os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
  try:
   with os.fdopen(os.dup(fd),'rb')as stream:raw=stream.read(262145)
  finally:os.close(fd)
  if not 0<len(raw)<=262144 or hashlib.sha256(raw).hexdigest()!=wanted:raise ValueError()
  delivery[name]=raw
 namespace={'__name__':'verified_distinct_mcp_human_reauthentication_preparation'}
 exec(compile(delivery['prepare'],'<verified-distinct-mcp-reauthentication-preparation>','exec'),namespace)
 namespace['main'](delivery,commit)
except (Exception,KeyboardInterrupt)as error:
 print(json.dumps({'schema':'ouf.mcp-read-transport-reauthentication-stop.v1','status':'STOP_RECONCILE',
  'exceptionClass':type(error).__name__,'reason':'PRIVATE_DETAILS_REDACTED',
  'automaticReplayAllowed':False,'budgetReset':False,'runtimeCompletionProven':False}),flush=True)
 raise SystemExit(2)
OUF_MCP_REAUTH
