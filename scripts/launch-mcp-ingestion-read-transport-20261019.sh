#!/usr/bin/env bash
# One governed MCP-only update. No old installation/readback/admin replay.
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [[ ! -x "$ouf_gh" ]]; then ouf_gh="$(command -v gh || true)"; fi
[[ -n "$ouf_gh" && -x "$ouf_gh" ]] || { echo 'STOP: client GitHub approvato non disponibile; nessun sudo.' >&2; exit 1; }
ouf_commit='f57728d2aa68dc9cf58b86a7f3fad04b45df82dc'
ouf_delivery="$(mktemp -d "$HOME/ouf-mcp-ingestion-transport.XXXXXXXX")"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/tools/ingestion_read_transport_update/entry.py?ref=f57728d2aa68dc9cf58b86a7f3fad04b45df82dc" --jq .content | base64 --decode > "$ouf_delivery/entry.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/tools/ingestion_read_transport_update/authority.py?ref=f57728d2aa68dc9cf58b86a7f3fad04b45df82dc" --jq .content | base64 --decode > "$ouf_delivery/authority.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/tools/ingestion_read_transport_update/owner.py?ref=f57728d2aa68dc9cf58b86a7f3fad04b45df82dc" --jq .content | base64 --decode > "$ouf_delivery/owner.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/tools/ingestion_read_transport_update/native.py?ref=f57728d2aa68dc9cf58b86a7f3fad04b45df82dc" --jq .content | base64 --decode > "$ouf_delivery/native.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/tools/ingestion_read_transport_update/runtime.py?ref=f57728d2aa68dc9cf58b86a7f3fad04b45df82dc" --jq .content | base64 --decode > "$ouf_delivery/runtime.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/scripts/prepare-mcp-ingestion-read-transport.py?ref=f57728d2aa68dc9cf58b86a7f3fad04b45df82dc" --jq .content | base64 --decode > "$ouf_delivery/prepare.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/scripts/execute-mcp-ingestion-read-transport.py?ref=f57728d2aa68dc9cf58b86a7f3fad04b45df82dc" --jq .content | base64 --decode > "$ouf_delivery/bootstrap.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/scripts/diagnose-ingestion-administrative-preflight.py?ref=0c654ff46d6a44de32557247ae0790873d67d079" --jq .content | base64 --decode > "$ouf_delivery/diagnostic.py"
printf '%s  %s\n' \
 '853ddd61bc03127b533d4b300379d1027afeb0ed1eb4f8198bc19085de1a226c' "$ouf_delivery/entry.py" \
 'b70c9f933e76d3ac5903db79acdc2da4a098b10c794b2e99e7f3827c506f4135' "$ouf_delivery/authority.py" \
 'ab5fac08412ba2ce0bf63e33f02fc85a4d6d8ce72d30740d2704b1bcc9d29fc4' "$ouf_delivery/owner.py" \
 '4c15a67157db0e759f4e08a0317c673e8cdb148b7b0bb0bf8bc65a7d1f142ade' "$ouf_delivery/native.py" \
 'b1540ff600938c0a0f43c2473e5b77aa9313c0e1a249a7f5ffb291c78daa1257' "$ouf_delivery/runtime.py" \
 '10bc3567f2983ea6d73055efaab3c2f9012b7c29d1a468d898cc51a0eeb2ed80' "$ouf_delivery/prepare.py" \
 '7ce1e73b83fc433cce966be524600eed5e128ae9e9c36930821184a66638f51c' "$ouf_delivery/bootstrap.py" \
 '661726c94b71aeb2b820ecf945ea5b15e7fdd9bca4b6f08f55275528f556da1b' "$ouf_delivery/diagnostic.py" | sha256sum --check
printf '%s\n' 'Tecniche8/8; funzionali4/6. Aggiornamento distinto della sola immagine MCP.' \
 'Breve indisponibilita MCP; vecchio container conservato fermo con restart disabilitato.' \
 'Nessuna migrazione, modifica policy47/grant, metadati,80rotte, fonte o job.' \
 'Sessione HUMAN originale fino a2026-10-19T10:32:43Z, cumulativo massimo256; nessun nuovo login/budget.' \
 'Preparazione richiede almeno15minuti residui: avviare prima delle10:17:43Z (12:17:43 Europe/Rome).' \
 'Il terminale chiedera APPROVO seguito dall hash della revisione corrente.' \
 'Un solo lancio. Dopo STOP/interruzione non ripetere; conservare il log pubblico.' \
 "Log: $ouf_delivery/run.log"
sudo /usr/bin/python3 -u -I -B -S - "$ouf_delivery" "$ouf_commit" <<'OUF_MCP_TRANSPORT' | tee "$ouf_delivery/run.log"
import hashlib,json,os,sys
from pathlib import Path
directory=Path(sys.argv[1]);commit=sys.argv[2]
expected={'entry': '853ddd61bc03127b533d4b300379d1027afeb0ed1eb4f8198bc19085de1a226c', 'authority': 'b70c9f933e76d3ac5903db79acdc2da4a098b10c794b2e99e7f3827c506f4135', 'owner': 'ab5fac08412ba2ce0bf63e33f02fc85a4d6d8ce72d30740d2704b1bcc9d29fc4', 'native': '4c15a67157db0e759f4e08a0317c673e8cdb148b7b0bb0bf8bc65a7d1f142ade', 'runtime': 'b1540ff600938c0a0f43c2473e5b77aa9313c0e1a249a7f5ffb291c78daa1257', 'prepare': '10bc3567f2983ea6d73055efaab3c2f9012b7c29d1a468d898cc51a0eeb2ed80', 'bootstrap': '7ce1e73b83fc433cce966be524600eed5e128ae9e9c36930821184a66638f51c', 'diagnostic': '661726c94b71aeb2b820ecf945ea5b15e7fdd9bca4b6f08f55275528f556da1b'}
try:
 if commit!='f57728d2aa68dc9cf58b86a7f3fad04b45df82dc':raise ValueError()
 delivery={}
 for name,wanted in expected.items():
  fd=os.open(directory/(name+'.py'),os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
  try:
   with os.fdopen(os.dup(fd),'rb')as stream:raw=stream.read(262145)
  finally:os.close(fd)
  if not 0<len(raw)<=262144 or hashlib.sha256(raw).hexdigest()!=wanted:raise ValueError()
  delivery[name]=raw
 namespace={'__name__':'verified_mcp_ingestion_transport_preparation'}
 exec(compile(delivery['prepare'],'<verified-mcp-ingestion-transport-preparation>','exec'),namespace)
 namespace['main'](delivery,commit)
except (Exception,KeyboardInterrupt)as error:
 print(json.dumps({'schema':'ouf.mcp-ingestion-read-transport-stop.v1','status':'STOP_RECONCILE',
  'exceptionClass':type(error).__name__,'reason':'PRIVATE_DETAILS_REDACTED',
  'automaticReplayAllowed':False,'budgetReset':False,'runtimeCompletionProven':False}),flush=True)
 raise SystemExit(2)
OUF_MCP_TRANSPORT
