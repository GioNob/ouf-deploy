#!/usr/bin/env bash
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [[ ! -x "$ouf_gh" ]]; then ouf_gh="$(command -v gh || true)"; fi
[[ -n "$ouf_gh" && -x "$ouf_gh" ]] || { echo 'STOP: client GitHub approvato non disponibile; nessun sudo.' >&2; exit 1; }
ouf_commit='b46a99b23f12ef33ef04393ecefb07a6569e8b74'
ouf_delivery="$(mktemp -d "$HOME/ouf-installation-owner-update.XXXXXXXX")"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/tools/installation_owner_update/entry.py?ref=b46a99b23f12ef33ef04393ecefb07a6569e8b74" --jq .content | base64 --decode > "$ouf_delivery/entry.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/tools/installation_owner_update/authority.py?ref=b46a99b23f12ef33ef04393ecefb07a6569e8b74" --jq .content | base64 --decode > "$ouf_delivery/authority.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/tools/installation_owner_update/owner.py?ref=b46a99b23f12ef33ef04393ecefb07a6569e8b74" --jq .content | base64 --decode > "$ouf_delivery/owner.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/tools/installation_owner_update/native.py?ref=b46a99b23f12ef33ef04393ecefb07a6569e8b74" --jq .content | base64 --decode > "$ouf_delivery/native.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/tools/installation_owner_update/runtime.py?ref=b46a99b23f12ef33ef04393ecefb07a6569e8b74" --jq .content | base64 --decode > "$ouf_delivery/runtime.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/scripts/prepare-installation-owner-update.py?ref=b46a99b23f12ef33ef04393ecefb07a6569e8b74" --jq .content | base64 --decode > "$ouf_delivery/prepare.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/scripts/execute-installation-owner-update.py?ref=b46a99b23f12ef33ef04393ecefb07a6569e8b74" --jq .content | base64 --decode > "$ouf_delivery/bootstrap.py"
printf '%s  %s\n' \
 '06b64ef0900347ea61a70983551705ebc7bdb81fc5bcb572b7a67ec3f63e7468' "$ouf_delivery/entry.py" \
 '6d9b716f6ca3d04126cd7fe466ea68afab4c25eb7414906fb1e51dd9b1d54e09' "$ouf_delivery/authority.py" \
 'b847d1dfd1d589d4cd9b650ab92ddb25c316e73a478251e38a1d6b37e453cd48' "$ouf_delivery/owner.py" \
 'ab1ea5a5949495fa72c50c5c61711727f640b1962682abfc1cd615afbebeb737' "$ouf_delivery/native.py" \
 'c5bf88a3487e46e83bb18215ad035f43a4a0dbd00e8749d9a2513ad41b153034' "$ouf_delivery/runtime.py" \
 '4adb8f7c474918f87ed3214a5da6f1da42a74bebc423ce1fd5f8c6f810a61f1d' "$ouf_delivery/prepare.py" \
 'd0c06c33c1ad2a3483e58ded25b91ea1a2f0042aace2128338b92f8ec05fa7d0' "$ouf_delivery/bootstrap.py" | sha256sum --check
printf '%s\n' 'Tecniche 8/8; funzionali 4/6. Azione distinta: aggiornamento del SOLO owner Onboarding.'  'Gate nativo APPROVO + hash e firme dei due ruoli sul piano corrente; massimo 15 minuti.'  'Sessione HUMAN esistente a 11 scope, ultimo counter 243/256; nessun nuovo login, reset o rinnovo finestra.'  'Scadenza finestra: 19 ottobre 2026 ore 17:54:19 Europe/Rome. Richiesti almeno 20 minuti residui prima del gate.'  'Immagine gia costruita/scansionata; audit JAR nell immagine e 34 migrazioni identiche al sorgente installato.'  'Onboarding brevemente indisponibile; vecchio container conservato fermo; ambiente, mount e endpoint preservati.'  'MCP/UDP/Ingestion, 82 rotte, profilo ACTIVE5, policy47, metadati0440 e piano6bebb5d1 conservati.'  'Nessuna migrazione, SQL manuale, creazione/attivazione/export profilo, GatewayPUT, fonte o acquisizione.'  'Applicazione successiva del binding richiedera un gate distinto. Nessun replay dei contesti completati.'  'Un solo lancio: dopo STOP/interruzione conservare i claim e restituire solo le ricevute pubbliche.'  "Log privato: $ouf_delivery/run.log"
sudo /usr/bin/python3 -u -I -B -S - "$ouf_delivery" "$ouf_commit" <<'OUF_INSTALLATION_OWNER_UPDATE' | tee "$ouf_delivery/run.log"
import ast,hashlib,json,os,re,stat,sys
from pathlib import Path
directory=Path(sys.argv[1]);commit=sys.argv[2]
expected={'entry': '06b64ef0900347ea61a70983551705ebc7bdb81fc5bcb572b7a67ec3f63e7468', 'authority': '6d9b716f6ca3d04126cd7fe466ea68afab4c25eb7414906fb1e51dd9b1d54e09', 'owner': 'b847d1dfd1d589d4cd9b650ab92ddb25c316e73a478251e38a1d6b37e453cd48', 'native': 'ab1ea5a5949495fa72c50c5c61711727f640b1962682abfc1cd615afbebeb737', 'runtime': 'c5bf88a3487e46e83bb18215ad035f43a4a0dbd00e8749d9a2513ad41b153034', 'prepare': '4adb8f7c474918f87ed3214a5da6f1da42a74bebc423ce1fd5f8c6f810a61f1d', 'bootstrap': 'd0c06c33c1ad2a3483e58ded25b91ea1a2f0042aace2128338b92f8ec05fa7d0'}
codes=set()
try:
 if commit!='b46a99b23f12ef33ef04393ecefb07a6569e8b74':raise ValueError()
 delivery={}
 for name,wanted in expected.items():
  fd=os.open(directory/(name+'.py'),os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
  try:
   info=os.fstat(fd)
   if not stat.S_ISREG(info.st_mode)or info.st_nlink!=1 or not 0<info.st_size<=262144:raise ValueError()
   with os.fdopen(os.dup(fd),'rb')as stream:raw=stream.read(262145)
  finally:os.close(fd)
  if len(raw)!=info.st_size or hashlib.sha256(raw).hexdigest()!=wanted:raise ValueError()
  delivery[name]=raw
 codes={n.value for raw in delivery.values()for n in ast.walk(ast.parse(raw))if isinstance(n,ast.Constant)and type(n.value)is str and re.fullmatch('[A-Z][A-Z0-9_]{2,159}',n.value)}
 namespace={'__name__':'qualified_installation_owner_update_preparation'}
 exec(compile(delivery['prepare'],'<qualified-installation-owner-update-preparer>','exec'),namespace)
 namespace['main'](delivery,commit)
except (Exception,KeyboardInterrupt)as error:
 print(json.dumps({'schema':'ouf.installation-owner-update-preparation-stop.v1','status':'STOP_RECONCILE',
  'exceptionClass':type(error).__name__,'reasonCode':str(error)if str(error)in codes else'PRIVATE_DETAILS_REDACTED',
  'phase':'PREPARATION','automaticReplayAllowed':False,'budgetReset':False,'runtimeCompletionProven':False}),flush=True)
 raise SystemExit(2)
OUF_INSTALLATION_OWNER_UPDATE
