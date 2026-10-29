#!/usr/bin/env bash
# Distinct finite HUMAN Gateway action: add two READ routes; keep all containers.
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [[ ! -x "$ouf_gh" ]]; then ouf_gh="$(command -v gh || true)"; fi
[[ -n "$ouf_gh" && -x "$ouf_gh" ]] || { echo 'STOP: client GitHub approvato non disponibile; nessun sudo.' >&2; exit 1; }
ouf_commit='0be8fb13db3ff1ea014920bbbbb3738a8a434240'
ouf_delivery="$(mktemp -d "$HOME/ouf-ingestion-gateway-custody.XXXXXXXX")"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/tools/mcp_read_transport_gateway82/entry.py?ref=0be8fb13db3ff1ea014920bbbbb3738a8a434240" --jq .content | base64 --decode > "$ouf_delivery/entry.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/tools/mcp_read_transport_gateway82/authority.py?ref=0be8fb13db3ff1ea014920bbbbb3738a8a434240" --jq .content | base64 --decode > "$ouf_delivery/authority.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/tools/mcp_read_transport_gateway82/owner.py?ref=0be8fb13db3ff1ea014920bbbbb3738a8a434240" --jq .content | base64 --decode > "$ouf_delivery/owner.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/tools/mcp_read_transport_gateway82/native.py?ref=0be8fb13db3ff1ea014920bbbbb3738a8a434240" --jq .content | base64 --decode > "$ouf_delivery/native.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/tools/mcp_read_transport_gateway82_continuation/runtime.py?ref=0be8fb13db3ff1ea014920bbbbb3738a8a434240" --jq .content | base64 --decode > "$ouf_delivery/runtime.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/tools/mcp_read_transport_gateway82_continuation/entry.py?ref=0be8fb13db3ff1ea014920bbbbb3738a8a434240" --jq .content | base64 --decode > "$ouf_delivery/continuation-entry.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/tools/mcp_read_transport_gateway82_continuation/authority.py?ref=0be8fb13db3ff1ea014920bbbbb3738a8a434240" --jq .content | base64 --decode > "$ouf_delivery/continuation-authority.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/tools/mcp_read_transport_gateway82_continuation/login.py?ref=0be8fb13db3ff1ea014920bbbbb3738a8a434240" --jq .content | base64 --decode > "$ouf_delivery/login.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/scripts/prepare-mcp82-human-continuation.py?ref=0be8fb13db3ff1ea014920bbbbb3738a8a434240" --jq .content | base64 --decode > "$ouf_delivery/prepare.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/scripts/execute-mcp82-human-continuation.py?ref=0be8fb13db3ff1ea014920bbbbb3738a8a434240" --jq .content | base64 --decode > "$ouf_delivery/bootstrap.py"
printf '%s  %s\n' \
 'c88c16d8f82cab61ede9bfbf1830c3d56489c5c78a83baf3f36d2c0ce50ada87' "$ouf_delivery/entry.py" \
 '04a8c3e08e54b6318083e9c3e7a580194f218d18e6b2f528e4f084b9b2dba495' "$ouf_delivery/authority.py" \
 '9cebe572e89e5b6aada0fc1273b169184d2de17b1ab7739d2fd8661093b24810' "$ouf_delivery/owner.py" \
 'aa4d7d7fa57f529ca9c44736336f48928f6b122d200d8d96c6cc60977b7897a0' "$ouf_delivery/native.py" \
 'a4346cc6f481a245876c3570de21d41a9a690babaf99a37503c37b8417295543' "$ouf_delivery/runtime.py" \
 '607b375e0617bff50ae323b67bd1dd42776da67ef916c06d98b637a60eaaaa2b' "$ouf_delivery/continuation-entry.py" \
 '6bd2a677f9923449ef2f47890c13eb0e817d40cce35e1e4efe61277c8a40306a' "$ouf_delivery/continuation-authority.py" \
 'ece8b297a09b7bea9cb1aaf96fb72e78b0bc6433d2aabe9a91adb7d14055dce2' "$ouf_delivery/login.py" \
 '581a11c015e00b513d9d6a68868c9f04fd74e00c31e891360571bfa06f4410ee' "$ouf_delivery/prepare.py" \
 '6fae0218179c0d78731aa6108b5eee365ca184478c702dd296a80073af693ea9' "$ouf_delivery/bootstrap.py" | sha256sum --check
printf '%s\n' 'Tecniche8/8; funzionali4/6. Nuova continuazione HUMAN DISTINTA + aggiornamento SOLO MCP.'  'PREPARAZIONE non apre login o authority. Gate RIAPRO LOGIN + hash apre UNA finestra7200secondi.'  'Contatore corrente da229, tetto cumulativo256, nessun reset o vecchio refresh; stessi soggetto/tenant/client/scope.'  'Dopo login IAM verificato: nuovo piano attuale e gate APPROVO + hash per sostituire solo MCP a79b139 con1f2c28d.'  '82rotte Gateway conservate; nessuna PUT/migrazione/metadata write/grant/policy/attivazione fonte/job.'  'Gatewayazxw328z completato NON viene rilanciato. Immagine gia qualificata: nessun rebuild.'  'Un solo lancio. Dopo STOP o interruzione: conserva tutti i claim e restituisci solo ricevute pubbliche.'  "Log privato: $ouf_delivery/run.log"
sudo /usr/bin/python3 -u -I -B -S - "$ouf_delivery" "$ouf_commit" <<'OUF_MCP82_HUMAN_CONTINUATION' | tee "$ouf_delivery/run.log"
import ast,hashlib,json,os,re,sys
from pathlib import Path
directory=Path(sys.argv[1]);commit=sys.argv[2]
expected={'entry': 'c88c16d8f82cab61ede9bfbf1830c3d56489c5c78a83baf3f36d2c0ce50ada87', 'authority': '04a8c3e08e54b6318083e9c3e7a580194f218d18e6b2f528e4f084b9b2dba495', 'owner': '9cebe572e89e5b6aada0fc1273b169184d2de17b1ab7739d2fd8661093b24810', 'native': 'aa4d7d7fa57f529ca9c44736336f48928f6b122d200d8d96c6cc60977b7897a0', 'runtime': 'a4346cc6f481a245876c3570de21d41a9a690babaf99a37503c37b8417295543', 'continuation-entry': '607b375e0617bff50ae323b67bd1dd42776da67ef916c06d98b637a60eaaaa2b', 'continuation-authority': '6bd2a677f9923449ef2f47890c13eb0e817d40cce35e1e4efe61277c8a40306a', 'login': 'ece8b297a09b7bea9cb1aaf96fb72e78b0bc6433d2aabe9a91adb7d14055dce2', 'prepare': '581a11c015e00b513d9d6a68868c9f04fd74e00c31e891360571bfa06f4410ee', 'bootstrap': '6fae0218179c0d78731aa6108b5eee365ca184478c702dd296a80073af693ea9'}
filenames={'entry': 'entry.py', 'authority': 'authority.py', 'owner': 'owner.py', 'native': 'native.py', 'runtime': 'runtime.py', 'continuation-entry': 'continuation-entry.py', 'continuation-authority': 'continuation-authority.py', 'login': 'login.py', 'prepare': 'prepare.py', 'bootstrap': 'bootstrap.py'}
codes=set()
try:
 if commit!='0be8fb13db3ff1ea014920bbbbb3738a8a434240':raise ValueError()
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
 print(json.dumps({'schema':'ouf.mcp82-human-continuation-preparation-stop.v1','status':'STOP_RECONCILE',
  'exceptionClass':type(error).__name__,'reasonCode':str(error)if str(error)in codes else'PRIVATE_DETAILS_REDACTED',
  'phase':'PREPARATION','automaticReplayAllowed':False,'budgetReset':False,'runtimeCompletionProven':False}),flush=True)
 raise SystemExit(2)
OUF_MCP82_HUMAN_CONTINUATION
