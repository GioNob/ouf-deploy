#!/usr/bin/env bash
# Existing NEW217 window only; technical code consent then separate MCP approval.
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [[ ! -x "$ouf_gh" ]]; then ouf_gh="$(command -v gh || true)"; fi
[[ -n "$ouf_gh" && -x "$ouf_gh" ]] || { echo 'STOP: client GitHub approvato non disponibile; nessun sudo.' >&2; exit 1; }
ouf_commit='f0ecc3ec7db6a97c5bd331a2a0bd07b5752c976e'
ouf_delivery="$(mktemp -d "$HOME/ouf-mcp-window-compatibility.XXXXXXXX")"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/tools/mcp_read_transport_compatibility/entry.py?ref=f0ecc3ec7db6a97c5bd331a2a0bd07b5752c976e" --jq .content | base64 --decode > "$ouf_delivery/entry.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/tools/mcp_read_transport_compatibility/authority.py?ref=f0ecc3ec7db6a97c5bd331a2a0bd07b5752c976e" --jq .content | base64 --decode > "$ouf_delivery/authority.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/tools/mcp_read_transport_compatibility/continuation.py?ref=f0ecc3ec7db6a97c5bd331a2a0bd07b5752c976e" --jq .content | base64 --decode > "$ouf_delivery/continuation.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/tools/mcp_read_transport_compatibility/runtime.py?ref=f0ecc3ec7db6a97c5bd331a2a0bd07b5752c976e" --jq .content | base64 --decode > "$ouf_delivery/runtime.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/scripts/prepare-mcp-existing-window-compatibility.py?ref=f0ecc3ec7db6a97c5bd331a2a0bd07b5752c976e" --jq .content | base64 --decode > "$ouf_delivery/prepare.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/scripts/execute-mcp-existing-window-compatibility.py?ref=f0ecc3ec7db6a97c5bd331a2a0bd07b5752c976e" --jq .content | base64 --decode > "$ouf_delivery/bootstrap.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/scripts/human-renewal-compatibility-source.py?ref=f0ecc3ec7db6a97c5bd331a2a0bd07b5752c976e" --jq .content | base64 --decode > "$ouf_delivery/transformer.py"
printf '%s  %s\n' \
 '3949809050ec7eb4c8cecc2da65a3a27ddc61efa96aa85db7daa9127993f74a1' "$ouf_delivery/entry.py" \
 '7aee114b6538d73084ee85b370a010fac08c76dd278eaa23fac01e2e52796ee5' "$ouf_delivery/authority.py" \
 '9388fad951976356a6256f284a01904c1200f691566c3cfc4cb8c10939d4f327' "$ouf_delivery/continuation.py" \
 'b6978a3f5f72c696a7190a453183fe6b84940863a5923349ae523f76f4382532' "$ouf_delivery/runtime.py" \
 '39643eea6e4d5b04b65ae7a60db7747e7257fdbf8f25a2059bb0809d903433bb' "$ouf_delivery/prepare.py" \
 '2158aa2eab64222e3222b6c26db0c647f262942d14c38efc19f9a4a78fa0fc19' "$ouf_delivery/bootstrap.py" \
 '7505e4ab38adb8a11516d126e59188b9eb8924009e6dfc1d6336fb6b312ddb26' "$ouf_delivery/transformer.py" | sha256sum --check
printf '%s\n' 'Tecniche8/8; funzionali4/6. Compatibilita del formato approvato, stessa sessione NEW217.' \
 'NON riapro login o finestra: consenso13:15:03, scadenza15:15:03 italiane del19ottobre2026.' \
 '217/256consumati,39residui. Review, decisione, journal e claim wiqedn9w non vengono riscritti.' \
 'Primo gate APPROVO COMPATIBILITA + hash: esecuzione del guard corretto e UN solo avvio gia autorizzato.' \
 'Poi completa il login indicato dal provider con lo stesso account; segue APPROVO + hash per il SOLO MCP.' \
 'Breve indisponibilita MCP; nessuna migrazione, modifica IAM/grant/policy47/metadati/80rotte/fonte o job.' \
 'Preparazione/ripresa richiedono almeno20minuti residui: prima delle14:55:03 italiane; nessuna proroga.' \
 'Un solo lancio. Dopo STOP/interruzione non ripetere. Riporta solo ricevute pubbliche o STOP, non codici device.' \
 "Log privato: $ouf_delivery/run.log"
sudo /usr/bin/python3 -u -I -B -S - "$ouf_delivery" "$ouf_commit" <<'OUF_EXISTING_WINDOW' | tee "$ouf_delivery/run.log"
import ast,hashlib,json,os,re,sys
from pathlib import Path
directory=Path(sys.argv[1]);commit=sys.argv[2]
expected={'entry': '3949809050ec7eb4c8cecc2da65a3a27ddc61efa96aa85db7daa9127993f74a1', 'authority': '7aee114b6538d73084ee85b370a010fac08c76dd278eaa23fac01e2e52796ee5', 'continuation': '9388fad951976356a6256f284a01904c1200f691566c3cfc4cb8c10939d4f327', 'runtime': 'b6978a3f5f72c696a7190a453183fe6b84940863a5923349ae523f76f4382532', 'prepare': '39643eea6e4d5b04b65ae7a60db7747e7257fdbf8f25a2059bb0809d903433bb', 'bootstrap': '2158aa2eab64222e3222b6c26db0c647f262942d14c38efc19f9a4a78fa0fc19', 'transformer': '7505e4ab38adb8a11516d126e59188b9eb8924009e6dfc1d6336fb6b312ddb26'}
codes=set()
try:
 if commit!='f0ecc3ec7db6a97c5bd331a2a0bd07b5752c976e':raise ValueError()
 delivery={}
 for name,wanted in expected.items():
  fd=os.open(directory/(name+'.py'),os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
  try:
   with os.fdopen(os.dup(fd),'rb')as stream:raw=stream.read(262145)
  finally:os.close(fd)
  if not 0<len(raw)<=262144 or hashlib.sha256(raw).hexdigest()!=wanted:raise ValueError()
  delivery[name]=raw
 codes={node.value for name in('prepare','transformer')for node in ast.walk(ast.parse(delivery[name]))if isinstance(node,ast.Constant)and type(node.value)is str and re.fullmatch('[A-Z][A-Z0-9_]{2,159}',node.value)}
 namespace={'__name__':'verified_same_window_compatibility_preparation'}
 exec(compile(delivery['prepare'],'<verified-same-window-compatibility-preparation>','exec'),namespace)
 namespace['main'](delivery,commit)
except (Exception,KeyboardInterrupt)as error:
 print(json.dumps({'schema':'ouf.mcp-existing-window-compatibility-preparation-stop.v1','status':'STOP_RECONCILE',
  'exceptionClass':type(error).__name__,'reasonCode':str(error)if str(error)in codes else'PRIVATE_DETAILS_REDACTED',
  'phase':'PREPARATION','automaticReplayAllowed':False,'budgetReset':False,'runtimeCompletionProven':False}),flush=True)
 raise SystemExit(2)
OUF_EXISTING_WINDOW
