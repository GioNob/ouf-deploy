#!/usr/bin/env bash
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [[ ! -x "$ouf_gh" ]]; then ouf_gh="$(command -v gh || true)"; fi
[[ -n "$ouf_gh" && -x "$ouf_gh" ]] || { echo 'STOP: client GitHub approvato non disponibile; nessun sudo.' >&2; exit 1; }
ouf_commit='9600d850e5d4b4b42004e68028a5aa6e49c20d35'
ouf_delivery="$(mktemp -d "$HOME/ouf-installation-binding-apply.XXXXXXXX")"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/tools/installation_binding_apply/entry.py?ref=9600d850e5d4b4b42004e68028a5aa6e49c20d35" --jq .content | base64 --decode > "$ouf_delivery/entry.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/tools/installation_binding_apply/authority.py?ref=9600d850e5d4b4b42004e68028a5aa6e49c20d35" --jq .content | base64 --decode > "$ouf_delivery/authority.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/tools/installation_binding_apply/owner.py?ref=9600d850e5d4b4b42004e68028a5aa6e49c20d35" --jq .content | base64 --decode > "$ouf_delivery/owner.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/tools/installation_binding_apply/native.py?ref=9600d850e5d4b4b42004e68028a5aa6e49c20d35" --jq .content | base64 --decode > "$ouf_delivery/native.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/tools/installation_binding_apply/baseline.py?ref=9600d850e5d4b4b42004e68028a5aa6e49c20d35" --jq .content | base64 --decode > "$ouf_delivery/baseline.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/tools/installation_binding_apply/login.py?ref=9600d850e5d4b4b42004e68028a5aa6e49c20d35" --jq .content | base64 --decode > "$ouf_delivery/login.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/tools/installation_binding_apply/runtime.py?ref=9600d850e5d4b4b42004e68028a5aa6e49c20d35" --jq .content | base64 --decode > "$ouf_delivery/runtime.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/scripts/prepare-installation-binding-apply.py?ref=9600d850e5d4b4b42004e68028a5aa6e49c20d35" --jq .content | base64 --decode > "$ouf_delivery/prepare.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/scripts/execute-installation-binding-apply.py?ref=9600d850e5d4b4b42004e68028a5aa6e49c20d35" --jq .content | base64 --decode > "$ouf_delivery/bootstrap.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/releases/installation-binding-gateway-compiler-20261019.json?ref=9600d850e5d4b4b42004e68028a5aa6e49c20d35" --jq .content | base64 --decode > "$ouf_delivery/compiler.py"
printf '%s  %s\n' \
 '768c65f0c67d33d976387927c488e3f2edb7b193d82c7e2b2caaaa82de78f8d3' "$ouf_delivery/entry.py" \
 '81b2a1b6b558bed87c631d7f20e4e8cefd27d4c84977378450fb53f57eb869af' "$ouf_delivery/authority.py" \
 'f4ca4690a44849f7d4f6165a5e3ddbea220dce9a8e4e27ca29a335936e97cc9c' "$ouf_delivery/owner.py" \
 'a8c9b81a8fdf83d303538bb35e0708bf1991e054f4b777c0e7534655410e9c08' "$ouf_delivery/native.py" \
 'c578e5eae5a8d037f04e934a763320ce7026609eebca3a162e28766f78d0c1cd' "$ouf_delivery/baseline.py" \
 '6a40ff6bd596fddd65aa1f24065194e9b6119023ad4775ccb7848c9e29b36221' "$ouf_delivery/login.py" \
 'cedab473c91c8c5bbd33d77c71c7fd019dccad10afc76049ad5570201e77acab' "$ouf_delivery/runtime.py" \
 '05f66e21cba4a8e883554130b4c48b8f0b550c7cb4f2710506256b70987ee5b5' "$ouf_delivery/prepare.py" \
 '69265603e7503e989209fd45141af616135b6d58e96077f6973f555e77ede6f7' "$ouf_delivery/bootstrap.py" \
 'c7cf27baf38425bbaa2528a81cb385bcf81d23434ed655b131804f26bfcf9732' "$ouf_delivery/compiler.py" | sha256sum --check
printf '%s\n' 'Azione distinta: solo binding installation, proiezione autorevole e2rotte Ingestion; tecniche8/8,funzionali4/6.' '251/256 consumati,5residui. Una nuova finestra HUMAN di7200secondi richiede consenso nativo esplicito; nessun reset del budget.' 'La vecchia finestra non viene riutilizzata. Nessun vecchio access token, refresh o device code viene riutilizzato.' 'Consenso1 RIAPRO LOGIN +hash: nuova finestra di7200secondi, stesso limite cumulativo256. Dopo browser, LOGIN COMPLETATO +hash prima del primo polling token.' 'Consenso2 APPROVO +hash:3POST owner,1export; attivazione con ETag forte revisione/checksum/generazione.' 'Consenso3 APPROVO +hash:1pubblicazione atomica proiezione e2PUT Gateway;80rotte conservate.' 'Nessun aggiornamento container, migrazione/SQL manuale, IAM/grant, metadati MCP, fonte o acquisizione.' 'Ogni effetto ha claim persistente: dopo STOP/interruzione conservare tutto e non rilanciare.'
printf 'Log privato: %s\n' "$ouf_delivery/run.log"
sudo /usr/bin/python3 -u -I -B -S - "$ouf_delivery" "$ouf_commit" <<'OUF_INSTALLATION_OWNER_UPDATE' | tee "$ouf_delivery/run.log"
import ast,hashlib,json,os,re,stat,sys
from pathlib import Path
directory=Path(sys.argv[1]);commit=sys.argv[2]
expected={'entry': '768c65f0c67d33d976387927c488e3f2edb7b193d82c7e2b2caaaa82de78f8d3', 'authority': '81b2a1b6b558bed87c631d7f20e4e8cefd27d4c84977378450fb53f57eb869af', 'owner': 'f4ca4690a44849f7d4f6165a5e3ddbea220dce9a8e4e27ca29a335936e97cc9c', 'native': 'a8c9b81a8fdf83d303538bb35e0708bf1991e054f4b777c0e7534655410e9c08', 'baseline': 'c578e5eae5a8d037f04e934a763320ce7026609eebca3a162e28766f78d0c1cd', 'login': '6a40ff6bd596fddd65aa1f24065194e9b6119023ad4775ccb7848c9e29b36221', 'runtime': 'cedab473c91c8c5bbd33d77c71c7fd019dccad10afc76049ad5570201e77acab', 'prepare': '05f66e21cba4a8e883554130b4c48b8f0b550c7cb4f2710506256b70987ee5b5', 'bootstrap': '69265603e7503e989209fd45141af616135b6d58e96077f6973f555e77ede6f7', 'compiler': 'c7cf27baf38425bbaa2528a81cb385bcf81d23434ed655b131804f26bfcf9732'}
codes=set()
try:
 if commit!='9600d850e5d4b4b42004e68028a5aa6e49c20d35':raise ValueError()
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
 print(json.dumps({'schema':'ouf.installation-binding-apply-preparation-stop.v1','status':'STOP_RECONCILE',
  'exceptionClass':type(error).__name__,'reasonCode':str(error)if str(error)in codes else'PRIVATE_DETAILS_REDACTED',
  'phase':'PREPARATION','automaticReplayAllowed':False,'budgetReset':False,'runtimeCompletionProven':False}),flush=True)
 raise SystemExit(2)
OUF_INSTALLATION_OWNER_UPDATE
