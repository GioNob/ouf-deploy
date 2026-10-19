#!/usr/bin/env bash
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [[ ! -x "$ouf_gh" ]]; then ouf_gh="$(command -v gh || true)"; fi
[[ -n "$ouf_gh" && -x "$ouf_gh" ]] || { echo 'STOP: client GitHub approvato non disponibile; nessun sudo.' >&2; exit 1; }
ouf_commit='d34f13643d7049489537f50b790a83f8fac920fd'
ouf_delivery="$(mktemp -d "$HOME/ouf-installation-route-reconcile.XXXXXXXX")"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/tools/installation_route_reconcile/entry.py?ref=d34f13643d7049489537f50b790a83f8fac920fd" --jq .content | base64 --decode > "$ouf_delivery/entry.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/tools/installation_route_reconcile/authority.py?ref=d34f13643d7049489537f50b790a83f8fac920fd" --jq .content | base64 --decode > "$ouf_delivery/authority.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/tools/installation_route_reconcile/owner.py?ref=d34f13643d7049489537f50b790a83f8fac920fd" --jq .content | base64 --decode > "$ouf_delivery/owner.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/tools/installation_route_reconcile/native.py?ref=d34f13643d7049489537f50b790a83f8fac920fd" --jq .content | base64 --decode > "$ouf_delivery/native.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/tools/installation_route_reconcile/baseline.py?ref=d34f13643d7049489537f50b790a83f8fac920fd" --jq .content | base64 --decode > "$ouf_delivery/baseline.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/tools/installation_route_reconcile/login.py?ref=d34f13643d7049489537f50b790a83f8fac920fd" --jq .content | base64 --decode > "$ouf_delivery/login.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/tools/installation_route_reconcile/reconcile.py?ref=d34f13643d7049489537f50b790a83f8fac920fd" --jq .content | base64 --decode > "$ouf_delivery/reconcile.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/tools/installation_route_reconcile/runtime.py?ref=d34f13643d7049489537f50b790a83f8fac920fd" --jq .content | base64 --decode > "$ouf_delivery/runtime.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/tools/installation_route_reconcile/human_extension.py?ref=d34f13643d7049489537f50b790a83f8fac920fd" --jq .content | base64 --decode > "$ouf_delivery/human_extension.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/scripts/prepare-installation-route-reconcile.py?ref=d34f13643d7049489537f50b790a83f8fac920fd" --jq .content | base64 --decode > "$ouf_delivery/prepare.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/scripts/execute-installation-route-reconcile.py?ref=d34f13643d7049489537f50b790a83f8fac920fd" --jq .content | base64 --decode > "$ouf_delivery/bootstrap.py"
printf '%s  %s\n' \
 'd01ebd68e5cfa389985957973c800f6999f95c18c9e220f78dcb756a0346887b' "$ouf_delivery/entry.py" \
 '42338f1d61f883950d39353eacda499fbdf4934f11881d8d084a9f64169e6653' "$ouf_delivery/authority.py" \
 'fc3ce152a5be7a84d1ec0bb9c03ed79affbca0d84dc73113bb7bced749c477f5' "$ouf_delivery/owner.py" \
 'fd6d088961b0136aebfdfd90263fd377ed8d16510773ead5088d38ef0c2c612e' "$ouf_delivery/native.py" \
 'c578e5eae5a8d037f04e934a763320ce7026609eebca3a162e28766f78d0c1cd' "$ouf_delivery/baseline.py" \
 '89b0fce57aa18fdedbe4a85d9dde8b281b8e6009182eb927ce11435c763613b9' "$ouf_delivery/login.py" \
 '998d23f8e1ab0002207c2888e94a702d0927858912366ac043d050d7a243e0ff' "$ouf_delivery/reconcile.py" \
 '619990ba5969919f2c482464c66a923da2c48e628d48c65fd87aa3227d2afc5c' "$ouf_delivery/runtime.py" \
 'b6205968783149a9f9e5bfa4b1586c08bddd0d14f7cf287618f7d04b58fa8618' "$ouf_delivery/human_extension.py" \
 '00711fb02e8013fe987aec2c92366f454b13450e505fc4c7287cea9a64e423d6' "$ouf_delivery/prepare.py" \
 '5a7424da2c83122d7f7dafa0c717a4e78058d18b4da4b718230eb198b0b026ab' "$ouf_delivery/bootstrap.py" | sha256sum --check
printf '%s\n' 'Azione distinta: riconciliazione journal e SOLO2PUT Gateway; nessun replay owner o rename.' 'Budget proposto264: mantiene255consumati; nessun reset; scadenza20:55:55 italiane invariata.' 'Consenso1 APPROVO BUDGET264 +hash: profilo HUMAN v5 esplicito solo nel nuovo pacchetto; login fresco senza vecchi token/refresh.' 'Dopo successo nel browser: LOGIN COMPLETATO +hash prima della prima richiesta token.' 'Consenso2 APPROVO +hash: nuova autorita210s, due ruoli,2transizioni journal e2PUT con readback;80rotte conservate.' 'Zero POST/export owner, pubblicazioni file attivi, container, DB, IAM/grant, fonte o job. Tecniche8/8,funzionali4/6.' 'Una sola preparazione: dopo STOP/interruzione conservare tutto e non rilanciare.'
printf 'Log privato: %s\n' "$ouf_delivery/run.log"
sudo /usr/bin/python3 -u -I -B -S - "$ouf_delivery" "$ouf_commit" <<'OUF_INSTALLATION_ROUTE_RECONCILE' | tee "$ouf_delivery/run.log"
import ast,hashlib,json,os,re,stat,sys
from pathlib import Path
directory=Path(sys.argv[1]);commit=sys.argv[2]
expected={'entry': 'd01ebd68e5cfa389985957973c800f6999f95c18c9e220f78dcb756a0346887b', 'authority': '42338f1d61f883950d39353eacda499fbdf4934f11881d8d084a9f64169e6653', 'owner': 'fc3ce152a5be7a84d1ec0bb9c03ed79affbca0d84dc73113bb7bced749c477f5', 'native': 'fd6d088961b0136aebfdfd90263fd377ed8d16510773ead5088d38ef0c2c612e', 'baseline': 'c578e5eae5a8d037f04e934a763320ce7026609eebca3a162e28766f78d0c1cd', 'login': '89b0fce57aa18fdedbe4a85d9dde8b281b8e6009182eb927ce11435c763613b9', 'reconcile': '998d23f8e1ab0002207c2888e94a702d0927858912366ac043d050d7a243e0ff', 'runtime': '619990ba5969919f2c482464c66a923da2c48e628d48c65fd87aa3227d2afc5c', 'human_extension': 'b6205968783149a9f9e5bfa4b1586c08bddd0d14f7cf287618f7d04b58fa8618', 'prepare': '00711fb02e8013fe987aec2c92366f454b13450e505fc4c7287cea9a64e423d6', 'bootstrap': '5a7424da2c83122d7f7dafa0c717a4e78058d18b4da4b718230eb198b0b026ab'}
codes=set()
try:
 if commit!='d34f13643d7049489537f50b790a83f8fac920fd':raise ValueError()
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
 print(json.dumps({'schema':'ouf.installation-route-reconciliation-preparation-stop.v1','status':'STOP_RECONCILE',
  'exceptionClass':type(error).__name__,'reasonCode':str(error)if str(error)in codes else'PRIVATE_DETAILS_REDACTED',
  'phase':'PREPARATION','automaticReplayAllowed':False,'budgetReset':False,'runtimeCompletionProven':False}),flush=True)
 raise SystemExit(2)
OUF_INSTALLATION_ROUTE_RECONCILE
