#!/usr/bin/env bash
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [[ ! -x "$ouf_gh" ]]; then ouf_gh="$(command -v gh || true)"; fi
[[ -n "$ouf_gh" && -x "$ouf_gh" ]] || { echo 'STOP: client GitHub approvato non disponibile; nessun sudo.' >&2; exit 1; }
ouf_commit='7e0eddca54df18b3b01f5059b19feea50b7b645b'
ouf_delivery="$(mktemp -d "$HOME/ouf-installation-binding-plan.XXXXXXXX")"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/tools/installation_binding_plan/entry.py?ref=7e0eddca54df18b3b01f5059b19feea50b7b645b" --jq .content | base64 --decode > "$ouf_delivery/entry.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/tools/installation_binding_plan/login.py?ref=7e0eddca54df18b3b01f5059b19feea50b7b645b" --jq .content | base64 --decode > "$ouf_delivery/login.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/tools/installation_binding_plan/plan.py?ref=7e0eddca54df18b3b01f5059b19feea50b7b645b" --jq .content | base64 --decode > "$ouf_delivery/plan.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/tools/installation_binding_plan/discovery.py?ref=7e0eddca54df18b3b01f5059b19feea50b7b645b" --jq .content | base64 --decode > "$ouf_delivery/discovery.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/tools/installation_binding_plan/runtime.py?ref=7e0eddca54df18b3b01f5059b19feea50b7b645b" --jq .content | base64 --decode > "$ouf_delivery/runtime.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/scripts/prepare-installation-ingestion-binding-plan.py?ref=7e0eddca54df18b3b01f5059b19feea50b7b645b" --jq .content | base64 --decode > "$ouf_delivery/prepare.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/scripts/execute-installation-ingestion-binding-plan.py?ref=7e0eddca54df18b3b01f5059b19feea50b7b645b" --jq .content | base64 --decode > "$ouf_delivery/bootstrap.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/scripts/installation-binding-scope-constants.py?ref=7e0eddca54df18b3b01f5059b19feea50b7b645b" --jq .content | base64 --decode > "$ouf_delivery/transform.py"
printf '%s  %s\n' \
 'a74a8f84a069ea36e106d11b03d8479ebcbc6d9ae4c5c41ab98daaed740f56f6' "$ouf_delivery/entry.py" \
 '353e80f114a0a415a2b28451d16e930b13c1f0f23b4ed30a41f0c4f5a365f983' "$ouf_delivery/login.py" \
 '6783166371be9bdb4485da164a8dc7c5e74cd677378af57deac46c811159f15e' "$ouf_delivery/plan.py" \
 '1ced8eaa4190cddfaf54ed29058a036a7695e5f96e3f59735616411fba540221' "$ouf_delivery/discovery.py" \
 '0e13e75e2f92fa82eb661bef0cfa9d08e6f558c813405b53dd20ed825dbd85da' "$ouf_delivery/runtime.py" \
 '95bb8c4c09d853d6498fdcd3886bb4daf778def5140e2093bcfceb7dff26e7c0' "$ouf_delivery/prepare.py" \
 '7068d377d9eed61c0d407e7401946cfe07512a1f54a98f869b8beeb9590d712b' "$ouf_delivery/bootstrap.py" \
 '6b55db48b9d83f4652be38f57af2a06fb4dcc23f8858af6c61b6978990b95d2a' "$ouf_delivery/transform.py" | sha256sum --check
printf '%s\n' 'Tecniche8/8; funzionali4/6. PREPARAZIONE del piano binding Ingestion nel profilo governato.'  'Nuovo consenso HUMAN nativo RIAPRO LOGIN + hash per i4scope installation.configuration read/write/activate/export.'  'Stessi issuer/soggetto/tenant/client; UNA finestra7200s, cumulativo256 da ultimo236; nessun reset o vecchio refresh.'  'Dopo login: SOLO3GET owner,6GET Engine e1DNS positivo; nessuna revisione creata, validata o attivata.'  'Nessun export/profilo attivo scritto, GatewayPUT, container lifecycle, IAM/grant/source/job o SQL.'  'Install/readbackuow4n8lp,Gatewayazxw328z,MCPsrz6__wf NON rilanciati.'  'La futura applicazione richiede piano esatto, protezione owner contro ACTIVE obsoleto e gate distinto.'  'Un solo lancio: dopo STOP/interruzione conservare i claim; restituire solo ricevute pubbliche.'  "Log privato: $ouf_delivery/run.log"
sudo /usr/bin/python3 -u -I -B -S - "$ouf_delivery" "$ouf_commit" <<'OUF_INSTALLATION_BINDING_PLAN' | tee "$ouf_delivery/run.log"
import ast,hashlib,json,os,re,stat,sys
from pathlib import Path
directory=Path(sys.argv[1]);commit=sys.argv[2]
expected={'entry': 'a74a8f84a069ea36e106d11b03d8479ebcbc6d9ae4c5c41ab98daaed740f56f6', 'login': '353e80f114a0a415a2b28451d16e930b13c1f0f23b4ed30a41f0c4f5a365f983', 'plan': '6783166371be9bdb4485da164a8dc7c5e74cd677378af57deac46c811159f15e', 'discovery': '1ced8eaa4190cddfaf54ed29058a036a7695e5f96e3f59735616411fba540221', 'runtime': '0e13e75e2f92fa82eb661bef0cfa9d08e6f558c813405b53dd20ed825dbd85da', 'prepare': '95bb8c4c09d853d6498fdcd3886bb4daf778def5140e2093bcfceb7dff26e7c0', 'bootstrap': '7068d377d9eed61c0d407e7401946cfe07512a1f54a98f869b8beeb9590d712b', 'transform': '6b55db48b9d83f4652be38f57af2a06fb4dcc23f8858af6c61b6978990b95d2a'}
codes=set()
try:
 if commit!='7e0eddca54df18b3b01f5059b19feea50b7b645b':raise ValueError()
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
 codes={n.value for n in ast.walk(ast.parse(delivery['prepare']))if isinstance(n,ast.Constant)and type(n.value)is str and re.fullmatch('[A-Z][A-Z0-9_]{2,159}',n.value)}
 namespace={'__name__':'qualified_installation_binding_plan_preparation'}
 exec(compile(delivery['prepare'],'<qualified-installation-plan-preparer>','exec'),namespace)
 namespace['main'](delivery,commit)
except (Exception,KeyboardInterrupt)as error:
 print(json.dumps({'schema':'ouf.installation-binding-plan-preparation-stop.v1','status':'STOP_RECONCILE',
  'exceptionClass':type(error).__name__,'reasonCode':str(error)if str(error)in codes else'PRIVATE_DETAILS_REDACTED',
  'phase':'PREPARATION','automaticReplayAllowed':False,'budgetReset':False,'runtimeCompletionProven':False}),flush=True)
 raise SystemExit(2)
OUF_INSTALLATION_BINDING_PLAN
