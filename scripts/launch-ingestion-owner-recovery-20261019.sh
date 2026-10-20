#!/usr/bin/env bash
# Installation-specific, one-shot, two native gates. Never replay after STOP.
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [[ ! -x "$ouf_gh" ]]; then ouf_gh="$(command -v gh || true)"; fi
[[ -n "$ouf_gh" && -x "$ouf_gh" ]] || { printf '%s\n' 'STOP: client GitHub approvato non disponibile; nessun sudo.' >&2; exit 2; }
ouf_delivery="$(mktemp -d "$HOME/ouf-ingestion-owner-recovery.XXXXXXXX")"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/git/blobs/1708a74e7e0f2b6b1b0625415480657d5858f7fe' --jq .content | tr -d '\n' | base64 --decode > "$ouf_delivery/delivery.json"
printf '%s  %s\n' '3319f04c102ca3074dde735f11e37ce3b02aea86daaf58b84a95a5775efe02b3' "$ouf_delivery/delivery.json" | sha256sum -c -
printf '%s\n' 'Recupero distinto: login corretto e SOLO riferimento owner ingestionReadOwnerKey.' 'Consenso1: APPROVO BUDGET288 +hash;272consumati conservati,16residui,NUOVA finestra7200s. Nessun reset.' 'URL e codice nella conferma stessa. Una conferma prematura non avvia polling ripetuti: torna allo stesso prompt.' 'Dopo successo nel browser: LOGIN COMPLETATO +hash. Ogni conferma consente UNA richiesta token.' 'La richiesta per la verifica finale rimane riservata; vecchi token, refresh e device non sono usati.' 'Consenso2: APPROVO +hash; nuova autorita210s, due ruoli, massimo3POST owner e1export privato con If-Match/readback.' 'Zero chiavi generate, file attivi pubblicati, Gateway PUT, container, DB diretto, IAM/grant, fonte o job.' 'Prima dei consensi solo preparazione/riconciliazione privata. Il journal272 resta conservato; nessun valore credenziale stampato.' 'Tecniche8/8;funzionali4/6. Dopo STOP/interruzione non rilanciare: conservare tutto.'
printf 'Log privato: %s/run.log\n' "$ouf_delivery"
sudo /usr/bin/python3 -u -I -B -S - "$ouf_delivery/delivery.json" '3319f04c102ca3074dde735f11e37ce3b02aea86daaf58b84a95a5775efe02b3' <<'OUF_OWNER_REFERENCE' | tee "$ouf_delivery/run.log"
import ast,base64,hashlib,json,os,re,stat,sys
codes=set()
try:
 fd=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  before=os.fstat(fd)
  if not (stat.S_ISREG(before.st_mode)and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o600 and 0<before.st_size<=2097152):raise ValueError('PRIVATE_DELIVERY_REQUIRED')
  with os.fdopen(os.dup(fd),'rb')as stream:raw=stream.read(2097153)
  pin=lambda s:tuple(getattr(s,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
  if len(raw)!=before.st_size or pin(before)!=pin(os.fstat(fd))or hashlib.sha256(raw).hexdigest()!=sys.argv[2]:raise ValueError('AUTHENTICATED_DELIVERY_CHANGED')
 finally:os.close(fd)
 value=json.loads(raw)
 names={'entry','authority','owner','native','login','reconcile','runtime','bootstrap','confirmation_patch','human_extension','prepare'}
 if value.get('schema')!='ouf.ingestion-owner-recovery-delivery.v1' or value.get('sourceCommit')!='948242095f031673df01338a3c1eb313fd3c64e6' or set(value['files'])!=names:raise ValueError('EXACT_OWNER_REFERENCE_DELIVERY_REQUIRED')
 delivery={}
 for name,row in value['files'].items():
  raw=base64.b64decode(row['base64'],validate=True)
  if not 0<len(raw)<=262144 or hashlib.sha256(raw).hexdigest()!=row['sha256']:raise ValueError('OWNER_REFERENCE_SOURCE_CHANGED')
  delivery[name]=raw
 codes={n.value for raw in delivery.values()for n in ast.walk(ast.parse(raw))if isinstance(n,ast.Constant)and type(n.value)is str and re.fullmatch('[A-Z][A-Z0-9_]{2,159}',n.value)}
 namespace={'__name__':'qualified_owner_reference_preparation','__file__':'<authenticated-owner-reference-preparation>'}
 exec(compile(delivery['prepare'],namespace['__file__'],'exec'),namespace)
 namespace['main'](delivery,'948242095f031673df01338a3c1eb313fd3c64e6')
except (Exception,KeyboardInterrupt)as error:
 print(json.dumps({'schema':'ouf.ingestion-owner-recovery-preparation-stop.v1','status':'STOP_RECONCILE',
  'exceptionClass':type(error).__name__,'reasonCode':str(error)if str(error)in codes else'PRIVATE_DETAILS_REDACTED',
  'phase':'PREPARATION','automaticReplayAllowed':False,'budgetReset':False,'runtimeCompletionProven':False}),flush=True)
 raise SystemExit(2)
OUF_OWNER_REFERENCE
