#!/usr/bin/env bash
# Installation-specific, one-shot, two native gates. Never replay after STOP.
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [[ ! -x "$ouf_gh" ]]; then ouf_gh="$(command -v gh || true)"; fi
[[ -n "$ouf_gh" && -x "$ouf_gh" ]] || { printf '%s\n' 'STOP: client GitHub approvato non disponibile; nessun sudo.' >&2; exit 2; }
ouf_delivery="$(mktemp -d "$HOME/ouf-ingestion-owner-reference.XXXXXXXX")"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/git/blobs/5633382da7701e41bd793de9dae9bb1131c3e1a1' --jq .content | tr -d '\n' | base64 --decode > "$ouf_delivery/delivery.json"
printf '%s  %s\n' 'c58ce2620bf31a77a605adf6c278dcef89fd6cd8ca8487f82428095f6923a442' "$ouf_delivery/delivery.json" | sha256sum -c -
printf '%s\n' 'Azione distinta: login HUMAN272 e SOLO riferimento owner ingestionReadOwnerKey.' 'Consenso1: APPROVO BUDGET272 +hash;259consumati conservati,13residui,NUOVA finestra7200s dal consenso; vecchia scaduta preservata.' 'Login fresco senza vecchi token o refresh. Dopo successo browser: LOGIN COMPLETATO +hash prima della prima richiesta token.' 'Consenso2: APPROVO +hash per nuova autorita210s, due ruoli, massimo3POST owner e1export privato, readback e If-Match.' 'Nessuna generazione chiavi, pubblicazione file attivi, Gateway PUT, container, DB diretto, IAM/grant, fonte o job.' 'Tecniche8/8;funzionali4/6. Una sola preparazione: dopo STOP/interruzione conservare tutto e non rilanciare.'
printf 'Log privato: %s/run.log\n' "$ouf_delivery"
sudo /usr/bin/python3 -u -I -B -S - "$ouf_delivery/delivery.json" 'c58ce2620bf31a77a605adf6c278dcef89fd6cd8ca8487f82428095f6923a442' <<'OUF_OWNER_REFERENCE' | tee "$ouf_delivery/run.log"
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
 names={'entry','authority','owner','native','baseline','login','runtime','bootstrap','human_extension','predecessor_extension','prepare'}
 if value.get('schema')!='ouf.ingestion-owner-reference-delivery.v1' or value.get('sourceCommit')!='cea5627fea0a517061e01fbac505da159bc63371' or set(value['files'])!=names:raise ValueError('EXACT_OWNER_REFERENCE_DELIVERY_REQUIRED')
 delivery={}
 for name,row in value['files'].items():
  raw=base64.b64decode(row['base64'],validate=True)
  if not 0<len(raw)<=262144 or hashlib.sha256(raw).hexdigest()!=row['sha256']:raise ValueError('OWNER_REFERENCE_SOURCE_CHANGED')
  delivery[name]=raw
 codes={n.value for raw in delivery.values()for n in ast.walk(ast.parse(raw))if isinstance(n,ast.Constant)and type(n.value)is str and re.fullmatch('[A-Z][A-Z0-9_]{2,159}',n.value)}
 namespace={'__name__':'qualified_owner_reference_preparation','__file__':'<authenticated-owner-reference-preparation>'}
 exec(compile(delivery['prepare'],namespace['__file__'],'exec'),namespace)
 namespace['main'](delivery,'cea5627fea0a517061e01fbac505da159bc63371')
except (Exception,KeyboardInterrupt)as error:
 print(json.dumps({'schema':'ouf.ingestion-owner-reference-preparation-stop.v1','status':'STOP_RECONCILE',
  'exceptionClass':type(error).__name__,'reasonCode':str(error)if str(error)in codes else'PRIVATE_DETAILS_REDACTED',
  'phase':'PREPARATION','automaticReplayAllowed':False,'budgetReset':False,'runtimeCompletionProven':False}),flush=True)
 raise SystemExit(2)
OUF_OWNER_REFERENCE
