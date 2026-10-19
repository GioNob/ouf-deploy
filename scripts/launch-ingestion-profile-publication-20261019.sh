#!/usr/bin/env bash
# Installation-specific, one-shot, two native gates. Never replay after STOP.
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [[ ! -x "$ouf_gh" ]]; then ouf_gh="$(command -v gh || true)"; fi
[[ -n "$ouf_gh" && -x "$ouf_gh" ]] || { printf '%s\n' 'STOP: client GitHub approvato non disponibile; nessun sudo.' >&2; exit 2; }
ouf_delivery="$(mktemp -d "$HOME/ouf-ingestion-profile-publication.XXXXXXXX")"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/git/blobs/d758b5613c71ac009b2544bb9e47a35a9fa42dec' --jq .content | tr -d '\n' | base64 --decode > "$ouf_delivery/delivery.json"
printf '%s  %s\n' 'a72cc64cfc212d2acca817aa2b93726bd87b69d83742377a49a8d6e684e660d1' "$ouf_delivery/delivery.json" | sha256sum -c -
printf '%s\n' 'Azione distinta: pubblicazione della SOLA proiezione autorevole owner7.' 'Owner7 e login276/288 gia completati: non vengono ripetuti. Nessun nuovo login, budget o finestra.' 'Primo consenso VERIFICO SESSIONE +hash: al massimo UN refresh verificato (2richieste entro288), solo se serve margine.' 'Poi APPROVO +hash: nuova autorita120s dai due ruoli, UN rename atomico con CAS/readback e backup privato.' 'Zero POST/export owner, Gateway PUT, container, DB/migrazioni, chiavi generate, IAM/grant, fonte/job o metadati MCP.' 'Le82rotte restano conservate. Preparazione privata monouso; STOP/interruzione richiedono riconciliazione, non rilancio.' 'Tecniche8/8;funzionali4/6. Pubblicazione del profilo installation, non accettazione del client chatbot.'
printf 'Log privato: %s/run.log\n' "$ouf_delivery"
sudo /usr/bin/python3 -u -I -B -S - "$ouf_delivery/delivery.json" 'a72cc64cfc212d2acca817aa2b93726bd87b69d83742377a49a8d6e684e660d1' <<'OUF_OWNER_REFERENCE' | tee "$ouf_delivery/run.log"
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
 names={'entry','authority','owner','native','history','session','runtime','bootstrap','prepare'}
 if value.get('schema')!='ouf.ingestion-profile-publication-delivery.v1' or value.get('sourceCommit')!='ccbba4ebd986e98b465df733bce0149f8e730fb2' or set(value['files'])!=names:raise ValueError('EXACT_OWNER_REFERENCE_DELIVERY_REQUIRED')
 delivery={}
 for name,row in value['files'].items():
  raw=base64.b64decode(row['base64'],validate=True)
  if not 0<len(raw)<=262144 or hashlib.sha256(raw).hexdigest()!=row['sha256']:raise ValueError('OWNER_REFERENCE_SOURCE_CHANGED')
  delivery[name]=raw
 codes={n.value for raw in delivery.values()for n in ast.walk(ast.parse(raw))if isinstance(n,ast.Constant)and type(n.value)is str and re.fullmatch('[A-Z][A-Z0-9_]{2,159}',n.value)}
 namespace={'__name__':'qualified_owner_reference_preparation','__file__':'<authenticated-owner-reference-preparation>'}
 exec(compile(delivery['prepare'],namespace['__file__'],'exec'),namespace)
 namespace['main'](delivery,'ccbba4ebd986e98b465df733bce0149f8e730fb2')
except (Exception,KeyboardInterrupt)as error:
 print(json.dumps({'schema':'ouf.ingestion-profile-publication-preparation-stop.v1','status':'STOP_RECONCILE',
  'exceptionClass':type(error).__name__,'reasonCode':str(error)if str(error)in codes else'PRIVATE_DETAILS_REDACTED',
  'phase':'PREPARATION','automaticReplayAllowed':False,'budgetReset':False,'runtimeCompletionProven':False}),flush=True)
 raise SystemExit(2)
OUF_OWNER_REFERENCE
