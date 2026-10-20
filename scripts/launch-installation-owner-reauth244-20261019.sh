#!/usr/bin/env bash
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [[ ! -x "$ouf_gh" ]]; then ouf_gh="$(command -v gh || true)"; fi
[[ -n "$ouf_gh" && -x "$ouf_gh" ]] || { echo 'STOP: client GitHub approvato non disponibile; nessun sudo.' >&2; exit 1; }
ouf_commit='bcd33c71c7a906ec867c7ab2ccac40e4545a4f31'
ouf_delivery="$(mktemp -d "$HOME/ouf-installation-owner-update.XXXXXXXX")"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/tools/installation_owner_reauthentication/entry.py?ref=bcd33c71c7a906ec867c7ab2ccac40e4545a4f31" --jq .content | base64 --decode > "$ouf_delivery/entry.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/scripts/prepare-installation-owner-reauth244.py?ref=bcd33c71c7a906ec867c7ab2ccac40e4545a4f31" --jq .content | base64 --decode > "$ouf_delivery/prepare.py"
printf '%s  %s\n' \
 '1ce40aecf7f047e43dd9feb7051bd4542034372a458266100df18493ffc42b0f' "$ouf_delivery/entry.py" \
 '8211e28abed5089dbdac537a6d19db1d852a275acac96b39cd8664bc9a888451' "$ouf_delivery/prepare.py" | sha256sum --check
printf '%s\n' 'Azione distinta: una riautenticazione HUMAN nella finestra originale, poi gate owner separato.'  '244/256 consumati;12 residui,11scope invariati; scadenza19ottobre2026 ore17:54:19 Europe/Rome.'  'Nessun reset, estensione o replay del refresh bloccato; validatore HUMAN identico.'  'Gate1 APPROVO RIAUTENTICAZIONE + hash: solo nuovo device login, il provider puo negare.'  'Gate2 APPROVO + hash: solo Onboarding, breve indisponibilita, vecchio container conservato fermo.'  'Immagine gia verificata e34migrazioni invariate: niente rebuild o ripetizione della preparazione immagine.'  'Nessuna creazione/attivazione/export profilo, PUT Gateway, grant, fonte o acquisizione.'  'MCP/UDP/Ingestion, ACTIVE5,82rotte e metadati0440 conservati; tecniche8/8,funzionali4/6.'  'Dopo STOP/interruzione non rilanciare: restituire solo ricevute pubbliche.'  "Log privato: $ouf_delivery/run.log"
sudo /usr/bin/python3 -u -I -B -S - "$ouf_delivery" "$ouf_commit" <<'OUF_INSTALLATION_OWNER_UPDATE' | tee "$ouf_delivery/run.log"
import ast,hashlib,json,os,re,stat,sys
from pathlib import Path
directory=Path(sys.argv[1]);commit=sys.argv[2]
expected={'entry': '1ce40aecf7f047e43dd9feb7051bd4542034372a458266100df18493ffc42b0f', 'prepare': '8211e28abed5089dbdac537a6d19db1d852a275acac96b39cd8664bc9a888451'}
codes=set()
try:
 if commit!='bcd33c71c7a906ec867c7ab2ccac40e4545a4f31':raise ValueError()
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
