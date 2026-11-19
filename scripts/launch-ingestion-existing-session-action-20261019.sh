#!/usr/bin/env bash
# Installation-specific child action. No new login, budget or installation.
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [[ ! -x "$ouf_gh" ]]; then ouf_gh="$(command -v gh || true)"; fi
[[ -n "$ouf_gh" && -x "$ouf_gh" ]] || { echo 'STOP: client GitHub approvato non disponibile; nessun sudo.' >&2; exit 1; }
ouf_commit='37184220c2a565367a194d41e862a704f87dbdb8'
ouf_delivery="$(mktemp -d "$HOME/ouf-ingestion-existing-session.XXXXXXXX")"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/scripts/prepare-ingestion-existing-session-action.py?ref=$ouf_commit" --jq .content | base64 --decode > "$ouf_delivery/prepare.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/scripts/ingestion-existing-session-entry.py?ref=$ouf_commit" --jq .content | base64 --decode > "$ouf_delivery/entry.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/scripts/diagnose-ingestion-administrative-preflight.py?ref=0c654ff46d6a44de32557247ae0790873d67d079' --jq .content | base64 --decode > "$ouf_delivery/diagnostic.py"
printf '%s  %s\n' \
 '81effc49bf32354acce2eaaa8f230b5161e70d124feac948a41ab9e8534c6737' "$ouf_delivery/prepare.py" \
 '4d3f8df210dee1c1c838474a86569bce6f7af81c003ae4dd51c4e8b81d7a3e76' "$ouf_delivery/entry.py" \
 '661726c94b71aeb2b820ecf945ea5b15e7fdd9bca4b6f08f55275528f556da1b' "$ouf_delivery/diagnostic.py" | sha256sum --check
printf '%s\n' 'Tecniche8/8; funzionali4/6. Continuazione distinta dal preflight 0jvu7qzh.' \
 'Piano9216f0ba: registrazione/descrittore/scope ingestion.operations.read,104grant e2ruoli conservati.' \
 'Nessun nuovo login o budget. Finestra HUMAN originale fino a2026-10-19T10:32:43Z; cumulativo212/256 preservato.' \
 'Baseline riletta prima della review. Nel terminale verra richiesto APPROVO seguito dall hash corrente.' \
 'Un solo lancio. Dopo STOP/interruzione non ripetere; conservare il log pubblico.' \
 "Log: $ouf_delivery/run.log"
sudo /usr/bin/python3 -u -I -B -S - "$ouf_delivery" "$ouf_commit" <<'OUF_EXISTING_HUMAN' | tee "$ouf_delivery/run.log"
import hashlib,json,os,sys
from pathlib import Path
directory=Path(sys.argv[1]);commit=sys.argv[2]
expected={'prepare':'81effc49bf32354acce2eaaa8f230b5161e70d124feac948a41ab9e8534c6737',
 'entry':'4d3f8df210dee1c1c838474a86569bce6f7af81c003ae4dd51c4e8b81d7a3e76',
 'diagnostic':'661726c94b71aeb2b820ecf945ea5b15e7fdd9bca4b6f08f55275528f556da1b'}
try:
 if commit!='37184220c2a565367a194d41e862a704f87dbdb8':raise ValueError()
 delivery={}
 for name,wanted in expected.items():
  fd=os.open(directory/(name+'.py'),os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
  try:
   with os.fdopen(os.dup(fd),'rb')as stream:raw=stream.read(262145)
  finally:os.close(fd)
  if not 0<len(raw)<=262144 or hashlib.sha256(raw).hexdigest()!=wanted:raise ValueError()
  delivery[name]=raw
 namespace={'__name__':'verified_existing_session_preparation'}
 exec(compile(delivery['prepare'],'<verified-existing-session-preparation>','exec'),namespace)
 namespace['main'](delivery,commit)
except (Exception,KeyboardInterrupt)as error:
 print(json.dumps({'schema':'ouf.ingestion-existing-session-stop.v1','status':'STOP_RECONCILE',
  'exceptionClass':type(error).__name__,'reason':'PRIVATE_DETAILS_REDACTED',
  'automaticReplayAllowed':False,'budgetReset':False,'runtimeCompletionProven':False}),flush=True)
 raise SystemExit(2)
OUF_EXISTING_HUMAN
