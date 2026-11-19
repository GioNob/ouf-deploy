#!/usr/bin/env bash
# Installation-specific child action. No new login, budget or installation.
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [[ ! -x "$ouf_gh" ]]; then ouf_gh="$(command -v gh || true)"; fi
[[ -n "$ouf_gh" && -x "$ouf_gh" ]] || { echo 'STOP: client GitHub approvato non disponibile; nessun sudo.' >&2; exit 1; }
ouf_commit='bc6fd07e65589b59408cf2a0fb2a646d8d8e0812'
ouf_delivery="$(mktemp -d "$HOME/ouf-ingestion-publication-repair.XXXXXXXX")"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/scripts/prepare-ingestion-publication-repair.py?ref=$ouf_commit" --jq .content | base64 --decode > "$ouf_delivery/prepare.py"
"$ouf_gh" api "repos/GioNob/ouf-deploy/contents/scripts/ingestion-publication-repair-entry.py?ref=$ouf_commit" --jq .content | base64 --decode > "$ouf_delivery/entry.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/scripts/diagnose-ingestion-administrative-preflight.py?ref=0c654ff46d6a44de32557247ae0790873d67d079' --jq .content | base64 --decode > "$ouf_delivery/diagnostic.py"
printf '%s  %s\n' \
 'b31702089e27fff904c04431ad402856c820f18b99dd6c2addd0f6ac195b46ad' "$ouf_delivery/prepare.py" \
 '7f0391fe03be2b0bf974a82d51d0e978dd2d0942bc7f42e1c3f03858537910bd' "$ouf_delivery/entry.py" \
 '661726c94b71aeb2b820ecf945ea5b15e7fdd9bca4b6f08f55275528f556da1b' "$ouf_delivery/diagnostic.py" | sha256sum --check
printf '%s\n' 'Tecniche8/8; funzionali4/6. Riparazione distinta del publisher privato; ojz9hai3 conservato.' \
 'Prima verifico la sola guardia del publisher congelato e riconcilio i claim consumati.' \
 'Piano9216f0ba: registrazione/descrittore/scope ingestion.operations.read,104grant e2ruoli conservati.' \
 'Nessun nuovo login o budget. Finestra HUMAN originale fino a2026-10-19T10:32:43Z; contatore cumulativo corrente preservato, massimo256.' \
 'Baseline riletta prima della review. Nel terminale verra richiesto APPROVO seguito dall hash corrente.' \
 'Un solo lancio. Dopo STOP/interruzione non ripetere; conservare il log pubblico.' \
 "Log: $ouf_delivery/run.log"
sudo /usr/bin/python3 -u -I -B -S - "$ouf_delivery" "$ouf_commit" <<'OUF_EXISTING_HUMAN' | tee "$ouf_delivery/run.log"
import hashlib,json,os,sys
from pathlib import Path
directory=Path(sys.argv[1]);commit=sys.argv[2]
expected={'prepare':'b31702089e27fff904c04431ad402856c820f18b99dd6c2addd0f6ac195b46ad',
 'entry':'7f0391fe03be2b0bf974a82d51d0e978dd2d0942bc7f42e1c3f03858537910bd',
 'diagnostic':'661726c94b71aeb2b820ecf945ea5b15e7fdd9bca4b6f08f55275528f556da1b'}
try:
 if commit!='bc6fd07e65589b59408cf2a0fb2a646d8d8e0812':raise ValueError()
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
