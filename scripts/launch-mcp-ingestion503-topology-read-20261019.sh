#!/usr/bin/env bash
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [[ ! -x "$ouf_gh" ]]; then ouf_gh="$(command -v gh || true)"; fi
[[ -n "$ouf_gh" && -x "$ouf_gh" ]] || { echo 'STOP: client GitHub approvato non disponibile; nessun sudo.' >&2; exit 1; }
ouf_work="$(mktemp -d "$HOME/ouf-ingestion503-read.XXXXXXXX")"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/scripts/read-mcp-ingestion503-topology.py?ref=6c1659b44ce1c39b2495b053f719215c1d836cfa' --jq .content | base64 --decode > "$ouf_work/read.py"
printf '%s  %s\n' '707bbaa59d166a241cfc5c2943bf784f099c55901c67bfefdcb5fd3a83e4fef7' "$ouf_work/read.py" | sha256sum --check
printf '%s\n' 'Tecniche8/8; funzionali4/6. Diagnosi SOLA LETTURA dopo MCP completato srz6__wf.' \
 'Sei GET inspect, confronto reti/alias delle due rotte conservate e TCP listener Ingestion.' \
 'Nessun exec/processo container, OAuth, journal HUMAN, log, chiave privata, query DB o modifica.' \
 'Le configurazioni inspect restano in memoria; nessun segreto/valore/hash credenziale stampato.' \
 'Nessun replay di installazione, aggiornamento MCP, Gateway o acquisizioni.' \
 "Log pubblico: $ouf_work/read.log"
sudo /usr/bin/python3 -I -B -S - "$ouf_work/read.py" <<'OUF_READ503' | tee "$ouf_work/read.log"
import hashlib,os,stat,sys
try:
 fd=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  st=os.fstat(fd)
  if not stat.S_ISREG(st.st_mode)or st.st_nlink!=1 or not 0<st.st_size<=65536:raise ValueError()
  with os.fdopen(os.dup(fd),'rb')as stream:raw=stream.read(65537)
 finally:os.close(fd)
 expected='707bbaa59d166a241cfc5c2943bf784f099c55901c67bfefdcb5fd3a83e4fef7'
 if len(raw)!=st.st_size or hashlib.sha256(raw).hexdigest()!=expected:raise ValueError()
except (Exception,KeyboardInterrupt):
 print('STOP: payload diagnostico non verificato; nessuna diagnosi eseguita.',flush=True)
 raise SystemExit(2)
exec(compile(raw,'<qualified-read-only-ingestion503-topology>','exec'),{'__name__':'__main__','__file__':sys.argv[1]})
OUF_READ503
