#!/usr/bin/env bash
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [[ ! -x "$ouf_gh" ]]; then ouf_gh="$(command -v gh || true)"; fi
[[ -n "$ouf_gh" && -x "$ouf_gh" ]] || { echo 'STOP: client GitHub approvato non disponibile; nessun sudo.' >&2; exit 1; }
ouf_work="$(mktemp -d "$HOME/ouf-ingestion503-read.XXXXXXXX")"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/scripts/read-mcp-ingestion503-dns.py?ref=51c0db6a41fb7c14031b3dc7eae6eebdf47a37fe' --jq .content | base64 --decode > "$ouf_work/read.py"
printf '%s  %s\n' '2e45b0afecccf4015264b1a4ba40e4e781c1969969a580ffbed35639e0c9cdd1' "$ouf_work/read.py" | sha256sum --check
printf '%s\n' 'Tecniche8/8; funzionali4/6. Diagnosi SOLA LETTURA dopo MCP completato srz6__wf.' \
 'Sei GET inspect, profilo approvato e DUE query al DNS locale Docker dal namespace Gateway; ripristino obbligatorio.' \
 'Nessun processo/exec container, OAuth, journal HUMAN, log, chiave privata, HTTP backend o modifica.' \
 'Solo esiti DNS e confronti con il container owner; nessun nome, IP, segreto o hash credenziale stampato.' \
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
 expected='2e45b0afecccf4015264b1a4ba40e4e781c1969969a580ffbed35639e0c9cdd1'
 if len(raw)!=st.st_size or hashlib.sha256(raw).hexdigest()!=expected:raise ValueError()
except (Exception,KeyboardInterrupt):
 print('STOP: payload diagnostico non verificato; nessuna diagnosi eseguita.',flush=True)
 raise SystemExit(2)
exec(compile(raw,'<qualified-read-only-ingestion503-topology>','exec'),{'__name__':'__main__','__file__':sys.argv[1]})
OUF_READ503
