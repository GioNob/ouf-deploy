#!/usr/bin/env bash
# Protected history read only: no login, refresh, clock/budget change or replay.
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [[ ! -x "$ouf_gh" ]]; then ouf_gh="$(command -v gh || true)"; fi
[[ -n "$ouf_gh" && -x "$ouf_gh" ]] || { echo 'Client GitHub autorizzato non disponibile.' >&2; exit 1; }
ouf_history_dir="$(mktemp -d "$HOME/ouf-source-revision-completed-read.XXXXXXXX")"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/git/blobs/eea4ade6adca7f6e328070255e6659b2f1e0b34a' --jq '.content' | base64 --decode > "$ouf_history_dir/read.py"
printf '%s  %s\n' 'e9b06ec3b073e961d3347425304fa8c35c2a3396f2a5ed6f2d4752b4b2f422af' "$ouf_history_dir/read.py" | sha256sum --check
printf '%s\n' 'Tecniche8/8; funzionali4/6. Sola lettura del completamento uow4n8lp, massimo180secondi.' 'Verifico81file congelati,input kfy,claim successore,journal completo,metadati MCP0440,container e readiness.' 'Leggo le rotte con GET e tre transazioni SQL READ ONLY; controllo ricevuta/custodia backup senza aprire il dump.' 'Nessun token o journal HUMAN aperto; nessun login,refresh,authority,replay,nuova pubblicazione o reset budget.' 'Dopo STOP conservare il log; nessun rilancio executor.' "Log: $ouf_history_dir/read.log"
sudo /usr/bin/python3 -u -I -B -S - "$ouf_history_dir/read.py" <<'OUF_HUMAN_HISTORY_READ' | tee "$ouf_history_dir/read.log"
import hashlib,os,sys
fd=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
try:
 with os.fdopen(os.dup(fd),'rb') as stream:raw=stream.read(262145)
finally:os.close(fd)
if hashlib.sha256(raw).hexdigest()!='e9b06ec3b073e961d3347425304fa8c35c2a3396f2a5ed6f2d4752b4b2f422af':
 raise SystemExit('STOP: hash diagnostico non valido; nessun journal protetto letto.')
exec(compile(raw,'<verified-source-revision-completed-read>','exec'),{'__name__':'__main__','__file__':sys.argv[1]})
OUF_HUMAN_HISTORY_READ
