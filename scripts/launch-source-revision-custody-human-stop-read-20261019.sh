#!/usr/bin/env bash
# Protected history read only: no login, refresh, clock/budget change or replay.
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [[ ! -x "$ouf_gh" ]]; then ouf_gh="$(command -v gh || true)"; fi
[[ -n "$ouf_gh" && -x "$ouf_gh" ]] || { echo 'Client GitHub autorizzato non disponibile.' >&2; exit 1; }
ouf_history_dir="$(mktemp -d "$HOME/ouf-custody-human-stop-read.XXXXXXXX")"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/git/blobs/0735a43a18fb062f63f65d1e6117925486ed610f' --jq '.content' | base64 --decode > "$ouf_history_dir/read.py"
printf '%s  %s\n' 'aba445960c26e1e01daf847055a63147afc3bb6e104f9fe87ee424fe5ae8aab8' "$ouf_history_dir/read.py" | sha256sum --check
printf '%s\n' 'Tecniche8/8; funzionali4/6. Sola lettura inmfuoj2, IAM riconciliato e blocco HUMAN.' 'Verifico9file attesi,81file congelati,input kfy,claim e fence IAM. Leggo il journal HUMAN senza valori o hash; nessun bearer aperto.' 'Nessun login, refresh, modifica boot/clock, authority, replay o reset budget.' "Log: $ouf_history_dir/read.log"
sudo /usr/bin/python3 -u -I -B -S - "$ouf_history_dir/read.py" <<'OUF_HUMAN_HISTORY_READ' | tee "$ouf_history_dir/read.log"
import hashlib,os,sys
fd=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
try:
 with os.fdopen(os.dup(fd),'rb') as stream:raw=stream.read(262145)
finally:os.close(fd)
if hashlib.sha256(raw).hexdigest()!='aba445960c26e1e01daf847055a63147afc3bb6e104f9fe87ee424fe5ae8aab8':
 raise SystemExit('STOP: hash diagnostico non valido; nessun journal protetto letto.')
exec(compile(raw,'<verified-custody-human-stop-read>','exec'),{'__name__':'__main__','__file__':sys.argv[1]})
OUF_HUMAN_HISTORY_READ
