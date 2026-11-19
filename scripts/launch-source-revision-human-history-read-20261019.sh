#!/usr/bin/env bash
# Protected history read only: no login, refresh, clock/budget change or replay.
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [[ ! -x "$ouf_gh" ]]; then ouf_gh="$(command -v gh || true)"; fi
[[ -n "$ouf_gh" && -x "$ouf_gh" ]] || { echo 'Client GitHub autorizzato non disponibile.' >&2; exit 1; }
ouf_history_dir="$(mktemp -d "$HOME/ouf-source-revision-human-history.XXXXXXXX")"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/scripts/read-source-revision-human-history-20261019.py?ref=3f3c5cc04663948a840d64a0f75ca9579f5e9733' --jq '.content' | base64 --decode > "$ouf_history_dir/read.py"
printf '%s  %s\n' 'a49343e52fb15d70f822e3b6bbf0b4851f0f00d42a3dd3e1a801591d0167086a' "$ouf_history_dir/read.py" | sha256sum --check
printf '%s\n' 'Sola lettura: contesto k6rk22xj, binding/budget/boot HUMAN e catena storica dei successori.' 'I journal privati sono letti senza stampare credenziali o hash dei journal; nessun bearer file aperto.' 'Nessun login, refresh, modifica boot/clock, authority, replay o reset budget.' "Log: $ouf_history_dir/read.log"
sudo /usr/bin/python3 -u -I -B -S - "$ouf_history_dir/read.py" <<'OUF_HUMAN_HISTORY_READ' | tee "$ouf_history_dir/read.log"
import hashlib,os,sys
fd=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
try:
 with os.fdopen(os.dup(fd),'rb') as stream:raw=stream.read(262145)
finally:os.close(fd)
if hashlib.sha256(raw).hexdigest()!='a49343e52fb15d70f822e3b6bbf0b4851f0f00d42a3dd3e1a801591d0167086a':
 raise SystemExit('STOP: hash diagnostico non valido; nessun journal protetto letto.')
exec(compile(raw,'<verified-source-revision-human-history-read>','exec'),{'__name__':'__main__','__file__':sys.argv[1]})
OUF_HUMAN_HISTORY_READ
