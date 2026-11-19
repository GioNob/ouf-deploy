#!/usr/bin/env bash
# Protected history read only: no login, refresh, clock/budget change or replay.
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [[ ! -x "$ouf_gh" ]]; then ouf_gh="$(command -v gh || true)"; fi
[[ -n "$ouf_gh" && -x "$ouf_gh" ]] || { echo 'Client GitHub autorizzato non disponibile.' >&2; exit 1; }
ouf_history_dir="$(mktemp -d "$HOME/ouf-source-revision-human-binding-stop.XXXXXXXX")"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/scripts/read-source-revision-human-binding-stop-20261019.py?ref=d69093c40e0f3ff99fda5df19433512dd0dd810c' --jq '.content' | base64 --decode > "$ouf_history_dir/read.py"
printf '%s  %s\n' '48b2b3d6edd1fc9fbc86763f2241964825d997cc394b880a0670a2c1984283b1' "$ouf_history_dir/read.py" | sha256sum --check
printf '%s\n' 'Tecniche8/8; funzionali4/6. Sola lettura daxl0o6h, claim consumato e stato del nuovo login HUMAN.' 'Verifico decisione/revisione, tentativi, scadenza, presenza token e contratto dei due verificatori congelati. Nessun valore o hash dei journal; bearer non aperto.' 'Nessun login, refresh, modifica boot/clock, authority, replay o reset budget.' "Log: $ouf_history_dir/read.log"
sudo /usr/bin/python3 -u -I -B -S - "$ouf_history_dir/read.py" <<'OUF_HUMAN_HISTORY_READ' | tee "$ouf_history_dir/read.log"
import hashlib,os,sys
fd=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
try:
 with os.fdopen(os.dup(fd),'rb') as stream:raw=stream.read(262145)
finally:os.close(fd)
if hashlib.sha256(raw).hexdigest()!='48b2b3d6edd1fc9fbc86763f2241964825d997cc394b880a0670a2c1984283b1':
 raise SystemExit('STOP: hash diagnostico non valido; nessun journal protetto letto.')
exec(compile(raw,'<verified-source-revision-human-history-read>','exec'),{'__name__':'__main__','__file__':sys.argv[1]})
OUF_HUMAN_HISTORY_READ
