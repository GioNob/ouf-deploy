#!/usr/bin/env bash
# Protected history read only: no login, refresh, clock/budget change or replay.
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [[ ! -x "$ouf_gh" ]]; then ouf_gh="$(command -v gh || true)"; fi
[[ -n "$ouf_gh" && -x "$ouf_gh" ]] || { echo 'Client GitHub autorizzato non disponibile.' >&2; exit 1; }
ouf_history_dir="$(mktemp -d "$HOME/ouf-source-revision-iam-stop.XXXXXXXX")"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/scripts/read-source-revision-iam-stop-20261019.py?ref=3e597af8ca23d2cd42a6ebef84f86138e513fd3d' --jq '.content' | base64 --decode > "$ouf_history_dir/read.py"
printf '%s  %s\n' 'bc820d7f8c0f6ce9e4d32ad6d83d77dd288c0e3b542fed8e7114607ddecce608' "$ouf_history_dir/read.py" | sha256sum --check
printf '%s\n' 'Tecniche8/8; funzionali4/6. Sola lettura tvc2ilnv e preparazione kfy691gh.' 'Verifico i9file conservati, compilatore, piano e assenza artefatti login/authority. Nessun journal HUMAN o bearer aperto.' 'Nessun login, refresh, modifica boot/clock, authority, replay o reset budget.' "Log: $ouf_history_dir/read.log"
sudo /usr/bin/python3 -u -I -B -S - "$ouf_history_dir/read.py" <<'OUF_HUMAN_HISTORY_READ' | tee "$ouf_history_dir/read.log"
import hashlib,os,sys
fd=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
try:
 with os.fdopen(os.dup(fd),'rb') as stream:raw=stream.read(262145)
finally:os.close(fd)
if hashlib.sha256(raw).hexdigest()!='bc820d7f8c0f6ce9e4d32ad6d83d77dd288c0e3b542fed8e7114607ddecce608':
 raise SystemExit('STOP: hash diagnostico non valido; nessun journal protetto letto.')
exec(compile(raw,'<verified-source-revision-iam-stop-read>','exec'),{'__name__':'__main__','__file__':sys.argv[1]})
OUF_HUMAN_HISTORY_READ
