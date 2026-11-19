#!/usr/bin/env bash
# Protected history read only: no login, refresh, clock/budget change or replay.
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [[ ! -x "$ouf_gh" ]]; then ouf_gh="$(command -v gh || true)"; fi
[[ -n "$ouf_gh" && -x "$ouf_gh" ]] || { echo 'Client GitHub autorizzato non disponibile.' >&2; exit 1; }
ouf_history_dir="$(mktemp -d "$HOME/ouf-source-revision-after-approval-custody.XXXXXXXX")"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/git/blobs/34ac58ec3561eed917f5575f1fb22f073dd86b9f' --jq '.content' | base64 --decode > "$ouf_history_dir/read.py"
printf '%s  %s\n' 'a813cdf54f36c3619c8f70d4a173ce5533a99dc86bf41029e3f37d56fab99ab3' "$ouf_history_dir/read.py" | sha256sum --check
printf '%s\n' 'Tecniche8/8; funzionali4/6. Sola lettura dvf517sr dopo APPROVO: authority/claim/journal, custodia e generazioni.' 'Verifico anche la capsula completa e il binding HUMAN188. Non assumo assenza di effetti. Nessun bearer, chiave o dump aperto.' 'Nessun login, refresh, modifica boot/clock, authority, replay o reset budget.' "Log: $ouf_history_dir/read.log"
sudo /usr/bin/python3 -u -I -B -S - "$ouf_history_dir/read.py" <<'OUF_HUMAN_HISTORY_READ' | tee "$ouf_history_dir/read.log"
import hashlib,os,sys
fd=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
try:
 with os.fdopen(os.dup(fd),'rb') as stream:raw=stream.read(262145)
finally:os.close(fd)
if hashlib.sha256(raw).hexdigest()!='a813cdf54f36c3619c8f70d4a173ce5533a99dc86bf41029e3f37d56fab99ab3':
 raise SystemExit('STOP: hash diagnostico non valido; nessun journal protetto letto.')
exec(compile(raw,'<verified-source-revision-human-history-read>','exec'),{'__name__':'__main__','__file__':sys.argv[1]})
OUF_HUMAN_HISTORY_READ
