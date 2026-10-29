#!/usr/bin/env bash
# Protected history read only: no login, refresh, clock/budget change or replay.
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [[ ! -x "$ouf_gh" ]]; then ouf_gh="$(command -v gh || true)"; fi
[[ -n "$ouf_gh" && -x "$ouf_gh" ]] || { echo 'Client GitHub autorizzato non disponibile.' >&2; exit 1; }
ouf_history_dir="$(mktemp -d "$HOME/ouf-custody-iam-resume.XXXXXXXX")"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/git/blobs/8885224191dd62917a4a41425700f23b2266ee6a' --jq '.content' | base64 --decode > "$ouf_history_dir/read.py"
printf '%s  %s\n' '789f1a339ad74d89ff8002f2c22ab142d350206d9bc82e43512156df4c147409' "$ouf_history_dir/read.py" | sha256sum --check
printf '%s\n' 'Tecniche8/8; funzionali4/6. Riconciliazione privata kcw73ask e capsula custody riuscita.' 'Prima sola lettura:9file,81sorgenti,input originali,claim e HUMAN188. Nessun bearer aperto.' 'Solo se tutto coincide:un login IAM amministrativo nel prompt Keycloak; password mai nella chat. Dopo GET verificato:nuovo processo nativo,refresh HUMAN esistente e nuovo APPROVO. Nessuna nuova finestra HUMAN o reset budget. Dopo STOP non rilanciare.' "Log: $ouf_history_dir/read.log"
sudo /usr/bin/python3 -u -I -B -S - "$ouf_history_dir/read.py" <<'OUF_HUMAN_HISTORY_READ' | tee "$ouf_history_dir/read.log"
import hashlib,os,sys
fd=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
try:
 with os.fdopen(os.dup(fd),'rb') as stream:raw=stream.read(262145)
finally:os.close(fd)
if hashlib.sha256(raw).hexdigest()!='789f1a339ad74d89ff8002f2c22ab142d350206d9bc82e43512156df4c147409':
 raise SystemExit('STOP: hash diagnostico non valido; nessun journal protetto letto.')
exec(compile(raw,'<verified-custody-iam-resume>','exec'),{'__name__':'__main__','__file__':sys.argv[1]})
OUF_HUMAN_HISTORY_READ
