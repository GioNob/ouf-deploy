#!/usr/bin/env bash
# Read-only reconciliation; NEVER repeat the stopped preparation.
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [[ ! -x "$ouf_gh" ]]; then ouf_gh="$(command -v gh || true)"; fi
[[ -n "$ouf_gh" && -x "$ouf_gh" ]] || { echo 'Client GitHub autorizzato non disponibile.' >&2; exit 1; }
ouf_read_dir="$(mktemp -d "$HOME/ouf-postboot-stop-read.XXXXXXXX")"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/scripts/read-source-revision-postboot-stop.py?ref=2f5e21d6a13b68ab9a0844992281df8f85781531' --jq '.content' | base64 --decode > "$ouf_read_dir/read.py"
printf '%s  %s\n' '22209dfec60a0578ca4fddb31fc3554fc23836b46448b3d1ef01792011b3bdac' "$ouf_read_dir/read.py" | sha256sum --check
printf '%s\n' 'Sola lettura q7bq1ex3 e controllo f6w3lo6z: diagnosi proprieta senza valori. Nessun retry o authority.' "Log: $ouf_read_dir/read.log"
sudo /usr/bin/python3 -u -I -B -S - "$ouf_read_dir/read.py" <<'OUF_POSTBOOT_READ' | tee "$ouf_read_dir/read.log"
import hashlib,os,sys
fd=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
try:
 with os.fdopen(os.dup(fd),'rb') as stream:raw=stream.read(262145)
finally:os.close(fd)
if hashlib.sha256(raw).hexdigest()!='22209dfec60a0578ca4fddb31fc3554fc23836b46448b3d1ef01792011b3bdac':
 raise SystemExit('STOP: hash diagnostico non valido; nessuna lettura protetta eseguita.')
exec(compile(raw,'<verified-postboot-stop-read>','exec'),{'__name__':'__main__','__file__':sys.argv[1]})
OUF_POSTBOOT_READ
