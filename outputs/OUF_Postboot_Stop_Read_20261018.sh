#!/usr/bin/env bash
# Read-only reconciliation; NEVER repeat the stopped preparation.
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [[ ! -x "$ouf_gh" ]]; then ouf_gh="$(command -v gh || true)"; fi
[[ -n "$ouf_gh" && -x "$ouf_gh" ]] || { echo 'Client GitHub autorizzato non disponibile.' >&2; exit 1; }
ouf_read_dir="$(mktemp -d "$HOME/ouf-postboot-stop-read.XXXXXXXX")"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/scripts/read-source-revision-postboot-stop.py?ref=65403f3da55e7f025de7351a39bbe346e1ea4fec' --jq '.content' | base64 --decode > "$ouf_read_dir/read.py"
printf '%s  %s\n' '176845a70b675a6d93461efabb4e0ef094abf5155483e85e1081cbb992bec886' "$ouf_read_dir/read.py" | sha256sum --check
printf '%s\n' 'Sola lettura del tentativo f6w3lo6z e formato overlay. Nessun retry preparazione o authority.' "Log: $ouf_read_dir/read.log"
sudo /usr/bin/python3 -u -I -B -S - "$ouf_read_dir/read.py" <<'OUF_POSTBOOT_READ' | tee "$ouf_read_dir/read.log"
import hashlib,os,sys
fd=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
try:
 with os.fdopen(os.dup(fd),'rb') as stream:raw=stream.read(262145)
finally:os.close(fd)
if hashlib.sha256(raw).hexdigest()!='176845a70b675a6d93461efabb4e0ef094abf5155483e85e1081cbb992bec886':
 raise SystemExit('STOP: hash diagnostico non valido; nessuna lettura protetta eseguita.')
exec(compile(raw,'<verified-postboot-stop-read>','exec'),{'__name__':'__main__','__file__':sys.argv[1]})
OUF_POSTBOOT_READ
