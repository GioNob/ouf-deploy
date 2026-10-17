#!/usr/bin/env bash
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [ ! -x "$ouf_gh" ]; then ouf_gh="$(command -v gh || true)"; fi
[ -n "$ouf_gh" ] && [ -x "$ouf_gh" ] || { echo 'Client GitHub non disponibile; nessuna lettura sudo.' >&2; exit 1; }
ouf_read="$(mktemp -d "$HOME/ouf-csv-reference-read.XXXXXXXX")"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/scripts/read-csv-post-resolution-references-20261018.py?ref=37e7150ca150ab861ee1b5794e8091b8776cca51' --jq .content |
  base64 --decode > "$ouf_read/read.py"
printf '%s  %s\n' '30f10c26a9d51265b1941d048845b51ae5c77510bd0b888f060333cfff19c52e' "$ouf_read/read.py" | sha256sum --check -
echo 'Tecniche 8/8; funzionali 2/6. Leggo il blocco tecnico dell’unico job residuo e l’accessibilità dei riferimenti con la connessione già configurata; nessun rinnovo o retry.'
echo "Log del controllo in sola lettura: $ouf_read/read.log"
sudo /usr/bin/python3 -u -I -B -S - "$ouf_read/read.py" <<'PY' 2>&1 | tee "$ouf_read/read.log"
import hashlib,os,stat,sys
assert os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site
fd=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
try:
 before=os.fstat(fd)
 assert stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<before.st_size<=131072
 raw=os.read(fd,131073);after=os.fstat(fd)
 pin=lambda s:(s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
 assert len(raw)==before.st_size and pin(before)==pin(after)
 assert hashlib.sha256(raw).hexdigest()=='30f10c26a9d51265b1941d048845b51ae5c77510bd0b888f060333cfff19c52e'
finally:os.close(fd)
exec(compile(raw,'<verified-csv-reference-reader>','exec'),{'__name__':'__main__'})
PY
