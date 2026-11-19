#!/usr/bin/env bash
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [ ! -x "$ouf_gh" ]; then ouf_gh="$(command -v gh || true)"; fi
[ -n "$ouf_gh" ] && [ -x "$ouf_gh" ] || { echo 'Client GitHub non disponibile; nessuna lettura sudo.' >&2; exit 1; }
ouf_read="$(mktemp -d "$HOME/ouf-teatri-acquisition-read.XXXXXXXX")"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/scripts/read-teatri-active-acquisition-20261017.py?ref=43a39d7dd48ed591ef31132d9ccade36536bbdf0' --jq .content |
  base64 --decode > "$ouf_read/read.py"
printf '%s  %s\n' '7fb7dade825ac496d4bd19a7090fda53ea2d2a00f04d47840e718b71e62aa135' "$ouf_read/read.py" | sha256sum --check -
echo 'Tecniche8/8; funzionali2/6. Conteggi acquisizione/ACK/UDP; nessun token, grant, riavvio o modifica dati.'
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
 assert hashlib.sha256(raw).hexdigest()=='7fb7dade825ac496d4bd19a7090fda53ea2d2a00f04d47840e718b71e62aa135'
finally:os.close(fd)
exec(compile(raw,'<verified-teatri-active-acquisition-reader>','exec'),{'__name__':'__main__'})
PY
