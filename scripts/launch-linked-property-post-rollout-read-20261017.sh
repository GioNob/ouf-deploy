#!/usr/bin/env bash
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [ ! -x "$ouf_gh" ]; then ouf_gh="$(command -v gh || true)"; fi
[ -n "$ouf_gh" ] && [ -x "$ouf_gh" ] || { echo 'Client GitHub non disponibile; nessuna lettura sudo.' >&2; exit 1; }
ouf_read="$(mktemp -d "$HOME/ouf-linked-property-post-rollout.XXXXXXXX")"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/scripts/read-linked-property-post-rollout-20261017.py?ref=5339fd025c1a8be036a291ea5f7c3a6e1de59c2e' --jq .content |
  base64 --decode > "$ouf_read/read.py"
printf '%s  %s\n' '017efca7aaed59cfd16bfdb29d3d19e5fcbd31a93812ed828b8e8713a2dac5b8' "$ouf_read/read.py" | sha256sum --check -
echo 'Tecniche8/8; funzionali2/6. Verifico V35 e metadati delle regole pubblicate sulla sorgente di collaudo; nessun token, grant, riavvio, acquisizione o pubblicazione.'
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
 assert hashlib.sha256(raw).hexdigest()=='017efca7aaed59cfd16bfdb29d3d19e5fcbd31a93812ed828b8e8713a2dac5b8'
finally:os.close(fd)
exec(compile(raw,'<verified-linked-property-post-rollout-reader>','exec'),{'__name__':'__main__'})
PY
