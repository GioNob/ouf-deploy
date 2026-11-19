#!/usr/bin/env bash
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [ ! -x "$ouf_gh" ]; then ouf_gh="$(command -v gh || true)"; fi
[ -n "$ouf_gh" ] && [ -x "$ouf_gh" ] || { echo 'Client GitHub non disponibile; nessuna lettura sudo.' >&2; exit 1; }
ouf_read="$(mktemp -d "$HOME/ouf-configuration-policy-read.XXXXXXXX")"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/scripts/read-onboarding-configuration-policy-metadata-20261017.py?ref=58839e33a89e74cf90f29641b520e10c855e2420' --jq .content |
  base64 --decode > "$ouf_read/read.py"
printf '%s  %s\n' 'f442a126dab9c438e5e11c4a425814079ec7479b76c450406c7416b2805500e7' "$ouf_read/read.py" | sha256sum --check -
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
 assert hashlib.sha256(raw).hexdigest()=='f442a126dab9c438e5e11c4a425814079ec7479b76c450406c7416b2805500e7'
finally:os.close(fd)
exec(compile(raw,'<verified-onboarding-readiness-token-metadata-reader>','exec'),{'__name__':'__main__'})
PY
