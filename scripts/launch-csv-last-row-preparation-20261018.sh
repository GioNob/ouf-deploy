#!/usr/bin/env bash
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [ ! -x "$ouf_gh" ]; then ouf_gh="$(command -v gh || true)"; fi
[ -n "$ouf_gh" ] && [ -x "$ouf_gh" ] || { echo 'Client GitHub non disponibile; nessuna preparazione sudo.' >&2; exit 1; }
ouf_read="$(mktemp -d "$HOME/ouf-csv-last-row-prepare.XXXXXXXX")"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/scripts/prepare-csv-last-row-recovery-20261018.py?ref=077945345bd3c589a641df41253579f1fbb024ba' --jq .content |
 base64 --decode > "$ouf_read/prepare.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_policy_token_owner/installed_owner.py?ref=a5a7271a4ddb349a3c086ccd2d13afd3a6569157' --jq .content |
 base64 --decode > "$ouf_read/native.py"
printf '%s  %s\n' '60cd5c961ea967c906f9bed340e052b2d67495c318954aa940e65c79c328a619' "$ouf_read/prepare.py" '5455d56e973f6c6d9a35900193ac50dab44147a9bd7dedfa13d356bd91901cba' "$ouf_read/native.py" | sha256sum --check -
echo 'Tecniche 8/8; funzionali 2/6. Preparo il piano privato per il solo job residuo: nessun login, grant, worker o retry.'
echo "Log della preparazione: $ouf_read/prepare.log"
sudo /usr/bin/python3 -u -I -B -S - "$ouf_read/prepare.py" "$ouf_read/native.py" <<'PYROOT' 2>&1 | tee "$ouf_read/prepare.log"
import hashlib,os,stat,sys
assert os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
source=None
for index,expected in ((1,'60cd5c961ea967c906f9bed340e052b2d67495c318954aa940e65c79c328a619'),(2,'5455d56e973f6c6d9a35900193ac50dab44147a9bd7dedfa13d356bd91901cba')):
 fd=os.open(sys.argv[index],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  before=os.fstat(fd);assert stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<before.st_size<=262144
  raw=os.read(fd,262145);after=os.fstat(fd)
  pin=lambda s:(s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
  assert len(raw)==before.st_size and pin(before)==pin(after) and hashlib.sha256(raw).hexdigest()==expected
  if index==1:source=raw
 finally:os.close(fd)
sys.argv=[sys.argv[1],sys.argv[2]]
exec(compile(source,'<verified-csv-last-row-private-preparation>','exec'),{'__name__':'__main__'})
PYROOT
