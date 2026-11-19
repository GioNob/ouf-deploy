#!/usr/bin/env bash
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [ ! -x "$ouf_gh" ]; then ouf_gh="$(command -v gh || true)"; fi
[ -n "$ouf_gh" ] && [ -x "$ouf_gh" ] || { echo 'Client GitHub non disponibile; nessuna lettura sudo.' >&2; exit 1; }
ouf_read="$(mktemp -d "$HOME/ouf-resolution-ths-property-read.XXXXXXXX")"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/scripts/read-resolution-ths-property-shapes-20261017.py?ref=70b13be02eda847008b9391623cbc3959a938b2c' --jq .content |
  base64 --decode > "$ouf_read/read.py"
printf '%s  %s\n' '82d2c386af2995c26b58225cb097c6030418fec4ce7a213f9f17617ee7987a30' "$ouf_read/read.py" | sha256sum --check -
echo 'Tecniche8/8; funzionali2/6. Forma delle proprieta THS, riferimenti env e Spring JSON; nessun token o segreto stampato, nessuna modifica.'
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/chatbot_file_cohort/gateway.py?ref=70b13be02eda847008b9391623cbc3959a938b2c' --jq .content |
  base64 --decode > "$ouf_read/gateway_custody.py"
printf '%s  %s\n' '5e7182d899a25a299b103d63f6bf81822280f09e58b963c38f735aa2a4fee72f' "$ouf_read/gateway_custody.py" | sha256sum --check -
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
 assert hashlib.sha256(raw).hexdigest()=='82d2c386af2995c26b58225cb097c6030418fec4ce7a213f9f17617ee7987a30'
finally:os.close(fd)
sys.argv=[sys.argv[1],os.path.join(os.path.dirname(sys.argv[1]),'gateway_custody.py')]
exec(compile(raw,'<verified-resolution-ths-property-reader>','exec'),{'__name__':'__main__'})
PY
