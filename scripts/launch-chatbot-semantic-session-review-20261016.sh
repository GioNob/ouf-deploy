#!/usr/bin/env bash
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [ ! -x "$ouf_gh" ]; then ouf_gh="$(command -v gh || true)"; fi
if [ -z "$ouf_gh" ]; then echo 'Client GitHub non trovato; nessuna esecuzione sudo.' >&2; exit 1; fi
ouf_read="$(mktemp -d "$HOME/ouf-semantic-session-review.XXXXXXXX")"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/scripts/prepare-chatbot-semantic-session-review-20261016.py?ref=a3c2953488bde021dec5277a5b64e8ebf3daed60' --jq .content | base64 --decode > "$ouf_read/read.py"
printf '%s  %s\n' '5fcf39579f2d81b9a916b0ed849d38896e9765b3b8c76f4320169f28553ab7f5' "$ouf_read/read.py" | sha256sum --check -
echo "Log della preparazione review: $ouf_read/read.log"
sudo /usr/bin/python3 -I -B - "$ouf_read/read.py" <<'PY' 2>&1 | tee "$ouf_read/read.log"
import hashlib,os,stat,subprocess,sys,tempfile
from pathlib import Path
expected='5fcf39579f2d81b9a916b0ed849d38896e9765b3b8c76f4320169f28553ab7f5'
assert os.geteuid()==0 and sys.flags.isolated
fd=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
try:
    before=os.fstat(fd)
    assert stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<before.st_size<=1048576
    with os.fdopen(os.dup(fd),'rb')as stream:raw=stream.read(1048577)
    after=os.fstat(fd)
    pin=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
    assert pin(before)==pin(after) and len(raw)==before.st_size and hashlib.sha256(raw).hexdigest()==expected
finally:os.close(fd)
with tempfile.TemporaryDirectory(prefix='ouf-semantic-policy-refresh-reader-')as directory:
    path=Path(directory)/'read.py'
    with path.open('xb')as stream:stream.write(raw)
    path.chmod(0o600)
    result=subprocess.run([sys.executable,'-I','-B',str(path)],stdin=subprocess.DEVNULL,
        env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
    raise SystemExit(result.returncode)
PY
