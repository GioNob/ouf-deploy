#!/usr/bin/env bash
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [ ! -x "$ouf_gh" ]; then ouf_gh="$(command -v gh || true)"; fi
if [ -z "$ouf_gh" ]; then echo 'Client GitHub non trovato; nessuna esecuzione sudo.' >&2; exit 1; fi
ouf_read="$(mktemp -d "$HOME/ouf-gateway-state.XXXXXXXX")"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/scripts/read-chatbot-gateway-state-20261016.py?ref=ebdcf153c450ea5ab55c1783d281f1b963c5c29c' --jq .content | base64 --decode > "$ouf_read/read.py"
printf '%s  %s\n' 'fa88de46ffe5b772b155a71ba0945d068fa16570e8e5768ade496fef1dad20d1' "$ouf_read/read.py" | sha256sum --check -
echo "Log della diagnosi: $ouf_read/read.log"
sudo /usr/bin/python3 -I -B - "$ouf_read/read.py" <<'PY' 2>&1 | tee "$ouf_read/read.log"
import hashlib,os,stat,subprocess,sys,tempfile
from pathlib import Path
expected='fa88de46ffe5b772b155a71ba0945d068fa16570e8e5768ade496fef1dad20d1'
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
with tempfile.TemporaryDirectory(prefix='ouf-gateway-reader-')as directory:
    path=Path(directory)/'read.py'
    with path.open('xb')as stream:stream.write(raw)
    path.chmod(0o600)
    result=subprocess.run([sys.executable,'-I','-B',str(path)],stdin=subprocess.DEVNULL,
        env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
    raise SystemExit(result.returncode)
PY
