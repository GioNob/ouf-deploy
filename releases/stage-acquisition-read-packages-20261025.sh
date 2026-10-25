#!/usr/bin/env bash
set -euo pipefail
umask 077
directory=$(mktemp -d "$HOME/ouf-acquisition-packages.XXXXXXXX")
log="$directory/operator.log"
source_commit=1b0efdaffc5f7e2b7c759281b90d8d2149559324
source_hash=f2301a02b01730c41d5db85ac96d2da9eaabf94319e4d73020296848e4040bdf
code_root=/etc/ouf/deploy-snapshots/acquisition-package-code-f2301a02b01730c4
set +e
(
  set -euo pipefail
  curl --fail --location --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 60 --retry 0 \
    "https://raw.githubusercontent.com/GioNob/ouf-deploy/$source_commit/scripts/stage-acquisition-read-packages-20261025.py" \
    --output "$directory/stage.py"
  printf '%s  %s\n' "$source_hash" "$directory/stage.py" | sha256sum --check -
  command -v gh >/dev/null
  command -v timeout >/dev/null
  timeout --signal=TERM --kill-after=5s 120s gh api 'repos/GioNob/ouf-ingestion-runtime/actions/artifacts/12590122027/zip' > "$directory/ingestion.zip"
  printf '%s  %s\n' 'db1db79a1d4f5efd37004bc9ddb84789269b361a8278f991a21ddabdbc331ac9' "$directory/ingestion.zip" | sha256sum --check -
  timeout --signal=TERM --kill-after=5s 120s gh api 'repos/GioNob/ouf-udp-object-resolution/actions/artifacts/12589789326/zip' > "$directory/udp.zip"
  printf '%s  %s\n' 'c38246d7bc5a6fdb16482b06fc19521f1c58ca652dac1f7ea69fe29f513c2412' "$directory/udp.zip" | sha256sum --check -
  timeout --signal=TERM --kill-after=5s 120s gh api 'repos/GioNob/ouf-mcp-server/actions/artifacts/12589824695/zip' > "$directory/mcp.zip"
  printf '%s  %s\n' '9a4d629d729f30853ca9902e40c9c2474f6e9ea538fcb306eb3b955db106e860' "$directory/mcp.zip" | sha256sum --check -
  timeout --signal=TERM --kill-after=5s 120s gh api 'repos/GioNob/ouf-api-gateway/actions/artifacts/12590580438/zip' > "$directory/gateway.zip"
  printf '%s  %s\n' 'dfcf3426786b5f371346ea5f4c5c64d8f1e47409000b784d23ccb47028c6e01d' "$directory/gateway.zip" | sha256sum --check -
  sudo python3 -I -S -B - "$directory/stage.py" "$code_root" "$source_hash" <<'PY'
import hashlib,os,stat,sys
from pathlib import Path
source,destination,expected=Path(sys.argv[1]),Path(sys.argv[2]),sys.argv[3]
def require(ok,code):
    if not ok:raise SystemExit(code)
require(os.geteuid()==os.getegid()==0,'ROOT_COPY_REQUIRED')
require(str(destination)=='/etc/ouf/deploy-snapshots/acquisition-package-code-'+expected[:16],'EXACT_NEW_CODE_ROOT_REQUIRED')
for parent in(destination.parent,*destination.parent.parents):
    s=parent.lstat();require(stat.S_ISDIR(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022,'ROOT_CODE_ANCESTRY_REQUIRED')
fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
try:
    before=os.fstat(fd);require(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and 0<before.st_size<=65536,'BOUNDED_SOURCE_REQUIRED')
    raw=os.read(fd,before.st_size+1)
    require(len(raw)==before.st_size and hashlib.sha256(raw).hexdigest()==expected,'PINNED_SOURCE_HASH_REQUIRED')
    after=os.fstat(fd)
    require(all(getattr(before,k)==getattr(after,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')),'SOURCE_CHANGED_DURING_COPY')
finally:os.close(fd)
require(not os.path.lexists(destination),'CODE_ROOT_EXISTS_STOP_RECONCILE')
destination.mkdir(mode=0o700)
out=os.open(destination/'stage.py',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
try:
    with os.fdopen(os.dup(out),'wb')as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
finally:os.close(out)
parent=os.open(destination,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
try:os.fsync(parent)
finally:os.close(parent)
PY
  printf '%s  %s\n' "$source_hash" "$code_root/stage.py" | sudo sha256sum --check -
  sudo python3 -I -S -B "$code_root/stage.py" "$directory"
) 2>&1 | tee "$log"
result=${PIPESTATUS[0]}
set -e
printf 'Exit=%s\nDirectory=%s\nLog=%s\n' "$result" "$directory" "$log"
exit "$result"
