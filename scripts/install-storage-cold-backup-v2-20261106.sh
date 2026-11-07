(
  set -eu
  umask 077
  download="$(mktemp)"
  trap 'rm -f -- "$download"' EXIT
  curl --fail --silent --show-error --location \
    'https://raw.githubusercontent.com/GioNob/ouf-deploy/562f2ca3efe0dd9052d3dce3f5abffb25380a918/scripts/storage-cold-backup.py' \
    --output "$download"
  sudo python3 -I -B -S - "$download" <<'PY'
import hashlib, os, sys
from pathlib import Path
raw = Path(sys.argv[1]).read_bytes()
assert len(raw) == 27538
assert hashlib.sha256(raw).hexdigest() == '74164357d05631f71c2dd86cf4a071abed61fa2a132e1652d77b927f86a58c2a'
target = Path('/var/lib/ouf-storage-cold-backup-v2.py')
fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
with os.fdopen(fd, 'wb') as out:
    out.write(raw)
    out.flush()
    os.fsync(out.fileno())
parent = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(parent)
finally:
    os.close(parent)
print('Download e SHA256: OK — v2 installata; sola preparazione', flush=True)
os.execv(sys.executable, [sys.executable, '-I', '-B', '-S', str(target), 'prepare'])
PY
)
