(
  set -eu
  umask 077
  download="$(mktemp)"
  trap 'rm -f -- "$download"' EXIT
  curl --fail --silent --show-error --location \
    'https://raw.githubusercontent.com/GioNob/ouf-deploy/639f7a640dc2f0aa0ec00e3b31c2b43bebe97111/scripts/storage-cold-backup.py' \
    --output "$download"
  sudo python3 -I -B -S - "$download" <<'PY'
import hashlib, os, sys
from pathlib import Path
raw = Path(sys.argv[1]).read_bytes()
assert len(raw) == 32524
assert hashlib.sha256(raw).hexdigest() == 'b23a822d0fd7000ac8806d47ff66c0ab053f0fa60ce33998268af792b9db53ac'
target = Path('/var/lib/ouf-storage-cold-backup-v3.py')
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
print('Download e SHA256: OK — v3 installata; sola preparazione', flush=True)
os.execv(sys.executable, [sys.executable, '-I', '-B', '-S', str(target), 'prepare'])
PY
)
