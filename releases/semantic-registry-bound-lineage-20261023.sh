#!/usr/bin/env bash
(
  set -euo pipefail
  umask 077
  OUF_DIAG_DIR="$(mktemp -d "$HOME/ouf-registry-bound-lineage.XXXXXXXX")"
  trap 'printf "\nDirectory conservata: %s\nLog conservato: %s/operator.log\n" "$OUF_DIAG_DIR" "$OUF_DIAG_DIR"' EXIT
  curl --fail --silent --show-error --location \
    --proto '=https' --proto-redir '=https' --max-time 30 --max-filesize 65536 \
    'https://raw.githubusercontent.com/GioNob/ouf-deploy/f8afcf2a78f76f3a201162547ad575c8a02896c7/scripts/read-registry-bound-owner-lineage-20261023.py' \
    -o "$OUF_DIAG_DIR/reader.py"
  sudo python3 -I -B -S - "$OUF_DIAG_DIR/reader.py" <<'PY' | tee "$OUF_DIAG_DIR/operator.log"
import hashlib, os, stat, sys
path = sys.argv[1]
fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
with os.fdopen(fd, "rb") as source:
    info = os.fstat(source.fileno())
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 65536:
        raise SystemExit("STOP: sorgente non ammissibile")
    code = source.read(65537)
if hashlib.sha256(code).hexdigest() != "24739440479a105a211986ed8c2a5c936b76779b6d176aa22662c9fe77168fff":
    raise SystemExit("STOP: hash sorgente non corrispondente")
sys.argv = [path]
exec(compile(code, path, "exec"), {"__name__": "__main__", "__file__": path})
PY
)
