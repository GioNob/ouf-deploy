#!/usr/bin/env bash
set -euo pipefail
sudo /usr/bin/python3 -I -B - /home/oufadmin/ouf-v2-admission-manifest-read.py <<'OUF_READ_ONLY'
import hashlib
from pathlib import Path
import sys
path=Path(sys.argv[1])
raw=path.read_bytes()
if len(raw)>32768 or hashlib.sha256(raw).hexdigest() != 'dc7fe99ce7f9ae22ee287b233ce9810d02f5b473eddf4638f584a097e001f389':
    raise SystemExit('OUF_ADMISSION_MANIFEST_READER_HASH=BLOCKED')
print('OUF_ADMISSION_MANIFEST_READER_HASH=PASS', flush=True)
exec(compile(raw,str(path),'exec'),{'__name__':'__main__','__file__':str(path)})
OUF_READ_ONLY
