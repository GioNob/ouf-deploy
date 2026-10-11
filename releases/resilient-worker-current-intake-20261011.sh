#!/usr/bin/env bash
# Read-only current bindings. No apply, restart, network write or new authority.
set -euo pipefail
umask 077
OUF_INTAKE="$(mktemp "$HOME/ouf-resilient-worker-intake.XXXXXXXX")"
gh api 'repos/GioNob/ouf-deploy/contents/scripts/read-resilient-worker-current-intake.py?ref=00a65cb9758c8f8cac40b1be51f0d5cfb58f3f64' --jq .content |
  base64 --decode > "$OUF_INTAKE"
printf '%s  %s\n' '431124adb0f7c05638decae1a6fdadf5fce69f830d4f218d7ac1eb66b996f52f' "$OUF_INTAKE" | sha256sum -c -
set +e
sudo /usr/bin/python3 -I -B -c '
import hashlib,pathlib,sys
path=sys.argv[1]
raw=pathlib.Path(path).read_bytes()
if len(raw)>65536 or hashlib.sha256(raw).hexdigest()!="431124adb0f7c05638decae1a6fdadf5fce69f830d4f218d7ac1eb66b996f52f":
    raise SystemExit("CURRENT_INTAKE_SOURCE_HASH_MISMATCH")
sys.argv=[path]
exec(compile(raw,path,"exec"),{"__name__":"__main__","__file__":path})
' "$OUF_INTAKE"
OUF_INTAKE_EXIT=$?
set -e
printf 'OUF_RESILIENT_WORKER_INTAKE_EXIT=%s PHASE=READ_CURRENT_BINDINGS_NO_APPLY\n' "$OUF_INTAKE_EXIT"
exit "$OUF_INTAKE_EXIT"
