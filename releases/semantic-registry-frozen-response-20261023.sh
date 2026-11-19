#!/usr/bin/env bash
# Separately claimed one SERVICE GET; private response, no recovery dispatch.
(
  set -euo pipefail
  umask 077
  if (( $# != 0 )); then
    printf '%s\n' 'STOP: questa verifica non accetta argomenti.'
    exit 2
  fi
  OUF_FROZEN_RESPONSE_SOURCE='6e1e0496d023b7a38818b211724f1cec036508b5'
  OUF_FROZEN_RESPONSE_SHA256='ebc7a2eaad6b8eefe166779cb3278d85cd9d8ce6a8f9f3bd20ca096a5d1f0cea'
  OUF_FROZEN_RESPONSE_GH="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
  [[ -x "$OUF_FROZEN_RESPONSE_GH" ]] || OUF_FROZEN_RESPONSE_GH="$(command -v gh)"
  OUF_FROZEN_RESPONSE_DIR="$(mktemp -d "$HOME/ouf-frozen-response.XXXXXXXX")"
  trap 'printf "\nDirectory conservata: %s\nLog conservato: %s/operator.log\n" "$OUF_FROZEN_RESPONSE_DIR" "$OUF_FROZEN_RESPONSE_DIR"' EXIT
  printf '{"schema":"ouf.semantic-registry-frozen-response-delivery.v1","sourceCommit":"%s","scriptSha256":"%s","readOnlyRuntime":true,"maximumEngineGets":2,"maximumResolverCalls":1,"maximumFrozenGets":1,"maximumNewTlsHandshakes":1}\n' \
    "$OUF_FROZEN_RESPONSE_SOURCE" "$OUF_FROZEN_RESPONSE_SHA256" > "$OUF_FROZEN_RESPONSE_DIR/operator.log"
  if ! (
    ulimit -f 128
    GH_PROMPT_DISABLED=1 GH_PAGER=cat /usr/bin/timeout --kill-after=5s 45s \
      "$OUF_FROZEN_RESPONSE_GH" api --method GET --hostname github.com \
      -H 'Accept: application/vnd.github.raw+json' \
      "repos/GioNob/ouf-deploy/contents/scripts/observe-registry-frozen-response-20261023.py?ref=$OUF_FROZEN_RESPONSE_SOURCE"
  ) > "$OUF_FROZEN_RESPONSE_DIR/read.py" 2> "$OUF_FROZEN_RESPONSE_DIR/download.stderr"; then
    printf '%s\n' '{"schema":"ouf.semantic-registry-frozen-response-delivery-result.v1","status":"STOP_RECONCILE","reasonCode":"PINNED_FROZEN_RESPONSE_DOWNLOAD_UNCONFIRMED","automaticReplayAllowed":false}' | tee -a "$OUF_FROZEN_RESPONSE_DIR/operator.log"
    exit 2
  fi
  sudo -- /usr/bin/python3 -I -B -S - "$OUF_FROZEN_RESPONSE_DIR/read.py" "$OUF_FROZEN_RESPONSE_SHA256" \
    2> "$OUF_FROZEN_RESPONSE_DIR/read.stderr" <<'PY' | tee -a "$OUF_FROZEN_RESPONSE_DIR/operator.log"
import hashlib, json, os, stat, sys
try:
    if not (len(sys.argv) == 3 and os.geteuid() == os.getegid() == 0
            and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode):
        raise ValueError()
    path, expected = sys.argv[1:]
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not (stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= 32768):
            raise ValueError()
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(32769)
        def identity(info):
            return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                    info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        if not (len(raw) == before.st_size and identity(before) == identity(os.fstat(fd))
                == identity(os.stat(path, follow_symlinks=False)) and hashlib.sha256(raw).hexdigest() == expected):
            raise ValueError()
    finally:
        os.close(fd)
except Exception:
    print(json.dumps({'schema': 'ouf.semantic-registry-frozen-response-delivery-result.v1',
        'status': 'STOP_RECONCILE', 'reasonCode': 'EXACT_FROZEN_RESPONSE_ROOT_LAUNCH_UNPROVEN',
        'automaticReplayAllowed': False, 'runtimeEffectsDispatched': 0}), flush=True)
    raise SystemExit(2)
sys.argv = [path]
exec(compile(raw, '<verified-frozen-response-observer>', 'exec'), {'__name__': '__main__', '__verified_diagnostic_sha256__': expected})
PY
)
