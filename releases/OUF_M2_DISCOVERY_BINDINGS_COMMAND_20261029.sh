(
  set -Eeuo pipefail
  umask 077
  ouf_m2_bindings_bootstrap=$(mktemp -d "$HOME/ouf-m2-bindings-bootstrap.XXXXXXXX")
  curl --fail --silent --show-error --location \
    --proto '=https' --proto-redir '=https' \
    --max-redirs 3 --connect-timeout 15 --max-time 60 \
    --max-filesize 16384 \
    'https://raw.githubusercontent.com/GioNob/ouf-deploy/09d2a2ba407f109fe8261ce61a6875b05d16a8d8/releases/read-m2-discovery-bindings-20261029.sh' \
    -o "$ouf_m2_bindings_bootstrap/run.sh"
  printf '%s  %s\n' \
    'eaca415a403169f97d22ce4df6f3f2873e3acd160e2e085d523a1d58d656207c' \
    "$ouf_m2_bindings_bootstrap/run.sh" | sha256sum -c -
  chmod 0400 "$ouf_m2_bindings_bootstrap/run.sh"
  /usr/bin/bash "$ouf_m2_bindings_bootstrap/run.sh"
)
