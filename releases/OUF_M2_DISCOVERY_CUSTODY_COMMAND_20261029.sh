(
  set -Eeuo pipefail
  umask 077
  ouf_custody_bootstrap=$(mktemp -d "$HOME/ouf-m2-custody-bootstrap.XXXXXXXX")
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
    --max-redirs 3 --connect-timeout 15 --max-time 60 --max-filesize 16384 \
    'https://raw.githubusercontent.com/GioNob/ouf-deploy/a2473d8925eaa54924d76dd630566c848030c80d/releases/read-m2-discovery-custody-20261029.sh' \
    -o "$ouf_custody_bootstrap/run.sh"
  printf '%s  %s\n' '308b8e5b69a52e7ae6f5b8ed7898519a3a78e8d60b25a4597857752c98070226' "$ouf_custody_bootstrap/run.sh" | sha256sum -c -
  chmod 0400 "$ouf_custody_bootstrap/run.sh"
  /usr/bin/bash "$ouf_custody_bootstrap/run.sh"
)
