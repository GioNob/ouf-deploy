#!/usr/bin/env bash
(
  set -euo pipefail
  umask 077
  OUF_DIAG_DIR="$(mktemp -d "$HOME/ouf-registry-owner-discovery.XXXXXXXX")"
  trap 'printf "\nDirectory conservata: %s\nLog conservato: %s/operator.log\n" "$OUF_DIAG_DIR" "$OUF_DIAG_DIR"' EXIT
  curl --fail --silent --show-error --location \
    --proto '=https' --proto-redir '=https' --max-time 30 \
    'https://raw.githubusercontent.com/GioNob/ouf-deploy/e607c78606b942b9515dad59ab8c09cf3af1db2b/scripts/read-registry-token-owner-candidates-20261023.py' \
    -o "$OUF_DIAG_DIR/reader.py"
  printf '%s  %s\n' \
    'a8b2aff8ea8e3c0be3fc928e925a756aafeb4e7ce4104530b244ec107071fb30' \
    "$OUF_DIAG_DIR/reader.py" | sha256sum --check
  sudo python3 -I -B -S "$OUF_DIAG_DIR/reader.py" | tee "$OUF_DIAG_DIR/operator.log"
)
