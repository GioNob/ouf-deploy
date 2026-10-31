(
  set -Eeuo pipefail
  umask 077
  ouf_peer_reconcile_bootstrap=$(mktemp -d "$HOME/ouf-peer-reconcile-bootstrap.XXXXXXXX")
  printf 'BootstrapDirectory=%s\n' "$ouf_peer_reconcile_bootstrap"
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 3 --connect-timeout 15 --max-time 60 \
    "https://raw.githubusercontent.com/GioNob/ouf-deploy/7d444e223e1e8d12484f5ec1320fb5a9e5fe99de/releases/reconcile-managed-csv-recovery-peer-binding-20261027.sh" \
    -o "$ouf_peer_reconcile_bootstrap/run.sh"
  printf '%s  %s\n' 'f5bdce6a4f1daef0c184140eebd74a0f3b49e90dd31ef9544adaf4f95de167d8' "$ouf_peer_reconcile_bootstrap/run.sh" | sha256sum -c -
  chmod 0400 "$ouf_peer_reconcile_bootstrap/run.sh"
  /usr/bin/bash "$ouf_peer_reconcile_bootstrap/run.sh"
)
