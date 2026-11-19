(
  set -euo pipefail
  umask 077
  ouf_image_reconcile_tmp=$(mktemp -d)
  trap 'rm -rf -- "$ouf_image_reconcile_tmp"' EXIT
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 3 \
    --tlsv1.2 --connect-timeout 10 --max-time 30 --retry 0 --max-filesize 16384 \
    https://raw.githubusercontent.com/GioNob/ouf-deploy/cfd24741ec350e5df09b5683042446e77a7e5132/scripts/launch-m2-retained-image-reconciliation-20261101.sh \
    --output "$ouf_image_reconcile_tmp/run.sh"
  printf '%s  %s\n' 1ac2191de860a7608af20200a5e748f6eba2949edf00008548da040a91f1ee15 "$ouf_image_reconcile_tmp/run.sh" | sha256sum --check --strict
  sudo -v
  set +e
  bash "$ouf_image_reconcile_tmp/run.sh"
  ouf_image_reconcile_exit=$?
  set -e
  printf 'ImageByteReconciliationExit=%s\n' "$ouf_image_reconcile_exit"
  exit "$ouf_image_reconcile_exit"
)
