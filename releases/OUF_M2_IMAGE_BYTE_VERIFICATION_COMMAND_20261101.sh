(
  set -euo pipefail
  umask 077
  ouf_image_verify_tmp=$(mktemp -d)
  trap 'rm -rf -- "$ouf_image_verify_tmp"' EXIT
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 3 \
    --tlsv1.2 --connect-timeout 10 --max-time 30 --retry 0 --max-filesize 16384 \
    https://raw.githubusercontent.com/GioNob/ouf-deploy/bdb49b4f018871930147c7a30d3734724f95a2ac/scripts/launch-m2-retained-image-verification-20261101.sh \
    --output "$ouf_image_verify_tmp/run.sh"
  printf '%s  %s\n' 575818ebf7d3607c6ffe2613aa4ed3c536f0fa6f96a1e19154f8370bda82c212 "$ouf_image_verify_tmp/run.sh" | sha256sum --check --strict
  sudo -v
  set +e
  bash "$ouf_image_verify_tmp/run.sh"
  ouf_image_verify_exit=$?
  set -e
  printf 'ImageByteVerificationExit=%s\n' "$ouf_image_verify_exit"
  exit "$ouf_image_verify_exit"
)
