(
  set -euo pipefail
  umask 077
  ouf_image_input_tmp=$(mktemp -d)
  trap 'rm -rf -- "$ouf_image_input_tmp"' EXIT
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 3 \
    --tlsv1.2 --connect-timeout 10 --max-time 30 --retry 0 --max-filesize 16384 \
    https://raw.githubusercontent.com/GioNob/ouf-deploy/1a519f533318d9274950b017b1fa2c4c928c70d1/scripts/launch-m2-retained-image-archives-20261101.sh \
    --output "$ouf_image_input_tmp/run.sh"
  printf '%s  %s\n' ad50569c294bc39a541f0fdeefea4eac27331c03ebe9ab133dca3ac2adc1dd16 "$ouf_image_input_tmp/run.sh" | sha256sum --check --strict
  sudo -v
  set +e
  bash "$ouf_image_input_tmp/run.sh"
  ouf_image_input_exit=$?
  set -e
  printf 'ImageArchiveInputExit=%s\n' "$ouf_image_input_exit"
  exit "$ouf_image_input_exit"
)
