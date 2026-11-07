(
  set -euo pipefail
  umask 077
  ouf_selected_image_tmp=$(mktemp -d)
  trap 'rm -rf -- "$ouf_selected_image_tmp"' EXIT
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 3 \
    --tlsv1.2 --connect-timeout 10 --max-time 30 --retry 0 --max-filesize 16384 \
    https://raw.githubusercontent.com/GioNob/ouf-deploy/1de7ba7fa5e393f64c25d3c19b47c88267553d3c/scripts/launch-m2-retained-selected-image-20261101.sh \
    --output "$ouf_selected_image_tmp/run.sh"
  printf '%s  %s\n' 7c534bc3d94b9fec0983c3d11508d94b4e335f0457c648939a5daf387608d89a "$ouf_selected_image_tmp/run.sh" | sha256sum --check --strict
  sudo -v
  set +e
  bash "$ouf_selected_image_tmp/run.sh"
  ouf_selected_image_exit=$?
  set -e
  printf 'SelectedRuntimeByteVerificationExit=%s\n' "$ouf_selected_image_exit"
  exit "$ouf_selected_image_exit"
)
