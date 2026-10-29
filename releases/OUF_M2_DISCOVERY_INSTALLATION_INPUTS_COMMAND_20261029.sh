(
  set -Eeuo pipefail
  umask 077
  ouf_m2_installation_bootstrap=$(mktemp -d "$HOME/ouf-m2-installation-bootstrap.XXXXXXXX")
  curl --fail --silent --show-error --location \
    --proto '=https' --proto-redir '=https' \
    --max-redirs 3 --connect-timeout 15 --max-time 60 \
    --max-filesize 16384 \
    'https://raw.githubusercontent.com/GioNob/ouf-deploy/c2035ca457e95f95d772b8e3660c241bfdec6e7b/releases/read-m2-discovery-installation-inputs-20261029.sh' \
    -o "$ouf_m2_installation_bootstrap/run.sh"
  printf '%s  %s\n' \
    'ec7775e982a705feb7a8ceaaa789397241d990eed36c7efefb26fde675dcb969' \
    "$ouf_m2_installation_bootstrap/run.sh" | sha256sum -c -
  chmod 0400 "$ouf_m2_installation_bootstrap/run.sh"
  /usr/bin/bash "$ouf_m2_installation_bootstrap/run.sh"
)
