(
  set -euo pipefail
  umask 077
  ouf_control_launch=$(mktemp -d "$HOME/ouf-control-update-launch.XXXXXXXX")
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 3 --connect-timeout 15 --max-time 60 --max-filesize 32768 \
    'https://raw.githubusercontent.com/GioNob/ouf-deploy/965583e9aadc1a690541c83d543626abe8bf165c/releases/apply-managed-csv-control-update-20261027.sh' \
    -o "$ouf_control_launch/run.sh"
  printf '%s  %s\n' 'f91f09abc6b8c399256a246ff738c462d59540d5cd36a047041d81a4ab94260a' "$ouf_control_launch/run.sh" | sha256sum --check -
  chmod 0400 "$ouf_control_launch/run.sh"
  bash --noprofile --norc "$ouf_control_launch/run.sh"
)
