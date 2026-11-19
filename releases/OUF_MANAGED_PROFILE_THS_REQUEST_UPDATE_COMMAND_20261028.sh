(
  set -euo pipefail
  umask 077
  ouf_ths_update_launch=$(mktemp -d "$HOME/ouf-ths-update-launch.XXXXXXXX")
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 3 --connect-timeout 15 --max-time 60 --max-filesize 32768 \
    'https://raw.githubusercontent.com/GioNob/ouf-deploy/79710e413ef0692f65c04836372150a701af126f/releases/apply-managed-profile-ths-request-20261028.sh' \
    -o "$ouf_ths_update_launch/run.sh"
  printf '%s  %s\n' '689c0087ebc41cfdc410dfb922e6e18056debd35d1981c39e0d9487e35b4e088' "$ouf_ths_update_launch/run.sh" | sha256sum --check -
  chmod 0400 "$ouf_ths_update_launch/run.sh"
  bash --noprofile --norc "$ouf_ths_update_launch/run.sh"
)
