(
  set -euo pipefail
  umask 077
  ouf_capability_launch=$(mktemp -d "$HOME/ouf-profile-capability-launch.XXXXXXXX")
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 3 --connect-timeout 15 --max-time 60 --max-filesize 32768 \
    'https://raw.githubusercontent.com/GioNob/ouf-deploy/7360b98ee12cd884d37a97d54806b44dbe4f9e4f/releases/read-managed-profile-capabilities-20261028.sh' \
    -o "$ouf_capability_launch/run.sh"
  printf '%s  %s\n' 'bdce4c433aff3b43cd5aeb90ade8fe4ebdc4f3ef283a2621df6347498c7141eb' "$ouf_capability_launch/run.sh" | sha256sum --check -
  chmod 0400 "$ouf_capability_launch/run.sh"
  bash --noprofile --norc "$ouf_capability_launch/run.sh"
)
