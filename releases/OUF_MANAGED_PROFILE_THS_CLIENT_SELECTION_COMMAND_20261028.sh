(
  set -euo pipefail
  umask 077
  ouf_ths_client_launch=$(mktemp -d "$HOME/ouf-ths-client-launch.XXXXXXXX")
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 3 --connect-timeout 15 --max-time 60 --max-filesize 32768 \
    'https://raw.githubusercontent.com/GioNob/ouf-deploy/185c1e7e7665212ef4279c6678179c0b48a6bbc4/releases/read-managed-profile-ths-client-20261028.sh' \
    -o "$ouf_ths_client_launch/run.sh"
  printf '%s  %s\n' 'f9044ce26a520f8d53ae401ac6731d3b2899b8bfc6a7225c7312fc03d753c3ce' "$ouf_ths_client_launch/run.sh" | sha256sum --check -
  chmod 0400 "$ouf_ths_client_launch/run.sh"
  bash --noprofile --norc "$ouf_ths_client_launch/run.sh"
)
