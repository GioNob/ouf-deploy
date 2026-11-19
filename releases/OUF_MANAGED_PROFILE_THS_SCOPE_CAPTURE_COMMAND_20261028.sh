# New read-only scope request capture; no login/APPROVO or runtime writes. STOP: preserve, never rerun.
(
  set -euo pipefail
  umask 077
  ouf_ths_scope_launch=$(mktemp -d "$HOME/ouf-ths-scope-launch.XXXXXXXX")
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 3 --connect-timeout 15 --max-time 60 --max-filesize 32768 \
    'https://raw.githubusercontent.com/GioNob/ouf-deploy/006e729bf20e83be7725d3c42b4b4bbfcb6df659/releases/read-managed-profile-ths-scopes-20261028.sh' \
    -o "$ouf_ths_scope_launch/run.sh"
  printf '%s  %s\n' 'b6afaba5cba7379761b982ce7f9f63bd9d0e000cf8328a57bee3aa6a32fc4d99' "$ouf_ths_scope_launch/run.sh" | sha256sum --check -
  chmod 0400 "$ouf_ths_scope_launch/run.sh"
  bash --noprofile --norc "$ouf_ths_scope_launch/run.sh"
)
