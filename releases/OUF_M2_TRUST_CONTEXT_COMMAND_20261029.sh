(
set -Eeuo pipefail
umask 077
[[ "$(id -un)" = oufadmin && -t 0 && -t 1 ]] || { printf '%s\n' 'OUFADMIN_INTERACTIVE_SSH_REQUIRED' >&2; exit 1; }
ouf_bootstrap=$(mktemp -d "$HOME/ouf-m2-trust-context-bootstrap.XXXXXXXX")
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
  --max-redirs 3 --connect-timeout 15 --max-time 60 --max-filesize 16384 \
  'https://raw.githubusercontent.com/GioNob/ouf-deploy/7d3c9cc8cfc7f8385f3a697e08b1b94737a08d61/releases/prepare-m2-discovery-trust-context-20261029.sh' \
  -o "$ouf_bootstrap/run.sh"
printf '%s  %s\n' 'cd8d4ea2a791a834db75e4022b290a1d037fce3f5445cffabf434399f1da8da5' "$ouf_bootstrap/run.sh" | sha256sum -c -
bash "$ouf_bootstrap/run.sh"
)
