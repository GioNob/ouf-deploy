(
set -Eeuo pipefail
umask 077
[[ "$(id -un)" = oufadmin && -t 0 && -t 1 ]] || { printf '%s\n' 'OUFADMIN_INTERACTIVE_SSH_REQUIRED' >&2; exit 1; }
ouf_bootstrap=$(mktemp -d "$HOME/ouf-m2-provider-reconcile-bootstrap.XXXXXXXX")
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
  --max-redirs 3 --connect-timeout 15 --max-time 60 --max-filesize 16384 \
  'https://raw.githubusercontent.com/GioNob/ouf-deploy/4dcbdc900855f401c897f99d77fae68fb8816066/releases/prepare-m2-provider-reconciliation-20261029.sh' \
  -o "$ouf_bootstrap/run.sh"
printf '%s  %s\n' '36895e6d53ed008670937b03a6bc947bb45c2ca6441cca34a9c0b371c21cc5ce' "$ouf_bootstrap/run.sh" | sha256sum -c -
bash "$ouf_bootstrap/run.sh"
)
