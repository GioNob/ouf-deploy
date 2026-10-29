(
set -euo pipefail
umask 077
ouf_roles_bootstrap=$(mktemp -d "$HOME/ouf-m2-material-roles-bootstrap.XXXXXXXX")
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
  --max-redirs 3 --connect-timeout 15 --max-time 60 --max-filesize 131072 \
  'https://raw.githubusercontent.com/GioNob/ouf-deploy/8bfaafed1b23b79500a3b4867a4f75112d87ca9e/releases/prepare-m2-discovery-material-roles-20261029.sh' \
  -o "$ouf_roles_bootstrap/run.sh" &&
printf '%s  %s\n' '06ca017cd74cf3cc87a81c32787a1ea2ab3929453809599bc682067f14fdcb69' "$ouf_roles_bootstrap/run.sh" | sha256sum -c - &&
chmod 0400 "$ouf_roles_bootstrap/run.sh" &&
bash "$ouf_roles_bootstrap/run.sh"
)
