(
set -euo pipefail
umask 077
ouf_material_bootstrap=$(mktemp -d "$HOME/ouf-m2-material-bootstrap.XXXXXXXX")
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
  --max-redirs 3 --connect-timeout 15 --max-time 60 --max-filesize 131072 \
  'https://raw.githubusercontent.com/GioNob/ouf-deploy/369ccc5cdb972dd7e361659f1f3d9cd47c59fe22/releases/prepare-m2-discovery-material-20261029.sh' \
  -o "$ouf_material_bootstrap/run.sh" &&
printf '%s  %s\n' '7e25e9e150f3452dd0e6c994ae0d38cb3db803cfb2c0dae59b2baa75d787c0bd' "$ouf_material_bootstrap/run.sh" | sha256sum -c - &&
chmod 0400 "$ouf_material_bootstrap/run.sh" &&
bash "$ouf_material_bootstrap/run.sh"
)
