#!/usr/bin/env bash
# Only redacted inventory; no candidate installation.
set -euo pipefail
umask 077
OUF_INV_COMMIT=671cbef1f16fec195f8b0095efdf561479a117ed
OUF_INV_SHA=7e61c2477b82411ba7cc97a4b9f5ee1556ad8453d537c51e8abb3c221fa4ec8a
OUF_INV_GH="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [[ ! -x "$OUF_INV_GH" ]]; then
  OUF_INV_GH="$(command -v gh)" || { echo 'GH_UNAVAILABLE_NO_SUDO_EXECUTED' >&2; exit 1; }
fi
OUF_INV_STAGE="$(mktemp -d "$HOME/ouf-vps-inventory.XXXXXXXX")"
"$OUF_INV_GH" api   "repos/GioNob/ouf-deploy/contents/scripts/collect-vps-inventory.py?ref=$OUF_INV_COMMIT"   --jq '.content' > "$OUF_INV_STAGE/source.b64"
base64 --decode "$OUF_INV_STAGE/source.b64" > "$OUF_INV_STAGE/read.py"
printf '%s  %s\n' "$OUF_INV_SHA" "$OUF_INV_STAGE/read.py" | sha256sum --check
sudo /usr/bin/python3 -I -B "$OUF_INV_STAGE/read.py" | tee "$OUF_INV_STAGE/inventory.json"
printf 'INVENTORY_REPORT=%s\n' "$OUF_INV_STAGE/inventory.json"
