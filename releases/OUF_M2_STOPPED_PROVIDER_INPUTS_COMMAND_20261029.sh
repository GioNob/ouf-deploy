#!/usr/bin/env bash
(
set -Eeuo pipefail
umask 077
[[ "$(id -un)" = oufadmin && -t 0 && -t 1 ]] || { printf '%s\n' 'OUFADMIN_INTERACTIVE_SSH_REQUIRED' >&2; exit 1; }
ouf_bootstrap=$(mktemp -d "$HOME/ouf-m2-stopped-provider-bootstrap.XXXXXXXX")
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
  --max-redirs 3 --connect-timeout 15 --max-time 60 --max-filesize 16384 \
  'https://raw.githubusercontent.com/GioNob/ouf-deploy/0c29421d39190f784f62c3928ac69c9c1138587d/releases/prepare-m2-stopped-provider-inputs-20261029.sh' \
  -o "$ouf_bootstrap/run.sh"
printf '%s  %s\n' '7b56c3eb8128085ce5704432ac87f2f6e3b89e9c06375517521fa9e8a2280a39' "$ouf_bootstrap/run.sh" | sha256sum -c -
bash "$ouf_bootstrap/run.sh"
)
