#!/bin/bash
# Operator-only bounded private launch preparation. No candidate start.
set -euo pipefail
umask 077
oufPrep="$(mktemp)"
trap 'rm -f -- "$oufPrep"' EXIT
/home/oufadmin/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh api \
  -H 'Accept: application/vnd.github.raw+json' \
  'repos/GioNob/ouf-deploy/contents/tools/semantic_frame_compiler/prepare_provider_v2_launch_inputs.py?ref=d92712c3a164b04c8bbc2521573bb951c78a666f' > "$oufPrep"
oufHash='6485246f0fdcd94e849982b1e082ac987f666cf1ddecf6c58ed8a4a38410c46d'
printf '%s  %s\n' "$oufHash" "$oufPrep" | sha256sum -c -
sudo /bin/sh -c '
  set -eu
  umask 077
  oufRoot="$(mktemp -d /etc/ouf/deploy-snapshots/semantic-v2-launch-source-XXXXXXXX)"
  install -m 600 "$1" "$oufRoot/prepare.py"
  printf "%s  %s\n" "$2" "$oufRoot/prepare.py" | sha256sum -c -
  exec /usr/bin/python3.13 -I -B "$oufRoot/prepare.py"
' sh "$oufPrep" "$oufHash"
