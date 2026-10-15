#!/usr/bin/env bash
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [ ! -x "$ouf_gh" ]; then
  ouf_gh="$(command -v gh || true)"
fi
[ -n "$ouf_gh" ] || { echo 'Client GitHub non trovato'; exit 1; }
ouf_read="$(mktemp -d "$HOME/ouf-retained-rootfs-proposal.XXXXXXXX")"
"$ouf_gh" api \
  'repos/GioNob/ouf-deploy/contents/scripts/read-chatbot-retained-rootfs-proposal-20261015.py?ref=3b22669289c82e03d57743b48cf8be9e5e73ae9f' \
  --jq .content | base64 --decode > "$ouf_read/read.py"
printf '%s  %s\n' \
  '40df05f3522f5213a74e83fd2621bba314dea3b5c6a7f530bf2415fff36d8276' \
  "$ouf_read/read.py" | sha256sum --check -
sudo /usr/bin/python3 -I -B -S "$ouf_read/read.py" \
  2>&1 | tee "$ouf_read/readback.log"
