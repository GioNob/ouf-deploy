#!/usr/bin/env bash
# Exact v2 startup metadata and bounded secret comparison; no service changes.
set -euo pipefail
if (( $# != 0 )); then printf '%s\n' 'Usage: reader (no arguments)' >&2; exit 2; fi
umask 077
ouf_startup_dir=$(mktemp -d /tmp/ouf-discovery-startup.XXXXXX)
trap 'rm -rf -- "$ouf_startup_dir"' EXIT
ouf_startup_source='066168fafad38c0f722541e710fb46ce2ac370de'
for ouf_startup_name in read-discovery-startup-20261109.py read-analysis-discovery-runtime-20261107.py; do
  curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
    --connect-timeout 10 --max-time 30 --max-filesize 65536 \
    "https://raw.githubusercontent.com/GioNob/ouf-deploy/$ouf_startup_source/scripts/$ouf_startup_name" \
    -o "$ouf_startup_dir/$ouf_startup_name"
done
(
  cd "$ouf_startup_dir"
  sha256sum -c <<'SHA256'
0df0567b786f6d5317951c838062e166a4d5037a07d95a3c145b578949372a89  read-discovery-startup-20261109.py
ef8dc8c4887122f2b2d76c05eaff7a8850c31004fcd661de2b3e49f51d6cc1b4  read-analysis-discovery-runtime-20261107.py
SHA256
)
sudo python3 -I -B "$ouf_startup_dir/read-discovery-startup-20261109.py"
