#!/usr/bin/env bash
# Read discovery metadata only. No application, database or credential calls.
set -euo pipefail
if (( $# != 0 )); then printf '%s\n' 'Usage: reader (no arguments)' >&2; exit 2; fi
umask 077
ouf_read_dir=$(mktemp -d /tmp/ouf-discovery-bindings.XXXXXX)
trap 'rm -rf -- "$ouf_read_dir"' EXIT
ouf_read_source='73bb41e5d6165ec704b06cb45c3a198669ebc6e1'
for ouf_read_name in read-discovery-activation-bindings-20261109.py read-discovery-contract-20261108.py read-analysis-discovery-runtime-20261107.py; do
  curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
    --connect-timeout 10 --max-time 30 --max-filesize 65536 \
    "https://raw.githubusercontent.com/GioNob/ouf-deploy/$ouf_read_source/scripts/$ouf_read_name" \
    -o "$ouf_read_dir/$ouf_read_name"
done
(
  cd "$ouf_read_dir"
  sha256sum -c <<'SHA256'
7f9232b3c2832a57769f0271003b1ce0f2ea57b7e6b0ba266e02dbf6549cc8a7  read-discovery-activation-bindings-20261109.py
468660ed73a24c7b8a842f5b99a9c268890c99bb4206ca2e4719865326b27277  read-discovery-contract-20261108.py
ef8dc8c4887122f2b2d76c05eaff7a8850c31004fcd661de2b3e49f51d6cc1b4  read-analysis-discovery-runtime-20261107.py
SHA256
)
sudo python3 -I -B "$ouf_read_dir/read-discovery-activation-bindings-20261109.py"
