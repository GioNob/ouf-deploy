#!/usr/bin/env bash
# Current provider native lifecycle: read only, no cleanup or service start.
set -euo pipefail
if (( $# != 0 )); then printf '%s\n' 'Usage: reader (no arguments)' >&2; exit 2; fi
umask 077
ouf_lifecycle_dir=$(mktemp -d /tmp/ouf-discovery-lifecycle.XXXXXX)
trap 'rm -rf -- "$ouf_lifecycle_dir"' EXIT
ouf_lifecycle_source='789a2e131abda301424f7d011b545e4607a5703b'
for ouf_lifecycle_name in read-discovery-lifecycle-20261109.py read-discovery-startup-20261109.py read-analysis-discovery-runtime-20261107.py; do
  curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
    --connect-timeout 10 --max-time 30 --max-filesize 65536 \
    "https://raw.githubusercontent.com/GioNob/ouf-deploy/$ouf_lifecycle_source/scripts/$ouf_lifecycle_name" \
    -o "$ouf_lifecycle_dir/$ouf_lifecycle_name"
done
(
  cd "$ouf_lifecycle_dir"
  sha256sum -c <<'SHA256'
4824c247ddb7c0c90b8740ebcaa1c2681dccd9efd7811666cb1c86210b322e67  read-discovery-lifecycle-20261109.py
0df0567b786f6d5317951c838062e166a4d5037a07d95a3c145b578949372a89  read-discovery-startup-20261109.py
ef8dc8c4887122f2b2d76c05eaff7a8850c31004fcd661de2b3e49f51d6cc1b4  read-analysis-discovery-runtime-20261107.py
SHA256
)
sudo python3 -I -B "$ouf_lifecycle_dir/read-discovery-lifecycle-20261109.py"
