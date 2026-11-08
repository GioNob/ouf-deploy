#!/usr/bin/env bash
# Read-only UDP preflight; no image import, service stop or migration.
set -euo pipefail
ouf_work=$(mktemp -d /tmp/ouf-udp-preflight.XXXXXX)
trap 'rm -rf -- "$ouf_work"' EXIT
ouf_source='b5a0a7b7177471218e42ce3e2ba2602c3fdf63f1'
for ouf_name in read-udp-wide-preflight-20261108.py udp-wide-source-resources-20261108.json read-onboarding-wide-preflight-20261108.py read-discovery-contract-20261108.py read-analysis-discovery-runtime-20261107.py; do
  curl --fail --silent --show-error --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 30 \
    "https://raw.githubusercontent.com/GioNob/ouf-deploy/$ouf_source/scripts/$ouf_name" -o "$ouf_work/$ouf_name"
done
(
  cd "$ouf_work"
  sha256sum -c <<'SHA256'
fa8239a9c6ddd99ea6cddd9a11ae5246d3e63440a54d70c7c6eeef8f87d2664f  read-udp-wide-preflight-20261108.py
01e35ca79b53ea15531f7ded57f76284f55353bb5f1e77625ac8790f57baa746  udp-wide-source-resources-20261108.json
fca0dccd2ed5e42904fa57a8c0d898eb537c233070653379971ef29d7b5498d6  read-onboarding-wide-preflight-20261108.py
468660ed73a24c7b8a842f5b99a9c268890c99bb4206ca2e4719865326b27277  read-discovery-contract-20261108.py
ef8dc8c4887122f2b2d76c05eaff7a8850c31004fcd661de2b3e49f51d6cc1b4  read-analysis-discovery-runtime-20261107.py
SHA256
)
sudo python3 -I -B "$ouf_work/read-udp-wide-preflight-20261108.py"
