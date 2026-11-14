#!/usr/bin/env bash
set -euo pipefail
ouf_work=$(mktemp -d /tmp/ouf-onboarding-wide-read.XXXXXX)
trap 'rm -rf -- "$ouf_work"' EXIT
ouf_source='91568e8deaf41bfd059b4a3ec41a91e2c5c953c7'
for ouf_name in read-onboarding-wide-preflight-20261108.py onboarding-wide-candidate-package-20261108.json read-discovery-contract-20261108.py read-analysis-discovery-runtime-20261107.py; do
  curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
    --connect-timeout 10 --max-time 30 \
    "https://raw.githubusercontent.com/GioNob/ouf-deploy/$ouf_source/scripts/$ouf_name" \
    -o "$ouf_work/$ouf_name"
done
(
  cd "$ouf_work"
  sha256sum -c <<'SHA256'
fca0dccd2ed5e42904fa57a8c0d898eb537c233070653379971ef29d7b5498d6  read-onboarding-wide-preflight-20261108.py
3bc9191934011c52a682c4c509c2de60349d8ab9c2494e5a64348661db816fe2  onboarding-wide-candidate-package-20261108.json
468660ed73a24c7b8a842f5b99a9c268890c99bb4206ca2e4719865326b27277  read-discovery-contract-20261108.py
ef8dc8c4887122f2b2d76c05eaff7a8850c31004fcd661de2b3e49f51d6cc1b4  read-analysis-discovery-runtime-20261107.py
SHA256
)
sudo python3 -I -B "$ouf_work/read-onboarding-wide-preflight-20261108.py"
