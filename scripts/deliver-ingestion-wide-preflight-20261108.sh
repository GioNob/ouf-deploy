#!/usr/bin/env bash
# Read-only installed Ingestion package, history and activity counts.
set -euo pipefail
ouf_work=$(mktemp -d /tmp/ouf-ingestion-wide-read.XXXXXX)
trap 'rm -rf -- "$ouf_work"' EXIT
ouf_source='4a58cd82326bd3a9fccc65a329feb80ebb3b66e0'
for ouf_name in read-ingestion-wide-preflight-20261108.py ingestion-wide-source-resources-20261108.json read-onboarding-wide-preflight-20261108.py read-discovery-contract-20261108.py read-analysis-discovery-runtime-20261107.py; do
  curl --fail --silent --show-error --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 30 \
    "https://raw.githubusercontent.com/GioNob/ouf-deploy/$ouf_source/scripts/$ouf_name" -o "$ouf_work/$ouf_name"
done
(
  cd "$ouf_work"
  sha256sum -c <<'SHA256'
4e04370c60cba787b1e125a7b934cc03bf6d8fc1dc0c867ae5c27b56e82be26f  read-ingestion-wide-preflight-20261108.py
6b53e6c008337e1acd5459a732e1c249fa843f4450b836e1d2b268e5b1644a2f  ingestion-wide-source-resources-20261108.json
fca0dccd2ed5e42904fa57a8c0d898eb537c233070653379971ef29d7b5498d6  read-onboarding-wide-preflight-20261108.py
468660ed73a24c7b8a842f5b99a9c268890c99bb4206ca2e4719865326b27277  read-discovery-contract-20261108.py
ef8dc8c4887122f2b2d76c05eaff7a8850c31004fcd661de2b3e49f51d6cc1b4  read-analysis-discovery-runtime-20261107.py
SHA256
)
sudo python3 -I -B "$ouf_work/read-ingestion-wide-preflight-20261108.py"
