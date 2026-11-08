#!/usr/bin/env bash
# Exact archived Ingestion 1024 candidate; preserve V18, existing work and backend identity.
set -euo pipefail
ouf_work=$(mktemp -d /tmp/ouf-ingestion-wide-install.XXXXXX)
trap 'rm -rf -- "$ouf_work"' EXIT
ouf_source='5d926783e3ec3d277b70d4962aa82f37cf2e1b18'
for ouf_name in upgrade-ingestion-wide-20261108.py read-ingestion-wide-preflight-20261108.py ingestion-wide-source-resources-20261108.json read-onboarding-wide-preflight-20261108.py upgrade-semantic-application-20261108.py read-discovery-contract-20261108.py read-analysis-discovery-runtime-20261107.py; do
  curl --fail --silent --show-error --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 30 \
    "https://raw.githubusercontent.com/GioNob/ouf-deploy/$ouf_source/scripts/$ouf_name" -o "$ouf_work/$ouf_name"
done
curl --fail --silent --show-error --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 30 \
  "https://raw.githubusercontent.com/GioNob/ouf-deploy/$ouf_source/tools/acquisition_read_native/retained_mac.py" -o "$ouf_work/retained_mac.py"
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
  --connect-timeout 15 --max-time 240 --max-filesize 150000000 \
  'https://nightly.link/GioNob/ouf-deploy/actions/artifacts/13633320899.zip' -o "$ouf_work/candidate.zip"
(
  cd "$ouf_work"
  sha256sum -c <<'SHA256'
f345e549aa75531f77a244966951ed775e98d90e0e24ebad85940a4bba7b8ee8  upgrade-ingestion-wide-20261108.py
4e04370c60cba787b1e125a7b934cc03bf6d8fc1dc0c867ae5c27b56e82be26f  read-ingestion-wide-preflight-20261108.py
6b53e6c008337e1acd5459a732e1c249fa843f4450b836e1d2b268e5b1644a2f  ingestion-wide-source-resources-20261108.json
fca0dccd2ed5e42904fa57a8c0d898eb537c233070653379971ef29d7b5498d6  read-onboarding-wide-preflight-20261108.py
2e7e7e42367b3329f6ebd441bba665f974ea43871049d863415524610138efb1  upgrade-semantic-application-20261108.py
468660ed73a24c7b8a842f5b99a9c268890c99bb4206ca2e4719865326b27277  read-discovery-contract-20261108.py
ef8dc8c4887122f2b2d76c05eaff7a8850c31004fcd661de2b3e49f51d6cc1b4  read-analysis-discovery-runtime-20261107.py
cb5dbbee4a80ce71860dfe5d32362a662d98898c58fd82009e69c5eb6ac1f7ce  retained_mac.py
83e15e242528d9128ddf5a813d0a9d4512f4076d07f845bab6a63ca1456b0109  candidate.zip
SHA256
)
sudo python3 -I -B "$ouf_work/upgrade-ingestion-wide-20261108.py" "$ouf_work/candidate.zip"
