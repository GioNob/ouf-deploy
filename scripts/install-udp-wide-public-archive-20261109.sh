#!/usr/bin/env bash
# Pinned archived UDP 1024; preserve SeaweedFS, both networks and V36.
set -euo pipefail
if (( $# > 1 )); then printf '%s\n' 'Usage: installer [exact-candidate.zip]' >&2; exit 2; fi
ouf_work=$(mktemp -d /tmp/ouf-udp-wide-install.XXXXXX)
trap 'rm -rf -- "$ouf_work"' EXIT
ouf_source='2a9e90cfb4a18d8a221ece1cde1019257684bdf5'
for ouf_name in upgrade-udp-wide-20261109.py read-udp-wide-preflight-20261108.py udp-wide-source-resources-20261108.json read-onboarding-wide-preflight-20261108.py upgrade-semantic-application-20261108.py read-discovery-contract-20261108.py read-analysis-discovery-runtime-20261107.py; do
  curl --fail --silent --show-error --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 30 \
    "https://raw.githubusercontent.com/GioNob/ouf-deploy/$ouf_source/scripts/$ouf_name" -o "$ouf_work/$ouf_name"
done
curl --fail --silent --show-error --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 30 \
  "https://raw.githubusercontent.com/GioNob/ouf-deploy/$ouf_source/tools/acquisition_read_native/retained_mac.py" -o "$ouf_work/retained_mac.py"
if (( $# == 1 )); then
  cp -- "$1" "$ouf_work/candidate.zip"
else
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --connect-timeout 15 --max-time 240 --max-filesize 130000000 \
    'https://nightly.link/GioNob/ouf-deploy/actions/runs/42527648108/udp-wide-image-42527648108.zip' -o "$ouf_work/candidate.zip"
fi
(
  cd "$ouf_work"
  sha256sum -c <<'SHA256'
12439c8bd9fa3a046171bcbd0a8f4d4987acaac77f877f2027c9abe862ee4516  upgrade-udp-wide-20261109.py
fa8239a9c6ddd99ea6cddd9a11ae5246d3e63440a54d70c7c6eeef8f87d2664f  read-udp-wide-preflight-20261108.py
01e35ca79b53ea15531f7ded57f76284f55353bb5f1e77625ac8790f57baa746  udp-wide-source-resources-20261108.json
fca0dccd2ed5e42904fa57a8c0d898eb537c233070653379971ef29d7b5498d6  read-onboarding-wide-preflight-20261108.py
2e7e7e42367b3329f6ebd441bba665f974ea43871049d863415524610138efb1  upgrade-semantic-application-20261108.py
468660ed73a24c7b8a842f5b99a9c268890c99bb4206ca2e4719865326b27277  read-discovery-contract-20261108.py
ef8dc8c4887122f2b2d76c05eaff7a8850c31004fcd661de2b3e49f51d6cc1b4  read-analysis-discovery-runtime-20261107.py
cb5dbbee4a80ce71860dfe5d32362a662d98898c58fd82009e69c5eb6ac1f7ce  retained_mac.py
f0f55c74a4674e78e6982ffa3575f2c7bcc96741dfdcde5da288863f0cf78340  candidate.zip
SHA256
)
sudo python3 -I -B "$ouf_work/upgrade-udp-wide-20261109.py" "$ouf_work/candidate.zip"
