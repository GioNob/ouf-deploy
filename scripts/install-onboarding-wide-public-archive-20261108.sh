#!/usr/bin/env bash
# Exact archived Onboarding 1024 candidate; preserve both SeaweedFS networks.
set -euo pipefail
ouf_work=$(mktemp -d /tmp/ouf-onboarding-wide-install.XXXXXX)
trap 'rm -rf -- "$ouf_work"' EXIT
ouf_source='e5bec2eed1a061f2b640ca281288a05b83425c0b'
for ouf_name in upgrade-onboarding-wide-20261108.py read-onboarding-wide-preflight-20261108.py onboarding-wide-candidate-package-20261108.json upgrade-semantic-application-20261108.py read-discovery-contract-20261108.py read-analysis-discovery-runtime-20261107.py; do
  curl --fail --silent --show-error --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 30 \
    "https://raw.githubusercontent.com/GioNob/ouf-deploy/$ouf_source/scripts/$ouf_name" -o "$ouf_work/$ouf_name"
done
curl --fail --silent --show-error --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 30 \
  "https://raw.githubusercontent.com/GioNob/ouf-deploy/$ouf_source/tools/acquisition_read_native/retained_mac.py" -o "$ouf_work/retained_mac.py"
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
  --connect-timeout 15 --max-time 240 --max-filesize 230000000 \
  'https://nightly.link/GioNob/ouf-source-onboarding/actions/artifacts/13592211485.zip' -o "$ouf_work/candidate.zip"
(
  cd "$ouf_work"
  sha256sum -c <<'SHA256'
bdedeba016f27b63c21f5892e9eb11bd1afe41aaa322060c6cae5fe9ceba6c68  upgrade-onboarding-wide-20261108.py
fca0dccd2ed5e42904fa57a8c0d898eb537c233070653379971ef29d7b5498d6  read-onboarding-wide-preflight-20261108.py
3bc9191934011c52a682c4c509c2de60349d8ab9c2494e5a64348661db816fe2  onboarding-wide-candidate-package-20261108.json
2e7e7e42367b3329f6ebd441bba665f974ea43871049d863415524610138efb1  upgrade-semantic-application-20261108.py
468660ed73a24c7b8a842f5b99a9c268890c99bb4206ca2e4719865326b27277  read-discovery-contract-20261108.py
ef8dc8c4887122f2b2d76c05eaff7a8850c31004fcd661de2b3e49f51d6cc1b4  read-analysis-discovery-runtime-20261107.py
cb5dbbee4a80ce71860dfe5d32362a662d98898c58fd82009e69c5eb6ac1f7ce  retained_mac.py
0894eceebb12bb8e81aceb6293713374ce6a3f2e6cdf50bb1be36f6b478bd0d0  candidate.zip
SHA256
)
sudo python3 -I -B "$ouf_work/upgrade-onboarding-wide-20261108.py" "$ouf_work/candidate.zip"
