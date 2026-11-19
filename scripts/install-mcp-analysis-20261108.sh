#!/usr/bin/env bash
# Exact archived MCP PR83 package; no gh installation or new application build.
set -euo pipefail
ouf_work=$(mktemp -d /tmp/ouf-mcp-analysis-install.XXXXXX)
trap 'rm -rf -- "$ouf_work"' EXIT
ouf_source='fcd06cd5b4fea69e7eaa59a4d5731b0bfc3131df'
for ouf_name in upgrade-mcp-analysis-20261108.py read-mcp-analysis-preflight-20261108.py upgrade-semantic-application-20261108.py apply-gateway-analysis-delta-20261108.py read-discovery-contract-20261108.py read-analysis-discovery-runtime-20261107.py; do
  curl --fail --silent --show-error --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 30 \
    "https://raw.githubusercontent.com/GioNob/ouf-deploy/$ouf_source/scripts/$ouf_name" -o "$ouf_work/$ouf_name"
done
curl --fail --silent --show-error --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 30 \
  "https://raw.githubusercontent.com/GioNob/ouf-deploy/$ouf_source/tools/acquisition_read_native/retained_mac.py" -o "$ouf_work/retained_mac.py"
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
  --connect-timeout 15 --max-time 180 --max-filesize 12000000 \
  'https://nightly.link/GioNob/ouf-mcp-server/actions/artifacts/13593930449.zip' -o "$ouf_work/candidate.zip"
(
  cd "$ouf_work"
  sha256sum -c <<'SHA256'
5f6739852c1a0d4318d6427c229409882a0f66ab1ad7110ed3c599300fa24758  upgrade-mcp-analysis-20261108.py
bf27b875fbc0fd90beb7cf5866835762faddaaa9df9dd353b1bc22c0e32d964a  read-mcp-analysis-preflight-20261108.py
2e7e7e42367b3329f6ebd441bba665f974ea43871049d863415524610138efb1  upgrade-semantic-application-20261108.py
7064c8443bb323c12a56846267e4faa9cb25bf3e6dfb35455e753fbe71ce8b01  apply-gateway-analysis-delta-20261108.py
468660ed73a24c7b8a842f5b99a9c268890c99bb4206ca2e4719865326b27277  read-discovery-contract-20261108.py
ef8dc8c4887122f2b2d76c05eaff7a8850c31004fcd661de2b3e49f51d6cc1b4  read-analysis-discovery-runtime-20261107.py
cb5dbbee4a80ce71860dfe5d32362a662d98898c58fd82009e69c5eb6ac1f7ce  retained_mac.py
2eae47d8c90b00b992bc916e5ce5a5bd32d9e724abe27d2838bd5d08ebc68d5e  candidate.zip
SHA256
)
sudo python3 -I -B "$ouf_work/upgrade-mcp-analysis-20261108.py" "$ouf_work/candidate.zip"
