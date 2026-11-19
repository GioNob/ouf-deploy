#!/usr/bin/env bash
# Exact qualified one-property repair; existing image/key/schema are reused.
set -euo pipefail
ouf_work=$(mktemp -d /tmp/ouf-semantic-key-repair.XXXXXX)
trap 'rm -rf -- "$ouf_work"' EXIT
ouf_base='https://raw.githubusercontent.com/GioNob/ouf-deploy/bece4c5b3dbaf20dcec05b19b4352284a23cc92e'
for ouf_file in \
  scripts/repair-semantic-discovery-key-20261108.py \
  scripts/upgrade-semantic-application-20261108.py \
  scripts/read-semantic-discovery-key-binding-20261108.py \
  scripts/read-semantic-application-exit-20261108.py \
  scripts/apply-gateway-analysis-delta-20261108.py \
  scripts/read-discovery-contract-20261108.py \
  scripts/read-analysis-discovery-runtime-20261107.py \
  tools/acquisition_read_native/retained_mac.py
do
  curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
    --connect-timeout 10 --max-time 30 \
    "$ouf_base/$ouf_file" -o "$ouf_work/${ouf_file##*/}"
done
(
  cd "$ouf_work"
  sha256sum -c - <<'SHA256'
8dc1752060b32f321bebc9816e9caa817d9707b2889603a236be8b482f338a40  repair-semantic-discovery-key-20261108.py
2e7e7e42367b3329f6ebd441bba665f974ea43871049d863415524610138efb1  upgrade-semantic-application-20261108.py
dad3bca82b930b2dded125183323fcb124ecb9ca127b699109498fb4ca2780a2  read-semantic-discovery-key-binding-20261108.py
68a3e85307fdefed431e3ea286ac55e32f388435522393fecc6784765c54fc00  read-semantic-application-exit-20261108.py
7064c8443bb323c12a56846267e4faa9cb25bf3e6dfb35455e753fbe71ce8b01  apply-gateway-analysis-delta-20261108.py
468660ed73a24c7b8a842f5b99a9c268890c99bb4206ca2e4719865326b27277  read-discovery-contract-20261108.py
ef8dc8c4887122f2b2d76c05eaff7a8850c31004fcd661de2b3e49f51d6cc1b4  read-analysis-discovery-runtime-20261107.py
cb5dbbee4a80ce71860dfe5d32362a662d98898c58fd82009e69c5eb6ac1f7ce  retained_mac.py
SHA256
)
sudo python3 -I -B "$ouf_work/repair-semantic-discovery-key-20261108.py"
