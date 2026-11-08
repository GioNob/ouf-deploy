#!/usr/bin/env bash
# Finish only the verified stopped Ingestion prefix. No image download/import or repeated stop.
set -euo pipefail
ouf_work=$(mktemp -d /tmp/ouf-ingestion-resume.XXXXXX)
trap 'rm -rf -- "$ouf_work"' EXIT
ouf_source='9f1dfd3af254606afc28b85d4eef5c9d54d35b3a'
for ouf_name in resume-ingestion-wide-20261108.py upgrade-ingestion-wide-20261108.py read-ingestion-resume-prerequisites-20261108.py read-ingestion-wide-held-state-20261108.py read-discovery-contract-20261108.py read-analysis-discovery-runtime-20261107.py upgrade-semantic-application-20261108.py; do
  curl --fail --silent --show-error --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 30 \
    "https://raw.githubusercontent.com/GioNob/ouf-deploy/$ouf_source/scripts/$ouf_name" -o "$ouf_work/$ouf_name"
done
curl --fail --silent --show-error --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 30 \
  "https://raw.githubusercontent.com/GioNob/ouf-deploy/$ouf_source/tools/acquisition_read_native/retained_mac.py" -o "$ouf_work/retained_mac.py"
(
  cd "$ouf_work"
  sha256sum -c <<'SHA256'
ab43c6d02e7d8ada08a3325f1e0b9a8559fff7324338b98d117371497bf54390  resume-ingestion-wide-20261108.py
f345e549aa75531f77a244966951ed775e98d90e0e24ebad85940a4bba7b8ee8  upgrade-ingestion-wide-20261108.py
0ea9e19b93be285f72e3431b38beb66814392f42e1023733c0728387563c0ab2  read-ingestion-resume-prerequisites-20261108.py
d04eb75ec6aafec7fe82c6a7bf91e88814bd47e7fee829a32eeb83e4a6e7fb8c  read-ingestion-wide-held-state-20261108.py
468660ed73a24c7b8a842f5b99a9c268890c99bb4206ca2e4719865326b27277  read-discovery-contract-20261108.py
ef8dc8c4887122f2b2d76c05eaff7a8850c31004fcd661de2b3e49f51d6cc1b4  read-analysis-discovery-runtime-20261107.py
2e7e7e42367b3329f6ebd441bba665f974ea43871049d863415524610138efb1  upgrade-semantic-application-20261108.py
cb5dbbee4a80ce71860dfe5d32362a662d98898c58fd82009e69c5eb6ac1f7ce  retained_mac.py
SHA256
)
sudo python3 -I -B "$ouf_work/resume-ingestion-wide-20261108.py"
