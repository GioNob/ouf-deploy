#!/usr/bin/env bash
# Read stopped Ingestion metadata; no service mutation.
set -euo pipefail
ouf_work=$(mktemp -d /tmp/ouf-ingestion-resume-read.XXXXXX)
trap 'rm -rf -- "$ouf_work"' EXIT
ouf_source='e22ef8e3758b216789c20c0d2aa5b5d717126c41'
for ouf_name in read-ingestion-resume-prerequisites-20261108.py read-ingestion-wide-held-state-20261108.py read-discovery-contract-20261108.py read-analysis-discovery-runtime-20261107.py; do
  curl --fail --silent --show-error --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 30 \
    "https://raw.githubusercontent.com/GioNob/ouf-deploy/$ouf_source/scripts/$ouf_name" -o "$ouf_work/$ouf_name"
done
(
  cd "$ouf_work"
  sha256sum -c <<'SHA256'
0ea9e19b93be285f72e3431b38beb66814392f42e1023733c0728387563c0ab2  read-ingestion-resume-prerequisites-20261108.py
d04eb75ec6aafec7fe82c6a7bf91e88814bd47e7fee829a32eeb83e4a6e7fb8c  read-ingestion-wide-held-state-20261108.py
468660ed73a24c7b8a842f5b99a9c268890c99bb4206ca2e4719865326b27277  read-discovery-contract-20261108.py
ef8dc8c4887122f2b2d76c05eaff7a8850c31004fcd661de2b3e49f51d6cc1b4  read-analysis-discovery-runtime-20261107.py
SHA256
)
sudo python3 -I -B "$ouf_work/read-ingestion-resume-prerequisites-20261108.py"
