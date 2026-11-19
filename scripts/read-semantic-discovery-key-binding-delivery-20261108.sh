#!/usr/bin/env bash
# Pinned read-only binding diagnosis; no application restart or migration.
(
  set -eu
  ouf_work=$(mktemp -d /tmp/ouf-semantic-key.XXXXXX)
  trap 'rm -rf -- "$ouf_work"' EXIT
  ouf_base='https://raw.githubusercontent.com/GioNob/ouf-deploy/d5ac065cd92f6f2b21b313009fc5c703b8a98547/scripts'
  for ouf_file in \
    read-semantic-discovery-key-binding-20261108.py \
    read-discovery-contract-20261108.py \
    read-analysis-discovery-runtime-20261107.py
  do
    curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
      --connect-timeout 10 --max-time 30 \
      "$ouf_base/$ouf_file" -o "$ouf_work/$ouf_file"
  done
  (
    cd "$ouf_work"
    sha256sum -c - <<'SHA256'
dad3bca82b930b2dded125183323fcb124ecb9ca127b699109498fb4ca2780a2  read-semantic-discovery-key-binding-20261108.py
468660ed73a24c7b8a842f5b99a9c268890c99bb4206ca2e4719865326b27277  read-discovery-contract-20261108.py
ef8dc8c4887122f2b2d76c05eaff7a8850c31004fcd661de2b3e49f51d6cc1b4  read-analysis-discovery-runtime-20261107.py
SHA256
  )
  sudo python3 -I -B "$ouf_work/read-semantic-discovery-key-binding-20261108.py"
)
