#!/usr/bin/env bash
# D-004: local human launcher, approval hash is never generated or accepted here.
set -euo pipefail
ouf_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
exec sudo python3 -I -B "$ouf_root/scripts/apply-gateway-collector-episodes-20261112.py" "$@"
