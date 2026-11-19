#!/usr/bin/env bash
# D-004: local human launcher; no SSH or automatic approval.
set -euo pipefail
ouf_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
exec sudo python3 -I -B "$ouf_root/scripts/apply-gateway-owner-incidents-20261112.py" "$@"
