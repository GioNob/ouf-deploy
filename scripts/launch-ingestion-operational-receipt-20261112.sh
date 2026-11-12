#!/usr/bin/env bash
# D-004: the human runs this launcher; no remote execution or automatic approval.
set -euo pipefail
ouf_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
exec sudo python3 -I -B "$ouf_root/scripts/apply-ingestion-operational-receipt-20261112.py" "$@"
