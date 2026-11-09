#!/usr/bin/env bash
# Remove only the exact proven-unmounted provider namespace placeholder.
set -euo pipefail
if (( $# != 0 )); then printf '%s\n' 'Usage: bounded recovery (no arguments)' >&2; exit 2; fi
umask 077
ouf_terminal_dir=$(mktemp -d /tmp/ouf-discovery-terminal.XXXXXX)
trap 'rm -rf -- "$ouf_terminal_dir"' EXIT
ouf_terminal_source='633aecc9ca6585ef3684f560125f64652d115c87'
for ouf_terminal_name in reconcile-discovery-placeholder-20261109.py read-discovery-lifecycle-20261109.py read-discovery-startup-20261109.py read-analysis-discovery-runtime-20261107.py; do
  curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
    --connect-timeout 10 --max-time 30 --max-filesize 65536 \
    "https://raw.githubusercontent.com/GioNob/ouf-deploy/$ouf_terminal_source/scripts/$ouf_terminal_name" \
    -o "$ouf_terminal_dir/$ouf_terminal_name"
done
(
  cd "$ouf_terminal_dir"
  sha256sum -c <<'SHA256'
94649eefceddc348c92172872bf0cb180c21bd057ae84f7b371d9b2aa6c6259f  reconcile-discovery-placeholder-20261109.py
4824c247ddb7c0c90b8740ebcaa1c2681dccd9efd7811666cb1c86210b322e67  read-discovery-lifecycle-20261109.py
0df0567b786f6d5317951c838062e166a4d5037a07d95a3c145b578949372a89  read-discovery-startup-20261109.py
ef8dc8c4887122f2b2d76c05eaff7a8850c31004fcd661de2b3e49f51d6cc1b4  read-analysis-discovery-runtime-20261107.py
SHA256
)
sudo python3 -I -B "$ouf_terminal_dir/reconcile-discovery-placeholder-20261109.py"
