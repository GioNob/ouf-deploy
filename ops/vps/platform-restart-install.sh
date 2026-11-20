#!/usr/bin/env bash
# Run from a trusted local checkout, as root. Python is supplied by the operator.
set -euo pipefail
umask 077
# Claude fills this delivery commit after review (D-001).
C=0000000000000000000000000000000000000000
[[ $C =~ ^[0-9a-f]{40}$ && $C != 0000000000000000000000000000000000000000 ]] ||
  { echo 'Pin della consegna mancante' >&2; exit 2; }
[[ $EUID == 0 && ${OUF_PYTHON:?absolute Python 3.13 executable} == /* ]]
if [[ ${1:-} == operate ]]; then
  [[ ${OUF_OPERATOR_PIN:-} == "$C" ]] || { echo 'Pin operatore diverso' >&2; exit 2; }
fi
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT
files=(scripts/platform-restart.py ops/vps/systemd/ouf-platform-start.service
       tools/platform_restart/{__init__,controller,docker,install,profile}.py)
for file in "${files[@]}"; do
  mkdir -p -- "$stage/$(dirname -- "$file")"
  GIT_ALLOW_PROTOCOL='' GIT_NO_LAZY_FETCH=1 git --no-replace-objects -C "$repo" cat-file blob "$C:$file" > "$stage/$file"
  expected=$(sha256sum < "$stage/$file")
  delivered=$(sha256sum < "$repo/$file")
  [[ $delivered == "$expected" ]] || { echo 'Hash della consegna diverso' >&2; exit 1; }
done
env -i LC_ALL=C PATH="$(getconf PATH)" "$OUF_PYTHON" -I -B "$stage/tools/platform_restart/install.py" "$C" "$@"
