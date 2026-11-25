#!/usr/bin/env bash
# Use a root-custodied checkout. The read-only plan needs no staging directory.
set -euo pipefail
umask 077
C=0000000000000000000000000000000000000000
[[ $C =~ ^[0-9a-f]{40}$ && $C != 0000000000000000000000000000000000000000 ]] ||
  { echo 'Pin della consegna mancante' >&2; exit 2; }
[[ $EUID == 0 && ${OUF_PYTHON:?absolute Python 3.13 executable} == /* ]]
profile=${OUF_CAPTURE_PROFILE:?absolute private capture profile}
case "${1:-}" in
  plan) [[ $# == 1 ]]; args=(plan "$profile");;
  --measure) [[ $# == 1 ]]; args=(plan "$profile" --measure);;
  apply) [[ $# == 2 && $2 =~ ^[0-9a-f]{64}$ ]]; args=(apply "$profile" --plan-sha256 "$2");;
  *) exit 2;;
esac
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
files=(scripts/capture.py tools/capture/{__init__,contract,host,plan,apply,verify}.py
       tools/platform_restart/{__init__,profile}.py tools/privileged_executor/host-register.json
       contracts/{capture-profile,configuration-register}-v1.schema.json)
for file in "${files[@]}"; do
  GIT_ALLOW_PROTOCOL='' GIT_NO_LAZY_FETCH=1 git --no-replace-objects -C "$repo" \
    cat-file blob "$C:$file" | cmp -s - "$repo/$file" || { echo 'Blob diverso' >&2; exit 2; }
done
exec env -i PATH="$(getconf PATH)" LC_ALL=C OUF_CAPTURE_COMMIT="$C" \
  "$OUF_PYTHON" -I -B -X pycache_prefix=/dev/null "$repo/scripts/capture.py" "${args[@]}"
