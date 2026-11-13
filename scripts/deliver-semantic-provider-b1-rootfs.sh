#!/usr/bin/env bash
set -euo pipefail
umask 077

# Claude fills both pins after review/commit. Refuse an unpinned launcher.
commit='__PIN_COMMIT__'
controller_sha='__PIN_CONTROLLER_SHA256__'
[[ "$commit" =~ ^[0-9a-f]{40}$ && "$controller_sha" =~ ^[0-9a-f]{64}$ ]]
python_sha='889c603f0d17cb54060951bcf4c4f9b8c9ebd9e52b392c70209bbb9755d797d9'
printf '%s  %s\n' "$python_sha" /usr/bin/python3.13 | sudo sha256sum --check --status

# Root owns the download directory and all code. No user-writable source is
# ever imported by the isolated root interpreter. Retain delivery on failure.
work=$(sudo mktemp -d /var/tmp/ouf-semantic-b1-rootfs.XXXXXXXX)
sudo chmod 0700 "$work"
trap 'printf "OUF_B1_ROOTFS_DELIVERY=%s\n" "$work"' EXIT
base="https://raw.githubusercontent.com/GioNob/ouf-deploy/$commit"

fetch() {
  local relative=$1 expected=$2 name=${1##*/}
  sudo curl --fail --silent --show-error --max-time 30 --proto '=https' --tlsv1.2 \
    "$base/$relative" -o "$work/$name"
  sudo chmod 0600 "$work/$name"
  printf '%s  %s\n' "$expected" "$work/$name" | sudo sha256sum --check --status
}

fetch scripts/prepare-semantic-provider-b1-rootfs.py "$controller_sha"
fetch tools/semantic_image_rootfs/prepare_provider_image_rootfs.py cc2e238c37650f9fa77a2b3319160ef09aa61e1a5bd673e624ad5a9f0106eb32
fetch tools/semantic_stopped_rootfs/stopped_rootfs_comparison.py fbdf94a8946a2de0504055586a00e25cf6cad0dacd9fa214cc405e49e276e3e5
fetch tools/semantic_stopped_rootfs/rootfs_difference_report.py cb7b14165da33fcec227f5c9394cb5e640980b4c9be97a6289b9bbc801de8115
fetch tools/semantic_stopped_rootfs/rootfs_image_equivalence.py 5c4fcb28a979ca2d83bcf0bdbbb7d03599170875e30b56de63874891cb79e028

printf '%s  %s\n' "$python_sha" /usr/bin/python3.13 | sudo sha256sum --check --status
sudo /usr/bin/python3.13 -I -B "$work/prepare-semantic-provider-b1-rootfs.py" "$@"
