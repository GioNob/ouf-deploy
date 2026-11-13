#!/usr/bin/env bash
set -euo pipefail
umask 077

# D-001: fill only after review/commit. Each new file has a distinct pin.
commit='__PIN_COMMIT__'
controller_sha='__PIN_CONTROLLER_SHA256__'
launch_sha='__PIN_LAUNCH_SHA256__'
[[ "$commit" =~ ^[0-9a-f]{40}$ && "$controller_sha" =~ ^[0-9a-f]{64}$ && "$launch_sha" =~ ^[0-9a-f]{64}$ ]]
python_sha='889c603f0d17cb54060951bcf4c4f9b8c9ebd9e52b392c70209bbb9755d797d9'
printf '%s  %s\n' "$python_sha" /usr/bin/python3.13 | sudo sha256sum --check --status

# Every ancestor must satisfy the controller's root custody check.
work=$(sudo mktemp -d /etc/ouf/deploy-snapshots/semantic-b1-recipes-source.XXXXXXXX)
sudo chmod 0700 "$work"
trap 'printf "OUF_B1_RECIPES_DELIVERY=%s\n" "$work"' EXIT
sudo mkdir -m 0700 "$work/scripts" "$work/tools" \
  "$work/tools/semantic_frame_compiler" "$work/tools/semantic_successor_recipes"

fetch() {
  local path=$1 expected=$2
  sudo curl --fail --silent --show-error --max-time 30 --proto '=https' --tlsv1.2 \
    "https://raw.githubusercontent.com/GioNob/ouf-deploy/$commit/$path" -o "$work/$path"
  sudo chmod 0600 "$work/$path"
  printf '%s  %s\n' "$expected" "$work/$path" | sudo sha256sum --check --status
}

fetch scripts/prepare-semantic-provider-b1-recipes.py "$controller_sha"
fetch scripts/recreate-southbound-successor-20261113.py 13fe99b68e6e81af7976cf3b8a4c2e3b1d3ccfc0cb3896be0fd8665cf6390bcb
fetch tools/semantic_frame_compiler/compile_creation_frame_policy.py 36ee627e524415002a98fede8d7e61ad22ae95b6fec6b6686c1e01d878be570d
fetch tools/semantic_frame_compiler/build_role_frame_template.py 64f71f1c1414a87fda7e98a4402bef2b12ff8c5a917766810412825cca54f00c
fetch tools/semantic_frame_compiler/containerd-overlayfs-adapter.json 6dc554812c9298baffeb1ef7314eb2f43d7d4e5e41aea791f506a723f527b41e
fetch tools/semantic_successor_recipes/build_role_frame_template_tmpfs.py 63a04a56ac483b36e304db6694723dd5114372dc85011da5e1a5ae6b1aae3a15
fetch tools/semantic_successor_recipes/containerd-overlayfs-southbound-tmpfs.json 326d0b88276db8dde1729dfe0fabed9ca9d8ff9e8f6b87e6fcba7fa8f1741080
fetch tools/semantic_successor_recipes/creation_launch.py "$launch_sha"

printf '%s  %s\n' "$python_sha" /usr/bin/python3.13 | sudo sha256sum --check --status
sudo /usr/bin/python3.13 -I -B "$work/scripts/prepare-semantic-provider-b1-recipes.py" "$@"
