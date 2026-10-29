#!/bin/bash
set -euo pipefail
umask 077
test "$(id -un)" = oufadmin
test "$(uname -s)" = Linux
test "$(uname -m)" = x86_64
oufGh=/home/oufadmin/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh
oufCommit=396e1bbfedb897403f442cf44fac3b72dff3cd6b
oufWork="$(mktemp -d)"
for oufName in stopped_rootfs_comparison.py compare_provider_v2_stopped_rootfs.py; do
    "$oufGh" api "repos/GioNob/ouf-deploy/contents/tools/semantic_stopped_rootfs/$oufName?ref=$oufCommit" --jq '.content' | base64 -d > "$oufWork/$oufName"
done
"$oufGh" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_image_rootfs/prepare_provider_image_rootfs.py?ref=e5bead716d02527e937be83e1cb22cad74affcbb' --jq '.content' | base64 -d > "$oufWork/prepare_provider_image_rootfs.py"
printf '%s  %s\n' \
  fbdf94a8946a2de0504055586a00e25cf6cad0dacd9fa214cc405e49e276e3e5 "$oufWork/stopped_rootfs_comparison.py" \
  19f508c31cbfe943cb7ef5ee118103df08e86232a8159cb763b573d9316635d0 "$oufWork/compare_provider_v2_stopped_rootfs.py" \
  cc2e238c37650f9fa77a2b3319160ef09aa61e1a5bd673e624ad5a9f0106eb32 "$oufWork/prepare_provider_image_rootfs.py" | sha256sum -c -
sudo -v
printf '%s  %s\n' 889c603f0d17cb54060951bcf4c4f9b8c9ebd9e52b392c70209bbb9755d797d9 /usr/bin/python3.13 | sudo sha256sum -c -
oufRoot="$(sudo mktemp -d /etc/ouf/deploy-snapshots/semantic-v2-rootfs-comparison-source-XXXXXXXX)"
trap 'printf "OUF_ROOTFS_COMPARISON_SOURCE=%s\n" "$oufRoot"' EXIT
for oufName in stopped_rootfs_comparison.py compare_provider_v2_stopped_rootfs.py prepare_provider_image_rootfs.py; do
    sudo install -m 600 "$oufWork/$oufName" "$oufRoot/$oufName"
done
printf '%s  %s\n' \
  fbdf94a8946a2de0504055586a00e25cf6cad0dacd9fa214cc405e49e276e3e5 "$oufRoot/stopped_rootfs_comparison.py" \
  19f508c31cbfe943cb7ef5ee118103df08e86232a8159cb763b573d9316635d0 "$oufRoot/compare_provider_v2_stopped_rootfs.py" \
  cc2e238c37650f9fa77a2b3319160ef09aa61e1a5bd673e624ad5a9f0106eb32 "$oufRoot/prepare_provider_image_rootfs.py" | sudo sha256sum -c -
sudo /usr/bin/python3.13 -I -B "$oufRoot/compare_provider_v2_stopped_rootfs.py"
