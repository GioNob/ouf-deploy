#!/bin/bash
set -euo pipefail
umask 077
oufGh=/home/oufadmin/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh
oufCommit=f0b73a3a24205a4a0efa4da304682d211ac91c07
oufOld=/etc/ouf/deploy-snapshots/semantic-v2-rootfs-diagnosis-source-dpgshILU
oufWork="$(mktemp -d)"
oufRoot=''
oufStage=FETCH_COMPARISON_CODE
trap 'oufExit=$?; if test "$oufExit" -ne 0; then printf "OUF_IMAGE_COMPARISON_ERROR STAGE=%s EXIT_CODE=%s\n" "$oufStage" "$oufExit"; fi; if test -n "$oufRoot"; then printf "OUF_IMAGE_COMPARISON_SOURCE=%s\n" "$oufRoot"; fi' EXIT
for oufName in rootfs_image_equivalence.py compare_provider_v2_stopped_rootfs.py compare_image_equivalence.py; do
    "$oufGh" api "repos/GioNob/ouf-deploy/contents/tools/semantic_stopped_rootfs/$oufName?ref=$oufCommit" --jq '.content' | base64 -d > "$oufWork/$oufName"
done
oufStage=STAGE_COMPARISON
sudo -v
oufRoot="$(sudo mktemp -d /etc/ouf/deploy-snapshots/semantic-v2-image-equivalence-source-XXXXXXXX)"
for oufName in prepare_provider_image_rootfs.py stopped_rootfs_comparison.py rootfs_difference_report.py; do
    sudo install -m 600 "$oufOld/$oufName" "$oufRoot/$oufName"
done
for oufName in rootfs_image_equivalence.py compare_provider_v2_stopped_rootfs.py compare_image_equivalence.py; do
    sudo install -m 600 "$oufWork/$oufName" "$oufRoot/$oufName"
done
oufStage=CHECK_EXECUTABLE_CODE
printf '%s  %s\n' \
  cc2e238c37650f9fa77a2b3319160ef09aa61e1a5bd673e624ad5a9f0106eb32 "$oufRoot/prepare_provider_image_rootfs.py" \
  fbdf94a8946a2de0504055586a00e25cf6cad0dacd9fa214cc405e49e276e3e5 "$oufRoot/stopped_rootfs_comparison.py" \
  cb7b14165da33fcec227f5c9394cb5e640980b4c9be97a6289b9bbc801de8115 "$oufRoot/rootfs_difference_report.py" \
  5c4fcb28a979ca2d83bcf0bdbbb7d03599170875e30b56de63874891cb79e028 "$oufRoot/rootfs_image_equivalence.py" \
  85d8007cda5913fb75763e63630515dac8c80d2507904a40ce8e807f48603b0c "$oufRoot/compare_provider_v2_stopped_rootfs.py" \
  3b730d77ff4f479c7c77da042786a22e86514f393ac34f2b8b9b030c08f4450f "$oufRoot/compare_image_equivalence.py" | sudo sha256sum -c -
oufStage=COMPARE_AND_DIAGNOSE
sudo /usr/bin/python3.13 -I -B "$oufRoot/compare_image_equivalence.py"
