#!/bin/bash
set -euo pipefail
umask 077
oufGh=/home/oufadmin/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh
oufCommit=892480e3313e1de6eaab479e569e847951985732
oufOld=/etc/ouf/deploy-snapshots/semantic-v2-rootfs-comparison-source-FGtPizDO
oufWork="$(mktemp -d)"
oufRoot=''
oufStage=DOWNLOAD_DIAGNOSTIC_SOURCE
trap 'oufExit=$?; if test "$oufExit" -ne 0; then printf "OUF_DIAGNOSIS_SCRIPT_ERROR STAGE=%s EXIT_CODE=%s\n" "$oufStage" "$oufExit"; fi; if test -n "$oufRoot"; then printf "OUF_ROOTFS_DIAGNOSIS_SOURCE=%s\n" "$oufRoot"; fi' EXIT
for oufName in rootfs_difference_report.py compare_provider_v2_stopped_rootfs.py; do
    "$oufGh" api "repos/GioNob/ouf-deploy/contents/tools/semantic_stopped_rootfs/$oufName?ref=$oufCommit" --jq '.content' | base64 -d > "$oufWork/$oufName"
done
"$oufGh" api 'repos/GioNob/ouf-deploy/contents/releases/provider-v2-rootfs-diagnostic-entrypoint-20261008.py?ref=7e96dd7c0df655c3776ac417dbcec7694cf203d8' --jq '.content' | base64 -d > "$oufWork/diagnose_provider_v2_stopped_rootfs.py"
oufStage=STAGE_ROOT_DIAGNOSIS
sudo -v
oufRoot="$(sudo mktemp -d /etc/ouf/deploy-snapshots/semantic-v2-rootfs-diagnosis-source-XXXXXXXX)"
for oufName in prepare_provider_image_rootfs.py stopped_rootfs_comparison.py; do
    sudo install -m 600 "$oufOld/$oufName" "$oufRoot/$oufName"
done
oufStage=DIAGNOSTIC_SOURCE_HASH
for oufName in rootfs_difference_report.py compare_provider_v2_stopped_rootfs.py diagnose_provider_v2_stopped_rootfs.py; do
    sudo install -m 600 "$oufWork/$oufName" "$oufRoot/$oufName"
done
printf '%s  %s\n' \
  cc2e238c37650f9fa77a2b3319160ef09aa61e1a5bd673e624ad5a9f0106eb32 "$oufRoot/prepare_provider_image_rootfs.py" \
  fbdf94a8946a2de0504055586a00e25cf6cad0dacd9fa214cc405e49e276e3e5 "$oufRoot/stopped_rootfs_comparison.py" \
  cb7b14165da33fcec227f5c9394cb5e640980b4c9be97a6289b9bbc801de8115 "$oufRoot/rootfs_difference_report.py" \
  48a3527ea46b9d99b11e78ee626ba91ffd297f63790d5555d72bbdb4c04fc6b4 "$oufRoot/compare_provider_v2_stopped_rootfs.py" \
  cc9a16c40e92e3d88109b981746c85fa31ffd12a22201c12818a811744b45a1c "$oufRoot/diagnose_provider_v2_stopped_rootfs.py" | sudo sha256sum -c -
oufStage=READ_ONLY_DIFFERENCE_DIAGNOSIS
sudo /usr/bin/python3.13 -I -B "$oufRoot/diagnose_provider_v2_stopped_rootfs.py"
