#!/bin/bash
# Bounded private launch inputs and matching source-sealed observer only.
set -euo pipefail
umask 077
oufDir="$(mktemp -d)"
trap 'rm -rf -- "$oufDir"' EXIT
oufGh='/home/oufadmin/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh'
for oufFile in prepare_provider_v2_launch_inputs.py frame-observer.py; do
  "$oufGh" api -H 'Accept: application/vnd.github.raw+json' \
    "repos/GioNob/ouf-deploy/contents/tools/semantic_frame_compiler/$oufFile?ref=6f9f5289c3bcff2a1ecd9e11ebe67d52216aa6d8" > "$oufDir/$oufFile"
done
oufPrepHash='0044f2e95873e236c25c3323c4bf54ac0748c87dd3468c12c58f2b22c81db1eb'
oufObserverHash='122a1a44705892ba577d2e83467f39870627ffc16685f886757828611063b3fc'
printf '%s  %s\n' "$oufPrepHash" "$oufDir/prepare_provider_v2_launch_inputs.py" "$oufObserverHash" "$oufDir/frame-observer.py" | sha256sum -c -
sudo /bin/sh -c '
  set -eu
  umask 077
  oufRoot="$(mktemp -d /etc/ouf/deploy-snapshots/semantic-v2-launch-source-XXXXXXXX)"
  for oufFile in prepare_provider_v2_launch_inputs.py frame-observer.py; do
    install -m 600 "$1/$oufFile" "$oufRoot/$oufFile"
  done
  printf "%s  %s\n" "$2" "$oufRoot/prepare_provider_v2_launch_inputs.py" "$3" "$oufRoot/frame-observer.py" | sha256sum -c -
  exec /usr/bin/python3.13 -I -B "$oufRoot/prepare_provider_v2_launch_inputs.py"
' sh "$oufDir" "$oufPrepHash" "$oufObserverHash"
