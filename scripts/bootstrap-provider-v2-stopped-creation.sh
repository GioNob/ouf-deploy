#!/bin/bash
set -euo pipefail
umask 077
test "$(id -un)" = oufadmin
oufGh=/home/oufadmin/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh
oufRef=90840b2e8f14b08e8efd7150d929b49fc6568998
oufSha=998c43c244be4fe8aca229114580577a0800a9c7b230dc0eec89dd7d61661d05
oufWork="$(mktemp -d)"
"$oufGh" api "repos/GioNob/ouf-deploy/contents/scripts/create-provider-v2-stopped.py?ref=$oufRef" --jq '.content' | base64 -d > "$oufWork/create.py"
printf '%s  %s\n' "$oufSha" "$oufWork/create.py" | sha256sum -c -
sudo -v
oufPackage="$(sudo mktemp -d /etc/ouf/deploy-snapshots/semantic-v2-creation-source-XXXXXXXX)"
printf 'OUF_CREATION_SOURCE_SNAPSHOT=%s\n' "$oufPackage"
sudo install -m 600 "$oufWork/create.py" "$oufPackage/create-provider-v2-stopped.py"
printf '%s  %s\n' "$oufSha" "$oufPackage/create-provider-v2-stopped.py" | sudo sha256sum -c -
sudo /usr/bin/python3.13 -I -B "$oufPackage/create-provider-v2-stopped.py" --create-stopped-only
