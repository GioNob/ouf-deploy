#!/bin/bash
set -euo pipefail
umask 077
test "$(id -un)" = oufadmin
oufGh=/home/oufadmin/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh
oufRef=900c2e0607e67788be44ed2d99af415838128387
oufSha=2a9fc3d2861faa2e15370c70979b171cb63b2e09a2dfef1e2895ca27fa663861
oufWork="$(mktemp -d)"
"$oufGh" api "repos/GioNob/ouf-deploy/contents/scripts/resume-provider-v2-stopped.py?ref=$oufRef" --jq '.content' | base64 -d > "$oufWork/resume.py"
printf '%s  %s\n' "$oufSha" "$oufWork/resume.py" | sha256sum -c -
sudo -v
oufPackage="$(sudo mktemp -d /etc/ouf/deploy-snapshots/semantic-v2-recovery-source-XXXXXXXX)"
printf 'OUF_RECOVERY_SOURCE_SNAPSHOT=%s\n' "$oufPackage"
sudo install -m 600 "$oufWork/resume.py" "$oufPackage/resume-provider-v2-stopped.py"
printf '%s  %s\n' "$oufSha" "$oufPackage/resume-provider-v2-stopped.py" | sudo sha256sum -c -
sudo /usr/bin/python3.13 -I -B "$oufPackage/resume-provider-v2-stopped.py" --resume-import-and-create-stopped-only
