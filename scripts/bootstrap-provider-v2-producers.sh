#!/bin/bash
set -euo pipefail
umask 077
test "$(id -un)" = oufadmin
oufGh=/home/oufadmin/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh
oufWork="$(mktemp -d)"
"$oufGh" api 'repos/GioNob/ouf-deploy/contents/releases/provider-v2-producer-sources.sha256?ref=c050612d45c2d14f7275719f06beeaeb97bfc911' --jq '.content' | base64 -d > "$oufWork/sources.sha256"
printf '%s  %s\n' c1c15a0d92ec7dc953f9f100b19f8426341b0c4ba9f2374d99c8473330eb9ffe "$oufWork/sources.sha256" | sha256sum -c -
python3 - "$oufWork/sources.sha256" <<'PY'
from pathlib import Path
import re,sys
rows=Path(sys.argv[1]).read_text().splitlines()
assert len(rows)==26 and len(set(rows))==26
assert all(re.fullmatch('[0-9a-f]{64}  (scripts|tools)/[a-z_]+[.]py',x) for x in rows)
PY
mkdir -p "$oufWork/source/scripts" "$oufWork/source/tools"
while read -r oufSha oufPath; do
    "$oufGh" api "repos/GioNob/ouf-api-gateway/contents/$oufPath?ref=ace683b1019f79adaace86796b67e463b93ec12e" --jq '.content' | base64 -d > "$oufWork/source/$oufPath"
    printf '%s  %s\n' "$oufSha" "$oufWork/source/$oufPath" | sha256sum -c -
done < "$oufWork/sources.sha256"
"$oufGh" api 'repos/GioNob/ouf-semantic-registry/contents/tools/semantic_creation_frame_observer.py?ref=3505a2f6bfde9c3905b76a5e670ebc30b40d3d6d' --jq '.content' | base64 -d > "$oufWork/frame-observer.py"
printf '%s  %s\n' d15d290e903e16f64b9d153658453f2b857c5241eb30ded961fd981a3ba436e4 "$oufWork/frame-observer.py" | sha256sum -c -
sudo -v
oufPackage="$(sudo mktemp -d /etc/ouf/deploy-snapshots/semantic-provider-v2-producers-XXXXXXXX)"
trap 'printf "OUF_PRODUCERS_SNAPSHOT=%s\n" "$oufPackage"' EXIT
sudo install -d -m 700 "$oufPackage/source" "$oufPackage/source/scripts" "$oufPackage/source/tools"
sudo install -m 600 "$oufWork/sources.sha256" "$oufPackage/sources.sha256"
while read -r oufSha oufPath; do
    sudo install -m 600 "$oufWork/source/$oufPath" "$oufPackage/source/$oufPath"
done < "$oufWork/sources.sha256"
sudo install -m 600 "$oufWork/frame-observer.py" "$oufPackage/frame-observer.py"
printf '%s  %s\n' c1c15a0d92ec7dc953f9f100b19f8426341b0c4ba9f2374d99c8473330eb9ffe "$oufPackage/sources.sha256" d15d290e903e16f64b9d153658453f2b857c5241eb30ded961fd981a3ba436e4 "$oufPackage/frame-observer.py" | sudo sha256sum -c -
sudo /usr/bin/python3.13 -I -B "$oufPackage/source/scripts/stage_semantic_local_producers_package.py" --mode apply --package-root "$oufPackage" --source-commit ace683b1019f79adaace86796b67e463b93ec12e --source-manifest-sha256 c1c15a0d92ec7dc953f9f100b19f8426341b0c4ba9f2374d99c8473330eb9ffe
sudo /usr/bin/python3.13 -I -B "$oufPackage/source/scripts/stage_semantic_local_producers_package.py" --mode verify --package-root "$oufPackage" --source-commit ace683b1019f79adaace86796b67e463b93ec12e --source-manifest-sha256 c1c15a0d92ec7dc953f9f100b19f8426341b0c4ba9f2374d99c8473330eb9ffe
