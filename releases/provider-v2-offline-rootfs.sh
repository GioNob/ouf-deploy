#!/bin/bash
set -euo pipefail
umask 077
test "$(id -un)" = oufadmin
test "$(uname -s)" = Linux
test "$(uname -m)" = x86_64
oufGh=/home/oufadmin/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh
oufWork="$(mktemp -d)"
oufSourceCommit=ff1a50205c147295517fb7a4c5259d1d17298129
oufToolCommit=e5bead716d02527e937be83e1cb22cad74affcbb
oufManifestHash=fb797f12eb838bfdc5eae7cd28617f6d7d17531968d710735df248354496e250
oufUmociHash=b21ac9b656fa76035db6ac4793facfd26982165d96f730bae9606d6f0929932e
oufInitHash=be8b8804a0d63990d02cc4b44008c22397778b4fecf16077397103fe8a64cb22
oufPrepareHash=cc2e238c37650f9fa77a2b3319160ef09aa61e1a5bd673e624ad5a9f0106eb32
mkdir -p "$oufWork/source/scripts" "$oufWork/source/tools" "$oufWork/artifact"
"$oufGh" run download 37770703203 --repo GioNob/ouf-deploy --name ouf-pinned-umoci --dir "$oufWork/artifact"
printf '%s  %s\n' "$oufUmociHash" "$oufWork/artifact/umoci" "$oufInitHash" "$oufWork/artifact/docker-initlayer" | sha256sum -c -
"$oufGh" api "repos/GioNob/ouf-deploy/contents/tools/semantic_cohort_admission/cohort-draft/sources.json?ref=$oufSourceCommit" --jq '.content' | base64 -d > "$oufWork/source/sources.json"
printf '%s  %s\n' "$oufManifestHash" "$oufWork/source/sources.json" | sha256sum -c -
python3 - "$oufWork/source/sources.json" > "$oufWork/source-list.sha256" <<'OUF_SOURCE_LIST'
import json,re,sys
from pathlib import Path
def unique(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise ValueError("DUPLICATE_MANIFEST_KEY")
        result[key]=value
    return result
manifest=json.loads(Path(sys.argv[1]).read_text(),object_pairs_hook=unique)
assert manifest['schema']=='ouf.semantic-cohort-source-draft.v1' and manifest['startAuthorized'] is False
rows=manifest['sourceHashes']
assert len(rows)==29
for path,value in sorted(rows.items()):
    assert re.fullmatch('(scripts|tools)/[a-z_]+[.]py',path) and re.fullmatch('[0-9a-f]{64}',value)
    print(value+'  '+path)
OUF_SOURCE_LIST
while read -r oufSha oufPath; do
    "$oufGh" api "repos/GioNob/ouf-deploy/contents/tools/semantic_cohort_admission/cohort-draft/$oufPath?ref=$oufSourceCommit" --jq '.content' | base64 -d > "$oufWork/source/$oufPath"
    printf '%s  %s\n' "$oufSha" "$oufWork/source/$oufPath" | sha256sum -c -
done < "$oufWork/source-list.sha256"
"$oufGh" api "repos/GioNob/ouf-deploy/contents/tools/semantic_image_rootfs/prepare_provider_image_rootfs.py?ref=$oufToolCommit" --jq '.content' | base64 -d > "$oufWork/prepare.py"
printf '%s  %s\n' "$oufPrepareHash" "$oufWork/prepare.py" | sha256sum -c -
sudo -v
printf '%s  %s\n' 889c603f0d17cb54060951bcf4c4f9b8c9ebd9e52b392c70209bbb9755d797d9 /usr/bin/python3.13 | sudo sha256sum -c -
oufRoot="$(sudo mktemp -d /etc/ouf/deploy-snapshots/semantic-provider-v2-offline-rootfs-XXXXXXXX)"
trap 'printf "OUF_OFFLINE_ROOTFS_SNAPSHOT=%s\n" "$oufRoot"' EXIT
sudo install -d -m 700 "$oufRoot/source" "$oufRoot/source/scripts" "$oufRoot/source/tools" "$oufRoot/adapter" "$oufRoot/southbound"
sudo install -m 600 "$oufWork/source/sources.json" "$oufRoot/source/sources.json"
while read -r oufSha oufPath; do
    sudo install -m 600 "$oufWork/source/$oufPath" "$oufRoot/source/$oufPath"
done < "$oufWork/source-list.sha256"
sudo install -m 600 "$oufWork/prepare.py" "$oufRoot/prepare.py"
sudo install -m 700 "$oufWork/artifact/umoci" "$oufRoot/umoci"
sudo install -m 700 "$oufWork/artifact/docker-initlayer" "$oufRoot/docker-initlayer"
printf '%s  %s\n' "$oufManifestHash" "$oufRoot/source/sources.json" "$oufPrepareHash" "$oufRoot/prepare.py" "$oufUmociHash" "$oufRoot/umoci" "$oufInitHash" "$oufRoot/docker-initlayer" | sudo sha256sum -c -
oufArchiveRoot=/etc/ouf/deploy-snapshots/semantic-provider-v2-stopped-create-a2kbzv6l/images
sudo /usr/bin/python3.13 -I -B "$oufRoot/prepare.py" --archive "$oufArchiveRoot/adapter.image.tar.gz" --archive-sha256 8301649b854a01d0306fabb14a5f93dd08eb4b1df98c2af356c0c84773821207 --manifest-digest sha256:277dcefd4744c244f4f6f23f8969f3d0acd64369e2ff1bd67594955c4ca7fbbc --config-digest sha256:62e066bd021f386291f5de21ce0e1f9e67904a74b4146326070c7784493ad320 --umoci "$oufRoot/umoci" --umoci-sha256 "$oufUmociHash" --source "$oufRoot/source" --source-manifest-sha256 "$oufManifestHash" --output "$oufRoot/adapter" --docker-init-tool "$oufRoot/docker-initlayer" --docker-init-sha256 "$oufInitHash" --engine-commit 464cd50c3d9e92877d56940ea160de6fca7bea23
sudo /usr/bin/python3.13 -I -B "$oufRoot/prepare.py" --archive "$oufArchiveRoot/southbound.image.tar.gz" --archive-sha256 1588c2391f9da45f300d16dd191cfe483dff83f81ed9424baec40201e64d7641 --manifest-digest sha256:c15541037a08276e36715a3c3798c2d07fe6faabf5547d3885a66cd10575e366 --config-digest sha256:d4c47bbeca75d94e2231e17ca14552885b7b339a5f33dbace411e275c79ded04 --umoci "$oufRoot/umoci" --umoci-sha256 "$oufUmociHash" --source "$oufRoot/source" --source-manifest-sha256 "$oufManifestHash" --output "$oufRoot/southbound" --docker-init-tool "$oufRoot/docker-initlayer" --docker-init-sha256 "$oufInitHash" --engine-commit 464cd50c3d9e92877d56940ea160de6fca7bea23
echo OUF_OFFLINE_EXPECTED_DOCKER_ROOTFS=PASS
echo CONTAINER_OPERATIONS=0
