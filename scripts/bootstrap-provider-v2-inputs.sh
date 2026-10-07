#!/usr/bin/env bash
set -euo pipefail
umask 077
test "$(id -un)" = oufadmin
oufGh=/home/oufadmin/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh
test -x "$oufGh"
oufDownload="$(mktemp -d)"
oufSnapshot=''
trap 'if test -n "$oufSnapshot"; then printf "OUF_PROVIDER_V2_INPUTS_SNAPSHOT=%s\n" "$oufSnapshot"; fi' EXIT
oufRevision=4408d76fb8ba030d26d3bbab3d40335ad760a726
oufInstallerHash=de06ef9b78cc0c33d7fe0efbedd9019edcac5ad2b680695adf4d2dc224e491b1
oufManifestHash=81076c5c23e9dee3864a826e35266438ca1076d73b025a25df81638a97256d0b
"$oufGh" api "repos/GioNob/ouf-deploy/contents/scripts/prepare-provider-v2-inputs.py?ref=$oufRevision" --jq '.content' | base64 -d > "$oufDownload/prepare-provider-v2-inputs.py"
"$oufGh" api "repos/GioNob/ouf-deploy/contents/releases/provider-v2-runtime-sources.json?ref=$oufRevision" --jq '.content' | base64 -d > "$oufDownload/sources.json"
printf '%s  %s\n' "$oufInstallerHash" "$oufDownload/prepare-provider-v2-inputs.py" "$oufManifestHash" "$oufDownload/sources.json" | sha256sum -c -
python3 - "$oufDownload/sources.json" > "$oufDownload/source-list" <<'OUF_LIST'
import json,re,sys
v=json.load(open(sys.argv[1]))
assert v["schema"]=="ouf.semantic-provider-v2-runtime-sources.v1"
assert v["sourceCommit"]=="ace683b1019f79adaace86796b67e463b93ec12e"
assert len(v["sourceHashes"])==9
for path,sha in sorted(v["sourceHashes"].items()):
    assert re.fullmatch(r"tools/(?:[a-z_]+[.]py|lua/admit_semantic_provider[.]lua)",path)
    assert re.fullmatch(r"[0-9a-f]{64}",sha)
    print(sha,path)
OUF_LIST
while read -r oufHash oufPath; do
  mkdir -p "$oufDownload/source/$(dirname "$oufPath")"
  "$oufGh" api "repos/GioNob/ouf-api-gateway/contents/$oufPath?ref=ace683b1019f79adaace86796b67e463b93ec12e" --jq '.content' | base64 -d > "$oufDownload/source/$oufPath"
  printf '%s  %s\n' "$oufHash" "$oufDownload/source/$oufPath" | sha256sum -c -
done < "$oufDownload/source-list"
sudo -v
oufSnapshot="$(sudo mktemp -d /etc/ouf/deploy-snapshots/semantic-provider-v2-inputs-XXXXXXXX)"
sudo install -d -m 700 "$oufSnapshot/source" "$oufSnapshot/source/tools" "$oufSnapshot/source/tools/lua"
sudo install -m 600 "$oufDownload/prepare-provider-v2-inputs.py" "$oufSnapshot/prepare-provider-v2-inputs.py"
sudo install -m 600 "$oufDownload/sources.json" "$oufSnapshot/sources.json"
while read -r oufHash oufPath; do
  sudo install -m 600 "$oufDownload/source/$oufPath" "$oufSnapshot/source/$oufPath"
done < "$oufDownload/source-list"
printf '%s  %s\n' "$oufInstallerHash" "$oufSnapshot/prepare-provider-v2-inputs.py" "$oufManifestHash" "$oufSnapshot/sources.json" | sudo sha256sum -c -
sudo /usr/bin/python3 -I -B "$oufSnapshot/prepare-provider-v2-inputs.py" --package-root "$oufSnapshot" --prepare-private-startup-inputs-only
