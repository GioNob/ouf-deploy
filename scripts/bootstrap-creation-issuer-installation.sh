#!/usr/bin/env bash
set -euo pipefail
umask 077
test "$(id -un)" = oufadmin
oufGh=/home/oufadmin/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh
test -x "$oufGh"
oufDownload="$(mktemp -d)"
oufSnapshot=''
trap 'if test -n "$oufSnapshot"; then printf "OUF_CREATION_ISSUER_SNAPSHOT=%s\\n" "$oufSnapshot"; fi' EXIT
oufRevision=29b51e5d7a2c187dc1d8e088eb13e0b4e3404e61
oufManifestHash=2ad844d3426f8abe2bb59e8b020ff08bdac1d05de181da552a871bffd7f9cc69
oufInstallerHash=37a14176355aa7282678dbabbb10ac7c0d51c9c72dc175ac6ba3cfc9ee3e2c92
"$oufGh" api "repos/GioNob/ouf-deploy/contents/releases/creation-issuer-sources.json?ref=$oufRevision" --jq '.content' | base64 -d > "$oufDownload/sources.json"
"$oufGh" api "repos/GioNob/ouf-deploy/contents/scripts/install-creation-issuer.py?ref=$oufRevision" --jq '.content' | base64 -d > "$oufDownload/install-creation-issuer.py"
printf '%s  %s\n' "$oufManifestHash" "$oufDownload/sources.json" "$oufInstallerHash" "$oufDownload/install-creation-issuer.py" | sha256sum -c -
python3 - "$oufDownload/sources.json" > "$oufDownload/source-list" <<'OUF_LIST'
import json, re, sys
v=json.load(open(sys.argv[1]))
assert v["sourceCommit"]=="ace683b1019f79adaace86796b67e463b93ec12e"
assert len(v["sourceHashes"])==19
for path, sha in sorted(v["sourceHashes"].items()):
    assert re.fullmatch(r"(scripts|tools)/[a-z_]+[.]py",path)
    assert re.fullmatch(r"[0-9a-f]{64}",sha)
    print(sha,path)
OUF_LIST
while read -r oufHash oufPath; do
  mkdir -p "$oufDownload/source/$(dirname "$oufPath")"
  "$oufGh" api "repos/GioNob/ouf-api-gateway/contents/$oufPath?ref=ace683b1019f79adaace86796b67e463b93ec12e" --jq '.content' | base64 -d > "$oufDownload/source/$oufPath"
  printf '%s  %s\n' "$oufHash" "$oufDownload/source/$oufPath" | sha256sum -c -
done < "$oufDownload/source-list"
sudo -v
oufSnapshot="$(sudo mktemp -d /etc/ouf/deploy-snapshots/semantic-creation-issuer-install-XXXXXXXX)"
sudo install -d -m 700 "$oufSnapshot/source" "$oufSnapshot/source/scripts" "$oufSnapshot/source/tools"
sudo install -m 600 "$oufDownload/sources.json" "$oufSnapshot/sources.json"
sudo install -m 600 "$oufDownload/install-creation-issuer.py" "$oufSnapshot/install-creation-issuer.py"
while read -r oufHash oufPath; do
  sudo install -m 600 "$oufDownload/source/$oufPath" "$oufSnapshot/source/$oufPath"
done < "$oufDownload/source-list"
printf '%s  %s\n' "$oufInstallerHash" "$oufSnapshot/install-creation-issuer.py" | sudo sha256sum -c -
sudo /usr/bin/python3 -I -B "$oufSnapshot/install-creation-issuer.py" --package-root "$oufSnapshot" --manifest-sha256 "$oufManifestHash" --install-source-and-bind-existing-authority

