#!/bin/bash
set -euo pipefail
umask 077
test "$(id -un)" = oufadmin
oufGh=/home/oufadmin/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh
oufRef=6b74365821a668479eac10c2364b29d5cbab5eff
oufWork="$(mktemp -d)"
oufSnapshot=''
trap 'if test -n "$oufSnapshot"; then printf "OUF_RUNTIME_REGISTRATION_SNAPSHOT=%s\n" "$oufSnapshot"; fi' EXIT
"$oufGh" api "repos/GioNob/ouf-deploy/contents/scripts/register-provider-v2-runtime.py?ref=$oufRef" --jq '.content' | base64 -d > "$oufWork/register-provider-v2-runtime.py"
"$oufGh" api "repos/GioNob/ouf-deploy/contents/releases/provider-v2-runtime-registration-sources.json?ref=$oufRef" --jq '.content' | base64 -d > "$oufWork/sources.json"
printf '%s  %s\n' '2ee5d624ec653e9cdaf1f1d4c4774735e5d151e0f5a3e41587d766d0be998924' "$oufWork/register-provider-v2-runtime.py" '6e0894c95eafcc1b50d2dc15e38918a3912297a063f6800f2da3dd6c69ffa8da' "$oufWork/sources.json" | sha256sum -c -
python3 - "$oufWork/sources.json" > "$oufWork/paths" <<'PY'
import json,re,sys
m=json.load(open(sys.argv[1]))
assert set(m)=={'sourceCommit','sourceHashes'} and m['sourceCommit']=='ace683b1019f79adaace86796b67e463b93ec12e' and len(m['sourceHashes'])==19
for p,h in sorted(m['sourceHashes'].items()):
    assert re.fullmatch(r'(scripts|tools)/[a-z_]+\.py',p) and re.fullmatch('[0-9a-f]{64}',h)
    print(h,p)
PY
mkdir -p "$oufWork/source/scripts" "$oufWork/source/tools"
while read -r oufSha oufPath; do
    "$oufGh" api "repos/GioNob/ouf-api-gateway/contents/$oufPath?ref=ace683b1019f79adaace86796b67e463b93ec12e" --jq '.content' | base64 -d > "$oufWork/source/$oufPath"
    printf '%s  %s\n' "$oufSha" "$oufWork/source/$oufPath" | sha256sum -c -
done < "$oufWork/paths"
sudo -v
oufSnapshot="$(sudo mktemp -d /etc/ouf/deploy-snapshots/semantic-v2-runtime-registration-XXXXXXXX)"
sudo install -d -m 700 "$oufSnapshot/source/scripts" "$oufSnapshot/source/tools"
sudo install -m 600 "$oufWork/register-provider-v2-runtime.py" "$oufSnapshot/register-provider-v2-runtime.py"
sudo install -m 600 "$oufWork/sources.json" "$oufSnapshot/sources.json"
while read -r oufSha oufPath; do
    sudo install -m 600 "$oufWork/source/$oufPath" "$oufSnapshot/source/$oufPath"
done < "$oufWork/paths"
printf '%s  %s\n' '2ee5d624ec653e9cdaf1f1d4c4774735e5d151e0f5a3e41587d766d0be998924' "$oufSnapshot/register-provider-v2-runtime.py" '6e0894c95eafcc1b50d2dc15e38918a3912297a063f6800f2da3dd6c69ffa8da' "$oufSnapshot/sources.json" | sudo sha256sum -c -
sudo /usr/bin/python3.13 -I -B "$oufSnapshot/register-provider-v2-runtime.py" --package-root "$oufSnapshot" --manifest-sha256 6e0894c95eafcc1b50d2dc15e38918a3912297a063f6800f2da3dd6c69ffa8da
