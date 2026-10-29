#!/usr/bin/env bash
set -euo pipefail
umask 077
test "$(id -un)" = oufadmin
oufGh=/home/oufadmin/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh
test -x "$oufGh"
oufDownload="$(mktemp -d)"
oufSnapshot=''
trap 'if test -n "$oufSnapshot"; then printf "OUF_PROVIDER_V2_TRUST_SNAPSHOT=%s\n" "$oufSnapshot"; fi' EXIT
oufRevision=8474237d4b2ef7eefbb2ba9a0a0b524dcdbd241f
oufTrustHash=a724becfa3dbcb60052b9cb38a5479372747adb32bc54a7f6cb7b2eb4c3b1226
oufAccountHash=d3fe5e78d84e021c4a9afdade8ad01add681e1037d26238eb972e03fb9c472fb
"$oufGh" api "repos/GioNob/ouf-deploy/contents/scripts/prepare-provider-v2-trust.py?ref=$oufRevision" --jq '.content' | base64 -d > "$oufDownload/prepare-provider-v2-trust.py"
"$oufGh" api "repos/GioNob/ouf-deploy/contents/scripts/provider-role-accounts.py?ref=$oufRevision" --jq '.content' | base64 -d > "$oufDownload/provider-role-accounts.py"
printf '%s  %s\n' "$oufTrustHash" "$oufDownload/prepare-provider-v2-trust.py" "$oufAccountHash" "$oufDownload/provider-role-accounts.py" | sha256sum -c -
sudo -v
oufSnapshot="$(sudo mktemp -d /etc/ouf/deploy-snapshots/semantic-provider-v2-trust-XXXXXXXX)"
sudo install -m 600 "$oufDownload/prepare-provider-v2-trust.py" "$oufSnapshot/prepare-provider-v2-trust.py"
sudo install -m 600 "$oufDownload/provider-role-accounts.py" "$oufSnapshot/provider-role-accounts.py"
printf '%s  %s\n' "$oufTrustHash" "$oufSnapshot/prepare-provider-v2-trust.py" "$oufAccountHash" "$oufSnapshot/provider-role-accounts.py" | sudo sha256sum -c -
sudo /usr/bin/python3 -I -B "$oufSnapshot/prepare-provider-v2-trust.py" --package-root "$oufSnapshot" --prepare-private-trust-only
