#!/usr/bin/env bash
# D-052. Uso: plan <routesResultSha256> | apply <planSha256> <routesResultSha256>.
set -euo pipefail
umask 077

C=39adaab919b87c2efeab3798080b786b649ba5ef
[[ $C =~ ^[0-9a-f]{40}$ && $C != 0000000000000000000000000000000000000000 ]] \
  || { echo 'runbook non ancora fissato a un commit' >&2; exit 2; }
P=889c603f0d17cb54060951bcf4c4f9b8c9ebd9e52b392c70209bbb9755d797d9
S=/etc/ouf/deploy-snapshots
STATE=$HOME/.ouf-b1-recipes-v3-delivery
mode=${1:-}
hash=${2:-}
download=0
case "$mode" in
  plan) [[ $# == 2 ]]; download=1; args=(--plan); routes_receipt=$hash ;;
  apply)
    [[ $# == 3 && $hash =~ ^[0-9a-f]{64}$ ]]
    args=(--apply --plan-sha256 "$hash")
    routes_receipt=$3
    ;;
  *) echo 'uso: plan <routesResultSha256> | apply <planSha256> <routesResultSha256>' >&2; exit 2 ;;
esac
[[ $routes_receipt =~ ^[0-9a-f]{64}$ ]]
args+=(--routes-receipt-sha256 "$routes_receipt")

printf '%s  %s\n' "$P" /usr/bin/python3.13 | sudo sha256sum --check --status
if [[ $download == 1 ]]; then
  D=$(sudo mktemp -d "$S/b1-recipes-v3-source.XXXXXXXX")
else
  read -r D < "$STATE"
  [[ $D == "$S"/b1-recipes-v3-source.* ]]
fi

fetch() {
  local path=$1 expected=$2
  if [[ $download == 1 ]]; then
    sudo mkdir -p -m 0700 "$D/$(dirname "$path")"
    sudo curl --fail --silent --show-error --max-time 30 --proto '=https' --tlsv1.2 \
      "https://raw.githubusercontent.com/GioNob/ouf-deploy/$C/$path" -o "$D/$path"
    sudo chmod 0600 "$D/$path"
  fi
  printf '%s  %s\n' "$expected" "$D/$path" | sudo sha256sum --check --status
}
fetch scripts/prepare-semantic-provider-b1-recipes-v3.py 9b350e834431eae5960881f8690c7a7e8f7c108f9e4d454b108ad89be424297d
fetch tools/semantic_provider_routes/routes.py d0bfc3390207efa75db900760e9bfc121f4849019427e24f75cb5df2245006ba
fetch tools/semantic_provider_routes/custody.py 2ab7177f21fb5b330473895798c141282cdabc85c245142f96511fa13e848db3
fetch tools/semantic_provider_routes/publication.py eafd9bae591d1b3715dd0f79c5ca9904a1b761e57eb69989d6db7e3c2f9948ba
fetch ops/vps/r3-settings.json 4b1aa5560a23657b92fe0a99915d747d02d272a0b765c5b719921f4007d5c150
fetch tools/semantic_provider_routes/b1.py 55f1574ad9c0c50077a80a649556d4c75d8fe620898a4962592f374c47c974fc
fetch tools/semantic_frame_compiler/compile_creation_frame_policy.py 36ee627e524415002a98fede8d7e61ad22ae95b6fec6b6686c1e01d878be570d
fetch tools/semantic_image_rootfs/prepare_provider_image_rootfs.py cc2e238c37650f9fa77a2b3319160ef09aa61e1a5bd673e624ad5a9f0106eb32
fetch tools/semantic_stopped_rootfs/stopped_rootfs_comparison.py fbdf94a8946a2de0504055586a00e25cf6cad0dacd9fa214cc405e49e276e3e5
if [[ $download == 1 ]]; then
  printf '%s\n' "$D" > "$STATE"
fi
sudo /usr/bin/python3.13 -I -B "$D/scripts/prepare-semantic-provider-b1-recipes-v3.py" "${args[@]}"
