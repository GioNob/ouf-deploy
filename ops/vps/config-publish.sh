#!/usr/bin/env bash
set -euo pipefail
umask 077

C=0000000000000000000000000000000000000000
[[ $C =~ ^[0-9a-f]{40}$ && $C != 0000000000000000000000000000000000000000 ]] \
  || { echo 'runbook non ancora fissato a un commit' >&2; exit 2; }
P=889c603f0d17cb54060951bcf4c4f9b8c9ebd9e52b392c70209bbb9755d797d9
S=/etc/ouf/deploy-snapshots

# Uso: plan|apply|restore adapter.json [pin]; profile plan|apply|restore [pin e prefissi].
operation=publish
if [[ ${1:-} == profile ]]; then
  operation=profile
  shift
fi
mode=${1:-}
case "$mode" in
  plan|apply|restore) shift ;;
  *) echo 'uso: [profile] plan|apply|restore [argomenti]' >&2; exit 2 ;;
esac
STATE=$HOME/.ouf-config-publish-$operation-delivery
printf '%s  %s\n' "$P" /usr/bin/python3.13 | sudo sha256sum --check --status
if [[ $mode == plan ]]; then
  D=$(sudo mktemp -d "$S/config-publish-source.XXXXXXXX")
else
  read -r D < "$STATE"
  [[ $D == "$S"/config-publish-source.* ]]
fi

fetch() {
  local path=$1 expected=$2
  if [[ $mode == plan ]]; then
    sudo mkdir -p -m 0700 "$D/$(dirname "$path")"
    sudo curl --fail --silent --show-error --max-time 30 --proto '=https' --tlsv1.2 \
      "https://raw.githubusercontent.com/GioNob/ouf-deploy/$C/$path" -o "$D/$path"
    sudo chmod 0600 "$D/$path"
  fi
  printf '%s  %s\n' "$expected" "$D/$path" | sudo sha256sum --check --status
}
fetch scripts/prepare-semantic-provider-installation.py 87b7117c4a3c8a6375b57b5877050c96a63475419ad3dfbc2dc8e674cd0e9076
fetch scripts/semantic-provider-config.py adf43ebaadc65d27e13629c4ed07e35e013ce6427af606c7f2de38bf2c5e228c
fetch tools/semantic_provider_config/contract.py 056a97bd7d9f4e506c9200f232fa95a44b766ee7fa628444bb3816018b676e15
fetch tools/semantic_provider_config/observation.py 62d7db7c72ca0c21906a5f8d44470245f533e18604d41519ee891e7bd31bd681
fetch tools/semantic_provider_config/publication.py dd982c8417ce2b754a7203c64f780ba92ade51c96f4817b8127d62a918c084e2
fetch tools/semantic_provider_config/b1_v4.py 47bef0c41a407b6b35e2e4267e9897d923db48c1e68dbd9232d3589b1f88d1bc
fetch tools/semantic_provider_routes/routes.py 305f2535e2cc547de5f242080247d62a43b4bdb93303bf00a03bb36e87097997
fetch tools/semantic_provider_routes/custody.py 2ab7177f21fb5b330473895798c141282cdabc85c245142f96511fa13e848db3
fetch tools/semantic_provider_routes/publication.py eafd9bae591d1b3715dd0f79c5ca9904a1b761e57eb69989d6db7e3c2f9948ba
fetch tools/semantic_provider_routes/b1.py 47ce397f61065ad1e9cf73e09f3a5de181a727c58b425ae5b6ad0039ccfba0d9
fetch ops/vps/r3-settings.json 4b1aa5560a23657b92fe0a99915d747d02d272a0b765c5b719921f4007d5c150
fetch tools/semantic_frame_compiler/compile_creation_frame_policy.py 36ee627e524415002a98fede8d7e61ad22ae95b6fec6b6686c1e01d878be570d
fetch tools/semantic_image_rootfs/prepare_provider_image_rootfs.py cc2e238c37650f9fa77a2b3319160ef09aa61e1a5bd673e624ad5a9f0106eb32
fetch tools/semantic_stopped_rootfs/stopped_rootfs_comparison.py fbdf94a8946a2de0504055586a00e25cf6cad0dacd9fa214cc405e49e276e3e5
if [[ $mode == plan ]]; then
  printf '%s\n' "$D" > "$STATE"
fi
if [[ $operation == profile ]]; then
  sudo /usr/bin/python3.13 -I -B "$D/scripts/prepare-semantic-provider-installation.py" "--$mode" --namespace-revision "$@"
else
  sudo /usr/bin/python3.13 -I -B "$D/scripts/semantic-provider-config.py" publish "$mode" "$@"
fi
