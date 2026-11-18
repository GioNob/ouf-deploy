#!/usr/bin/env bash
# D-052. Uso: project | plan | apply <planSha256> | restore [planSha256].
set -euo pipefail
umask 077

C=39adaab919b87c2efeab3798080b786b649ba5ef
[[ $C =~ ^[0-9a-f]{40}$ && $C != 0000000000000000000000000000000000000000 ]] \
  || { echo 'runbook non ancora fissato a un commit' >&2; exit 2; }
P=889c603f0d17cb54060951bcf4c4f9b8c9ebd9e52b392c70209bbb9755d797d9
S=/etc/ouf/deploy-snapshots
STATE=$HOME/.ouf-routes-d052-delivery
mode=${1:-}
hash=${2:-}
download=0
case "$mode" in
  project|plan) [[ $# == 1 ]]; download=1; args=("--$mode") ;;
  apply) [[ $# == 2 && $hash =~ ^[0-9a-f]{64}$ ]]; args=(--apply --plan-sha256 "$hash") ;;
  restore)
    args=(--restore)
    if [[ $# == 2 ]]; then
      [[ $hash =~ ^[0-9a-f]{64}$ ]]
      args+=(--plan-sha256 "$hash")
    else
      [[ $# == 1 ]]
    fi
    ;;
  *) echo 'uso: project | plan | apply <planSha256> | restore [planSha256]' >&2; exit 2 ;;
esac

printf '%s  %s\n' "$P" /usr/bin/python3.13 | sudo sha256sum --check --status
if [[ $download == 1 ]]; then
  D=$(sudo mktemp -d "$S/routes-d052-source.XXXXXXXX")
else
  read -r D < "$STATE"
  [[ $D == "$S"/routes-d052-source.* ]]
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
fetch scripts/publish-semantic-provider-routes.py 6dc194b6562b1ec588df93dbc768e00af3571bb681cd95406b08aa1b9f6d94e3
fetch tools/semantic_provider_routes/routes.py d0bfc3390207efa75db900760e9bfc121f4849019427e24f75cb5df2245006ba
fetch tools/semantic_provider_routes/custody.py 2ab7177f21fb5b330473895798c141282cdabc85c245142f96511fa13e848db3
fetch tools/semantic_provider_routes/publication.py eafd9bae591d1b3715dd0f79c5ca9904a1b761e57eb69989d6db7e3c2f9948ba
fetch ops/vps/r3-settings.json 4b1aa5560a23657b92fe0a99915d747d02d272a0b765c5b719921f4007d5c150
if [[ $download == 1 ]]; then
  printf '%s\n' "$D" > "$STATE"
fi
sudo /usr/bin/python3.13 -I -B "$D/scripts/publish-semantic-provider-routes.py" "${args[@]}"
