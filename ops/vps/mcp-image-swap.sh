#!/usr/bin/env bash
# R-033. Human-operated, commit-pinned delivery. See docs/OUF_MCP_IMAGE_SWAP.md.
set -euo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
C=0000000000000000000000000000000000000000
[[ $C =~ ^[0-9a-f]{40}$ && $C != 0000000000000000000000000000000000000000 ]] || {
  echo 'Fissare il commit di consegna dopo la review.' >&2; exit 2;
}
case ${1:-} in
  snapshot|apply|rollback) [[ $# == 2 && $2 =~ ^[0-9a-f]{64}$ ]] ;;
  plan) [[ $# == 1 ]] ;;
  *) echo 'uso: snapshot <postgresCid> | plan | apply <planSha256> | rollback <planSha256>' >&2; exit 2 ;;
esac
[[ $EUID == 0 && ${SUDO_UID:-0} =~ ^[1-9][0-9]*$ ]] || {
  echo 'Usare sudo da un account operatore ordinario.' >&2; exit 2;
}
state=/etc/ouf/deploy-snapshots/mcp-image-swap-r033
D=$state/delivery-$C
trusted() {
  local p=$1 mode
  [[ $(realpath -e -- "$p") == "$p" ]] || return 1
  while [[ $p != / ]]; do
    [[ $(stat -c %u "$p") == 0 ]] || return 1
    mode=$(stat -c %a "$p")
    (( (8#$mode & 0022) == 0 )) || return 1
    p=$(dirname "$p")
  done
}
trusted "$(dirname "$state")"
[[ -d $state ]] || mkdir -m 0700 -- "$state"
trusted "$state"
[[ $(stat -c %a "$state") == 700 ]]
# Serialize staging as well as execution. The controller also locks its own entry point.
exec 9>"$state/launcher.lock"
flock -n 9
verify() { printf '%s  %s\n' "$2" "$1" | sha256sum --check --status; }
download() {
  local url=$1 destination=$2 hash=$3 limit=$4
  if [[ ! -e $destination ]]; then
    [[ $1 == https://* && ( $mode == snapshot || $mode == plan ) ]] || return 1
    tmp=$(mktemp "$state/download.XXXXXXXX")
    # Root opens the private output. Only the unprivileged curl accesses the network.
    sudo -H -u "#$SUDO_UID" -- /usr/bin/curl -q --fail --silent --show-error --location \
      --proto '=https' --proto-redir '=https' --tlsv1.2 --connect-timeout 12 --max-time 180 \
      --max-filesize "$limit" "$url" > "$tmp"
    verify "$tmp" "$hash"
    mv -T -- "$tmp" "$destination"
    tmp=
  fi
  trusted "$destination"
  verify "$destination" "$hash"
}
fetch() {
  local path=$1 hash=$2
  download "https://raw.githubusercontent.com/GioNob/ouf-deploy/$C/$path" "$D/$path" "$hash" 1048576
}
mode=$1
tmp=
trap 'if [[ -n $tmp ]]; then rm -f -- "$tmp"; fi' EXIT
if [[ $mode == snapshot || $mode == plan ]]; then
  mkdir -p -- "$D/scripts" "$D/tools/acquisition_read_native"
fi
trusted "$D/scripts"
trusted "$D/tools/acquisition_read_native"
fetch scripts/swap-mcp-image.py dbc1df537d85ee1b24f8fd6003b563030edc3a9fc44372692c467e2306a4f4e0
fetch scripts/upgrade-mcp-analysis-20261108.py 5f6739852c1a0d4318d6427c229409882a0f66ab1ad7110ed3c599300fa24758
fetch scripts/upgrade-semantic-application-20261108.py 2e7e7e42367b3329f6ebd441bba665f974ea43871049d863415524610138efb1
fetch scripts/read-discovery-contract-20261108.py 468660ed73a24c7b8a842f5b99a9c268890c99bb4206ca2e4719865326b27277
fetch scripts/read-analysis-discovery-runtime-20261107.py ef8dc8c4887122f2b2d76c05eaff7a8850c31004fcd661de2b3e49f51d6cc1b4
fetch tools/acquisition_read_native/retained_mac.py cb5dbbee4a80ce71860dfe5d32362a662d98898c58fd82009e69c5eb6ac1f7ce
if [[ $mode == plan || $mode == apply ]]; then
  trusted "$state/inputs.json"
  selection=$(/usr/bin/python3 -I -B - "$state/inputs.json" <<'PY'
import json, re, sys
with open(sys.argv[1], 'rb') as f:
    c = json.load(f)['candidate']
if (c['sourceCommit'] != 'b4c1091bcbbb374d7d4a190f58a818e1d17deac7'
        or type(c['artifactId']) is not int or c['artifactId'] <= 0
        or not re.fullmatch('[a-f0-9]{64}', c['zipSha256'])):
    sys.exit('Selezione del candidato R-033 non valida.')
print(c['artifactId'], c['zipSha256'])
PY
)
  read -r artifact zip_sha <<< "$selection"
  download "https://nightly.link/GioNob/ouf-mcp-server/actions/artifacts/$artifact.zip" \
    "$state/candidate-$artifact.zip" "$zip_sha" 67108864
fi
export DOCKER_API_VERSION=1.44
exec /usr/bin/python3 -I -B "$D/scripts/swap-mcp-image.py" "$@"
