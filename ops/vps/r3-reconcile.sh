#!/usr/bin/env bash
# R-012, riconciliazione umana delle epoche FAILED preparate sotto una testa superata.
# Uso: sudo bash r3-reconcile.sh plan
#      sudo bash r3-reconcile.sh apply <planSha256>
set -euo pipefail
umask 077

case "${1:-}" in
  plan) [[ $# == 1 ]] || exit 2 ;;
  apply) [[ $# == 2 && $2 =~ ^[0-9a-f]{64}$ ]] || exit 2 ;;
  *) echo 'uso: plan | apply <planSha256>' >&2; exit 2 ;;
esac

# Fissare al commit della consegna dopo review.
C=ae21c25e6cb2da7315853632de9269e13b34cca0
[[ $C =~ ^[0-9a-f]{40}$ && $C != 0000000000000000000000000000000000000000 ]] || {
  echo 'runbook non ancora fissato a un commit' >&2; exit 2;
}
[[ $EUID == 0 && $(/usr/bin/id -g) == 0 ]] || { echo 'eseguire tramite sudo' >&2; exit 2; }
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
PY=/usr/bin/python3.13
P=889c603f0d17cb54060951bcf4c4f9b8c9ebd9e52b392c70209bbb9755d797d9
S=/etc/ouf/deploy-snapshots
for parent in / /etc /etc/ouf "$S"; do
  [[ -d $parent && ! -L $parent && $(stat -c %u:%g "$parent") == 0:0 ]] || exit 2
  mode=$(stat -c %a "$parent")
  (( (8#$mode & 0022) == 0 )) || exit 2
done
[[ -f $PY && ! -L $PY && $(stat -c %u:%g:%h "$PY") == 0:0:1 ]] || exit 2
mode=$(stat -c %a "$PY")
(( (8#$mode & 0022) == 0 )) || exit 2
printf '%s  %s\n' "$P" "$PY" | sha256sum --check --status

D=$(mktemp -d "$S/semantic-provider-r3-reconcile-source.XXXXXXXX")
trap 'rm -rf -- "$D"' EXIT
fetch() {
  local path=$1 expected=$2
  mkdir -p "$D/$(dirname "$path")"
  curl -q --fail --silent --show-error --max-time 30 --proto '=https' --tlsv1.2 \
    "https://raw.githubusercontent.com/GioNob/ouf-deploy/$C/$path" -o "$D/$path"
  chmod 0600 "$D/$path"
  printf '%s  %s\n' "$expected" "$D/$path" | sha256sum --check --status
}
delivery() {
  # BEGIN DELIVERY
  fetch ops/vps/r3-settings.json 4b1aa5560a23657b92fe0a99915d747d02d272a0b765c5b719921f4007d5c150
  fetch scripts/reconcile-semantic-provider-r3-epoch.py 1d8ef04aea288f3ecd3318db72a731eecbb8af779174cc396e423628e172b03d
  fetch scripts/semantic-provider-deployment-broker-v2.py 6e97807d5fa010ec7bc670a49533a031dc8f1d5e2472d8569368adfdc15b2d7c
  fetch tools/semantic_authority_mandates/mandates.py 86e70b8cc043c6b5b44b186601d098e71c46130039fe9d35d3c1529adfc09a79
  fetch tools/semantic_lease_kernel_migration/__init__.py f28e340dc4cbae36c07010190190d5a8479e5fef730965ba1c2b33dd36ad2496
  fetch tools/semantic_lease_kernel_migration/boot_dispatcher.py 6524076bbfeb54546df2ccb2e5b1d3ac051b919c8f75200b70dde1d958a9aa9b
  fetch tools/semantic_provider_operation/__init__.py e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  fetch tools/semantic_provider_operation/authorization.py 8f5dd2fd86efb7add1bdb5325b6428db41cc539b7b00a3b33efa4d692ab958fc
  fetch tools/semantic_provider_operation/epochs.py b5188406c935079b35f2a81ba670df9578d6ef97a5d7308cbb9cf502a72635bb
  fetch tools/semantic_provider_r3/__init__.py 44f7a91396fbd53e601cc981747063d61ac3c8733fd69595808694d9250a61e6
  fetch tools/semantic_provider_r3/driver_denial_overlay_v16.py cc2393eb2bea4b299cd8b0a8cdecb7b6e67b8c83f7e8d3d15bd09d915e3b2009
  fetch tools/semantic_provider_r3/reconcile_prepared_epoch.py 128132309a7432764816d98454239a1ce97828bcc5a98567fae0e178fa16512d
  fetch tools/semantic_runtime_v52/semantic_provider_docker_runtime_v52.py 117c9c86bb173742e4da7051d18bdef68526d3a8172cf231c41a27d2ea815911
  # END DELIVERY
}
delivery
"$PY" -I -B "$D/scripts/reconcile-semantic-provider-r3-epoch.py" "$@"
