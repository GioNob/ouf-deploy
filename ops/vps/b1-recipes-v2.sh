#!/usr/bin/env bash
# Runbook D-027: ricette B1 v2 con il bundle parent reale del VPS.
# Uso:  bash b1-recipes-v2.sh plan
#       bash b1-recipes-v2.sh apply <planSha256>
# Valori pubblici; la chiave HMAC viene solo hashata dal controller (D-021).
set -euo pipefail
umask 077

mode=$(printf %s "${1:-}" | tr -d "[:space:]")
hash=$(printf %s "${2:-}" | tr -d "[:space:]")
case "$mode" in
  plan) extra=(--plan) ;;
  apply)
    [[ "$hash" =~ ^[0-9a-f]{64}$ ]] || { echo "uso: apply <planSha256> (ricevuti ${#hash} caratteri)" >&2; exit 2; }
    extra=(--apply --plan-sha256 "$hash") ;;
  *) echo 'uso: plan | apply <planSha256>' >&2; exit 2 ;;
esac

C=f4549b501f0ccdf931cc80f678c12e39851af0a8
L=85b615230fa2adda0219fab34320ac41a08f190f332dbb7894141a1878a05367
S=/etc/ouf/deploy-snapshots
ST=/var/lib/ouf-storage-migration

work=$(mktemp -d)
curl --fail --silent --show-error --proto '=https' --tlsv1.2 -o "$work/deliver.sh" \
  "https://raw.githubusercontent.com/GioNob/ouf-deploy/$C/scripts/deliver-semantic-provider-b1-recipes.sh"
printf '%s  %s\n' "$L" "$work/deliver.sh" | sha256sum --check

args=(
  --a2-root "$ST/semantic-provider-preparation-a2-20261113"
  --a2-plan-sha256 a435f29bd107fbb61d4f5d3ca594e42d2851a82beadeafb1aef13bcbe997cad2
  --a2-successors-sha256 394562b4162e8d1b615a6b61897446c8316b37e7a438fa99b389dbb5f119dfdb
  --recreation-receipt "$S/southbound-recreate-20261113-d022-v1/result.json"
  --recreation-receipt-sha256 56528cb24df9ce1d48f18ee67ac8105d308db8ee1602dd604a9573b08b22b79c
  --historical-adapter-id f3d59af93fc90162681cee3a7562bdff3bf2af8c05cbdb7e270d1508fff18f67
  --historical-southbound-id 1fc5ae6a0db4600e0124bb1f9d2998780d533fd2b4de7cb086d8675b6afb5916
  --adapter-id 85b5302f6dbc3e9a24ace904b8d8a2d43bc5185e340c1bfe5474c723a6b640ef
  --southbound-id 622a150067244ae8dbb4ac0f1889bc9e4b9823ed761820495f5c0849738dbc0d
  --adapter-transaction 7ff12b95c3f70c5eaebb1d0a12ab931d
  --southbound-transaction 864a28dbbd5ccc402f9406e500359123
  --expected-runtime ouf-semantic-admitted-v2
  --docker-socket /var/run/docker.sock
  --bundle-parent /run/containerd/io.containerd.runtime.v2.task/moby
  --metadata-parent /var/lib/docker/containers
  --network-namespace-parent /run/docker/netns
  --cgroup-driver systemd
  --storage-parent /var/lib/docker
  --rootfs-parent /var/lib/docker/rootfs/overlayfs
  --output-root "$S"
  --output-name semantic-provider-b1-recipes-20261114-v2
)
bash "$work/deliver.sh" "${extra[@]}" "${args[@]}"
