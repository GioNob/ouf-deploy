#!/usr/bin/env bash
# Runbook task-26: annullamento di B1 (ripristino del wrapper precedente).
# Uso:  bash b1-restore.sh plan              (sola lettura: prova che l'annullamento e' possibile)
#       bash b1-restore.sh apply <planSha256> (SOLO se si decide di annullare B1)
set -euo pipefail
umask 077

mode=${1:-}
case "$mode" in
  plan) extra=(--plan) ;;
  apply)
    [[ "${2:-}" =~ ^[0-9a-f]{64}$ ]] || { echo 'uso: apply <planSha256>' >&2; exit 2; }
    extra=(--apply --plan-sha256 "$2") ;;
  *) echo 'uso: plan | apply <planSha256>' >&2; exit 2 ;;
esac

C=d2883e424ae49c055970fce2d92c447afc77eb27
L=743870926522619ca03cd4a5b11a49df9fdfc2e84ba26f32d9f88debc0ae0daf
S=/etc/ouf/deploy-snapshots

work=$(mktemp -d)
curl --fail --silent --show-error --proto '=https' --tlsv1.2 -o "$work/deliver.sh" \
  "https://raw.githubusercontent.com/GioNob/ouf-deploy/$C/scripts/deliver-restore-semantic-provider-b1-wrapper.sh"
printf '%s  %s\n' "$L" "$work/deliver.sh" | sha256sum --check

args=(
  --b1-root "$S/semantic-provider-b1-install-20261114-v1"
  --wrapper /usr/local/sbin/ouf-semantic-admitted-v2
  --installed-wrapper-sha256 764c26d5a28c64fa50b376ca0215d2aedede0b3ef26534fbd84f4e58e3162879
  --prior-wrapper-sha256 55de41662098c1059a03d06ffb77bc965e5b033b9c3529dcfc7143808324efdd
  --prior-source-sha256 7894d0e942642d1daa5ae2e29c85cd7f0584b7cd285c539cab3ae624bab0bba9
  --prior-configuration-sha256 7462e41e6b40a3bb1ac23760f223a34a958bcd34151ce165f6f4625d942740c5
  --python-sha256 889c603f0d17cb54060951bcf4c4f9b8c9ebd9e52b392c70209bbb9755d797d9
  --lock /run/ouf-semantic-boot-guard/guard.lock
  --docker /usr/bin/docker
  --docker-sha256 7f5b38163f9c5367f4b42d905c0505877eafa4c20abe49430c85a770aefacf40
  --docker-socket unix:///var/run/docker.sock
  --successor 85b5302f6dbc3e9a24ace904b8d8a2d43bc5185e340c1bfe5474c723a6b640ef
  --successor 622a150067244ae8dbb4ac0f1889bc9e4b9823ed761820495f5c0849738dbc0d
  --output-root "$S"
  --output-name semantic-provider-b1-restore-v1
)
bash "$work/deliver.sh" "${extra[@]}" "${args[@]}"
