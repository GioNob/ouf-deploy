#!/usr/bin/env bash
# Runbook task-45 (R-007): igiene di /etc/ssh/sshd_config, configurazione effettiva invariata, nessun reload.
# Uso:  bash sshd-hygiene.sh plan                 (sola lettura)
#       bash sshd-hygiene.sh apply <planSha256>
#       bash sshd-hygiene.sh restore-plan | restore-apply <planSha256>
set -euo pipefail
C=a5693150655d82635e228a7203b2f848f2eb7679
H=f44b288ed4b7e67ce2a51c3995edd64b6b90b166c266b64bc5491d7811e7cc25
mode=${1:-}
D=$(mktemp -d)
U=https://raw.githubusercontent.com/GioNob/ouf-deploy/$C/scripts/apply-sshd-hygiene-20261115.py
curl -fsS -o "$D/s.py" "$U"
printf '%s  %s\n' "$H" "$D/s.py" | sha256sum --check --status
X=(sudo /usr/bin/python3.13 -I -B "$D/s.py")
case "$mode" in
  plan) "${X[@]}" --plan ;;
  apply) "${X[@]}" --apply --plan-sha256 "${2:?planSha256}" ;;
  restore-plan) "${X[@]}" --restore --plan ;;
  restore-apply) "${X[@]}" --restore --apply --plan-sha256 "${2:?planSha256}" ;;
  *) echo 'uso: plan | apply <sha> | restore-plan | restore-apply <sha>' >&2; exit 2 ;;
esac
