#!/usr/bin/env bash
# Runbook task-33: one governed early renewal with the installed renewal job (D-028).
# Uso:  bash mandate-renewal-early.sh plan               (sola lettura)
#       bash mandate-renewal-early.sh apply <planSha256>
set -euo pipefail
umask 077

mode=$(printf %s "${1:-}" | tr -d "[:space:]")
hash=$(printf %s "${2:-}" | tr -d "[:space:]")
case "$mode" in
  plan) extra=(--plan) ;;
  apply)
    [[ "$hash" =~ ^[0-9a-f]{64}$ ]] || { echo "uso: apply <planSha256> (ricevuti ${#hash} caratteri)" >&2; exit 2; }
    extra=(--apply --plan-sha256 "$hash") ;;
  *) echo 'uso: plan | apply <planSha256>' >&2; exit 2 ;;
esac

# Claude fills C and T after review and commit (D-001).
C=0000000000000000000000000000000000000000
T=0000000000000000000000000000000000000000000000000000000000000000
[[ "$C" =~ ^[0-9a-f]{40}$ && "$C" != 0000000000000000000000000000000000000000 ]] \
  || { echo 'runbook non ancora fissato a un commit' >&2; exit 2; }
P=889c603f0d17cb54060951bcf4c4f9b8c9ebd9e52b392c70209bbb9755d797d9
U=/etc/systemd/system/ouf-authority-mandate-renewal.service
printf '%s  %s\n' "$P" /usr/bin/python3.13 | sudo sha256sum --check --status

# The configuration hash is the one pinned in the installed unit.
H=$(sudo sed -n 's/^ExecStart=.* --configuration-sha256 \([0-9a-f]\{64\}\)$/\1/p' "$U")
[[ "$H" =~ ^[0-9a-f]{64}$ ]] || { echo 'hash della configurazione non trovato nella unit' >&2; exit 2; }

work=$(sudo mktemp -d /etc/ouf/deploy-snapshots/mandate-renewal-early-source.XXXXXXXX)
sudo chmod 0700 "$work"
trap 'printf "OUF_MANDATE_RENEWAL_EARLY_DELIVERY=%s\n" "$work"' EXIT
sudo curl --fail --silent --show-error --max-time 30 --proto '=https' --tlsv1.2 \
  "https://raw.githubusercontent.com/GioNob/ouf-deploy/$C/scripts/renew-mandates-early.py" -o "$work/early.py"
sudo chmod 0600 "$work/early.py"
printf '%s  %s\n' "$T" "$work/early.py" | sudo sha256sum --check --status

sudo /usr/bin/python3.13 -I -B "$work/early.py" "${extra[@]}" --configuration-sha256 "$H"
