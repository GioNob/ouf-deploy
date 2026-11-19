#!/usr/bin/env bash
# Runbook task-28: chiusura governata dell'incidente del rinnovo dei mandati (D-030).
# Rimuove solo i temporanei .tmp-* elencati nel plan e archivia l'incidente; mai N.json.
# Uso:  bash mandate-renewal-incident-close.sh plan               (sola lettura)
#       bash mandate-renewal-incident-close.sh apply <planSha256>
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

P=889c603f0d17cb54060951bcf4c4f9b8c9ebd9e52b392c70209bbb9755d797d9
D=/etc/ouf/authority-mandate-renewal
U=/etc/systemd/system/ouf-authority-mandate-renewal.service
printf '%s  %s\n' "$P" /usr/bin/python3.13 | sudo sha256sum --check --status

# The configuration hash is the one pinned in the installed unit.
H=$(sudo sed -n 's/^ExecStart=.* --configuration-sha256 \([0-9a-f]\{64\}\)$/\1/p' "$U")
[[ "$H" =~ ^[0-9a-f]{64}$ ]] || { echo 'hash della configurazione non trovato nella unit' >&2; exit 2; }

sudo /usr/bin/python3.13 -I -B "$D/renewal.py" incident-close "${extra[@]}" \
  --configuration "$D/configuration.json" --configuration-sha256 "$H"
