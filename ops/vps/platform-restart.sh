#!/usr/bin/env bash
# Use the installed profile with the pinned, hash-verified delivery.
set -euo pipefail
umask 077
# Claude fills the same delivery pin as the install runbook (D-001).
C=21c8ddd9e9f1000f121a2222001739ef344fa595
[[ $C =~ ^[0-9a-f]{40}$ && $C != 0000000000000000000000000000000000000000 ]] ||
  { echo 'Pin della consegna mancante' >&2; exit 2; }
mode=${1:-}
action=${2:-}
[[ $action == start || $action == stop ]] || { echo 'Azione richiesta: start | stop' >&2; exit 2; }
args=(operate --dest "${OUF_INSTALL_ROOT:?installation directory}" --operation "$mode" --action "$action")
case "$mode:$#" in
  plan:2) ;;
  apply:3) [[ $3 =~ ^[0-9a-f]{64}$ ]] || exit 2; args+=(--plan-sha256 "$3");;
  *) echo 'Uso: plan start|stop oppure apply start|stop <planSha256>' >&2; exit 2;;
esac
export OUF_OPERATOR_PIN="$C"
exec bash "$(dirname -- "${BASH_SOURCE[0]}")/platform-restart-install.sh" "${args[@]}"
