#!/usr/bin/env bash
# Task-40a: lettore B2 v2. Esecuzione manuale dell'umano, come nel v1.
# Uso: bash b2-read-v2.sh [percorso-assoluto-copia-privata-generation-receipt]
# Il launcher prepara soltanto il sorgente; il lettore non scrive e non esegue comandi.
# Output: hash, schemi, chiavi, stati e soli valori pubblici in whitelist.
# Nessun endpoint DNS, contenuto OCI, chiave o contenuto dei sorgenti in output.
# READ/contatori zero non attestano readiness o autorizzazione d'esercizio.
set -euo pipefail
umask 077

# Claude fixes both pins after review and commit (D-001). Do not run unpinned.
C=0000000000000000000000000000000000000000
R=0000000000000000000000000000000000000000000000000000000000000000
[[ "$C" =~ ^[0-9a-f]{40}$ && "$C" != 0000000000000000000000000000000000000000 &&
   "$R" =~ ^[0-9a-f]{64}$ && "$R" != 0000000000000000000000000000000000000000000000000000000000000000 ]] \
  || { echo 'runbook non ancora fissato a commit e hash' >&2; exit 2; }
[[ $# -le 1 ]] || { echo 'atteso al massimo il percorso della ricevuta privata' >&2; exit 2; }

P=889c603f0d17cb54060951bcf4c4f9b8c9ebd9e52b392c70209bbb9755d797d9
S=/etc/ouf/deploy-snapshots
M=/var/lib/ouf-storage-migration
U=https://raw.githubusercontent.com/GioNob/ouf-deploy/$C
printf '%s  %s\n' "$P" /usr/bin/python3.13 | sudo sha256sum --check --status
D=$(sudo mktemp -d "$S/semantic-provider-b2-read-v2-source.XXXXXXXX")
sudo chmod 0700 "$D"
sudo curl --fail --silent --show-error --max-time 30 --proto '=https' --tlsv1.2 \
  "$U/scripts/read-semantic-provider-b2-inputs-v2.py" -o "$D/reader.py"
sudo chmod 0600 "$D/reader.py"
printf '%s  %s\n' "$R" "$D/reader.py" | sudo sha256sum --check --status

args=(
  --coordinator-context "$S/discovery-coordinator-successor-20261109-uz9gw5ny"
  --coordinator-install "$S/semantic-coordinated-boot-install-successor-b3c3uwwt"
  --historic-registry "$S/semantic-provider-v2-transaction-mf9x0eqd/registry"
  --rootfs-result "$M/semantic-provider-b1-rootfs-20261113-a2/result.json"
  --recipes-root "$S/semantic-provider-b1-recipes-20261114-v2"
  --a2-root "$M/semantic-provider-preparation-a2-20261113"
  --historic-source "$S/semantic-provider-v2-transaction-mf9x0eqd/source"
)
if [[ $# -eq 1 ]]; then
  args+=(--generation-receipt "$1")
fi
sudo /usr/bin/python3.13 -I -B "$D/reader.py" "${args[@]}"
