#!/usr/bin/env bash
# Runbook task-35: inventario B2 in sola lettura (nessuna scrittura, nessuna firma, nessun container).
# Uso:  bash b2-read.sh
# Stampa solo hash, schemi, stati e campi pubblici. Incollare l'output a Claude.
set -euo pipefail
umask 077

# Claude fills these pins after review and commit (D-001).
C=fbda7d27613a53c994efe09ea167be8760130835
R=bf992cd6c04d8581fb7d674326f67770cc9b75d355eaff89502173545b5180e5
[[ "$C" =~ ^[0-9a-f]{40}$ && "$C" != 0000000000000000000000000000000000000000 ]] \
  || { echo 'runbook non ancora fissato a un commit' >&2; exit 2; }
P=889c603f0d17cb54060951bcf4c4f9b8c9ebd9e52b392c70209bbb9755d797d9
S=/etc/ouf/deploy-snapshots
M=/var/lib/ouf-storage-migration
U=https://raw.githubusercontent.com/GioNob/ouf-deploy/$C

printf '%s  %s\n' "$P" /usr/bin/python3.13 | sudo sha256sum --check --status
D=$(sudo mktemp -d "$S/semantic-provider-b2-read-source.XXXXXXXX")
sudo chmod 0700 "$D"
sudo curl --fail --silent --show-error --max-time 30 --proto '=https' --tlsv1.2 \
  "$U/scripts/read-semantic-provider-b2-inputs.py" -o "$D/reader.py"
sudo chmod 0600 "$D/reader.py"
printf '%s  %s\n' "$R" "$D/reader.py" | sudo sha256sum --check --status

args=(
  --wrapper /usr/local/sbin/ouf-semantic-admitted-v2
  --b1-root "$S/semantic-provider-b1-install-20261114-v1"
  --a2-root "$M/semantic-provider-preparation-a2-20261113"
  --recipes-root "$S/semantic-provider-b1-recipes-20261114-v2"
  --versioned-base-root /var/lib/ouf-authority-mandates/base-versioned
  --nft /usr/sbin/nft
)
sudo /usr/bin/python3.13 -I -B "$D/reader.py" "${args[@]}"
