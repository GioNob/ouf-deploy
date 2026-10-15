#!/usr/bin/env bash
# Exact same-source qualified unsigned paused-attestation continuation.
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [ ! -x "$ouf_gh" ]; then ouf_gh="$(command -v gh || true)"; fi
if [ -z "$ouf_gh" ]; then
  echo 'Client GitHub non trovato; nessuna esecuzione sudo.' >&2
  exit 1
fi
ouf_archive="$HOME/ouf-chatbot-file-delivery-126e49f3830667934bf8f8d7/cohort/cohort.zip"
if [ ! -f "$ouf_archive" ]; then
  echo 'Pacchetto qualificato già scaricato non trovato; nessuna esecuzione sudo.' >&2
  exit 1
fi
ouf_launch="$(mktemp -d "$HOME/ouf-paused-recovery-launch.XXXXXXXX")"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/scripts/deliver-chatbot-file-cohort.py?ref=b7d24c57d6e45e71994ac3f99f56f249d83cde22' --jq .content |
  base64 --decode > "$ouf_launch/deliver.py"
printf '%s  %s\n' 'ccdc95aa88ba2205bd9ac86f1b26654615a544b0ca35e0ab58f38fcd82740c30' "$ouf_launch/deliver.py" | sha256sum --check -
echo "Log della sessione: $ouf_launch/run.log"
/usr/bin/python3 -I -B "$ouf_launch/deliver.py" \
  --source-commit b7d24c57d6e45e71994ac3f99f56f249d83cde22 \
  --package-archive "$ouf_archive" \
  2>&1 | tee "$ouf_launch/run.log"
