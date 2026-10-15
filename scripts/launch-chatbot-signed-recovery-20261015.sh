#!/usr/bin/env bash
# Qualified source pin; same paused container; signed history and pending admission; cumulative four.
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [ ! -x "$ouf_gh" ]; then ouf_gh="$(command -v gh || true)"; fi
if [ -z "$ouf_gh" ]; then echo 'Client GitHub non trovato; nessuna esecuzione sudo.' >&2; exit 1; fi
ouf_archive="$HOME/ouf-chatbot-file-delivery-126e49f3830667934bf8f8d7/cohort/cohort.zip"
if [ ! -f "$ouf_archive" ]; then echo 'Pacchetto qualificato già scaricato non trovato; nessuna esecuzione sudo.' >&2; exit 1; fi
ouf_launch="$(mktemp -d "$HOME/ouf-signed-recovery-launch.XXXXXXXX")"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/scripts/deliver-chatbot-file-cohort.py?ref=e70ca5957772e170bc762dd937e1c46a40051f0a' --jq .content |
  base64 --decode > "$ouf_launch/deliver.py"
printf '%s  %s\n' 'baf0c8c681a2f01439f9fe2e0336f4db1cbf492fc85190775a7c3046a08b2b72' "$ouf_launch/deliver.py" | sha256sum --check -
echo "Log della sessione: $ouf_launch/run.log"
/usr/bin/python3 -I -B "$ouf_launch/deliver.py" \
  --source-commit e70ca5957772e170bc762dd937e1c46a40051f0a \
  --package-archive "$ouf_archive" 2>&1 | tee "$ouf_launch/run.log"
