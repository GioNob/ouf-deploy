#!/usr/bin/env bash
# Qualified source pin; same paused container, six effects, cumulative three.
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [ ! -x "$ouf_gh" ]; then ouf_gh="$(command -v gh || true)"; fi
if [ -z "$ouf_gh" ]; then echo 'Client GitHub non trovato; nessuna esecuzione sudo.' >&2; exit 1; fi
ouf_archive="$HOME/ouf-chatbot-file-delivery-126e49f3830667934bf8f8d7/cohort/cohort.zip"
if [ ! -f "$ouf_archive" ]; then echo 'Pacchetto qualificato già scaricato non trovato; nessuna esecuzione sudo.' >&2; exit 1; fi
ouf_launch="$(mktemp -d "$HOME/ouf-mount-recovery-launch.XXXXXXXX")"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/scripts/deliver-chatbot-file-cohort.py?ref=43819bc04dc40daaf119a2098945405f42d7bc6f' --jq .content |
  base64 --decode > "$ouf_launch/deliver.py"
printf '%s  %s\n' '72323604029b4ede41211a579e138ef6fcda03f8e396d1b67bdf251130118595' "$ouf_launch/deliver.py" | sha256sum --check -
echo "Log della sessione: $ouf_launch/run.log"
/usr/bin/python3 -I -B "$ouf_launch/deliver.py" \
  --source-commit 43819bc04dc40daaf119a2098945405f42d7bc6f \
  --package-archive "$ouf_archive" 2>&1 | tee "$ouf_launch/run.log"
