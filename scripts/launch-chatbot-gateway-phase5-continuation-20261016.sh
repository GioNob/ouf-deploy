#!/usr/bin/env bash
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [ ! -x "$ouf_gh" ]; then ouf_gh="$(command -v gh || true)"; fi
if [ -z "$ouf_gh" ]; then echo 'Client GitHub non trovato; nessuna esecuzione sudo.' >&2; exit 1; fi
ouf_archive="$HOME/ouf-chatbot-file-delivery-126e49f3830667934bf8f8d7/cohort/cohort.zip"
if [ ! -f "$ouf_archive" ]; then echo 'Archivio originale non trovato; nessuna esecuzione sudo.' >&2; exit 1; fi
ouf_launch="$(mktemp -d "$HOME/ouf-gateway-phase5-continuation-launch.XXXXXXXX")"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/scripts/deliver-chatbot-file-cohort.py?ref=aeeb625ddacc5837e4520788d73a6598aaa5734f' --jq .content | base64 --decode > "$ouf_launch/deliver.py"
printf '%s  %s\n' '01467f33c38a2c2c847a8818f5fd894d2aea104b01bab86b83dc6dfbb9f7fa5e' "$ouf_launch/deliver.py" | sha256sum --check -
echo "Log della sessione: $ouf_launch/run.log"
/usr/bin/python3 -I -B "$ouf_launch/deliver.py" \
  --source-commit aeeb625ddacc5837e4520788d73a6598aaa5734f \
  --package-archive "$ouf_archive" 2>&1 | tee "$ouf_launch/run.log"
