#!/usr/bin/env bash
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [ ! -x "$ouf_gh" ]; then ouf_gh="$(command -v gh || true)"; fi
if [ -z "$ouf_gh" ]; then echo 'Client GitHub non trovato; nessuna esecuzione sudo.' >&2; exit 1; fi
ouf_archive="$HOME/ouf-chatbot-file-delivery-126e49f3830667934bf8f8d7/cohort/cohort.zip"
if [ ! -f "$ouf_archive" ]; then echo 'Archivio originale non trovato; nessuna esecuzione sudo.' >&2; exit 1; fi
ouf_launch="$(mktemp -d "$HOME/ouf-gateway-phase5-null-binds-launch.XXXXXXXX")"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/scripts/deliver-chatbot-file-cohort.py?ref=5d9c9b6b944e71b25cd006994c511397295b4f4f' --jq .content | base64 --decode > "$ouf_launch/deliver.py"
printf '%s  %s\n' '7370190dfb5e5e46453fee65603b528d3e223f3e616a7b386a7047df2f9f7499' "$ouf_launch/deliver.py" | sha256sum --check -
echo "Log della sessione: $ouf_launch/run.log"
/usr/bin/python3 -I -B "$ouf_launch/deliver.py" \
  --source-commit 5d9c9b6b944e71b25cd006994c511397295b4f4f \
  --package-archive "$ouf_archive" 2>&1 | tee "$ouf_launch/run.log"
