#!/usr/bin/env bash
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [ ! -x "$ouf_gh" ]; then ouf_gh="$(command -v gh || true)"; fi
if [ -z "$ouf_gh" ]; then echo 'Client GitHub non trovato; nessuna esecuzione sudo.' >&2; exit 1; fi
ouf_archive="$HOME/ouf-chatbot-file-delivery-126e49f3830667934bf8f8d7/cohort/cohort.zip"
if [ ! -f "$ouf_archive" ]; then echo 'Archivio originale non trovato; nessuna esecuzione sudo.' >&2; exit 1; fi
ouf_launch="$(mktemp -d "$HOME/ouf-running-backup-recovery-launch.XXXXXXXX")"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/scripts/deliver-chatbot-file-cohort.py?ref=b93e3570bd3e43b6c8e99d2237743bb819e43304' --jq .content | base64 --decode > "$ouf_launch/deliver.py"
printf '%s  %s\n' '4b2d66a66cbda7335e328481fcb93925d605ead3ec1c3767b3f057401b13a3fd' "$ouf_launch/deliver.py" | sha256sum --check -
echo "Log della sessione: $ouf_launch/run.log"
/usr/bin/python3 -I -B "$ouf_launch/deliver.py" \
  --source-commit b93e3570bd3e43b6c8e99d2237743bb819e43304 \
  --package-archive "$ouf_archive" 2>&1 | tee "$ouf_launch/run.log"
