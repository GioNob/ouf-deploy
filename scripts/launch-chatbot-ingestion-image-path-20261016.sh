#!/usr/bin/env bash
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [ ! -x "$ouf_gh" ]; then ouf_gh="$(command -v gh || true)"; fi
if [ -z "$ouf_gh" ]; then echo 'Client GitHub non trovato; nessuna esecuzione sudo.' >&2; exit 1; fi
ouf_archive="$HOME/ouf-chatbot-file-delivery-126e49f3830667934bf8f8d7/cohort/cohort.zip"
if [ ! -f "$ouf_archive" ]; then echo 'Archivio originale non trovato; nessuna esecuzione sudo.' >&2; exit 1; fi
ouf_launch="$(mktemp -d "$HOME/ouf-ingestion-path-launch.XXXXXXXX")"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/scripts/deliver-chatbot-file-cohort.py?ref=d7bbb768970aad1a001ca4d085bcc87c58a29cec' --jq .content | base64 --decode > "$ouf_launch/deliver.py"
printf '%s  %s\n' '5cf2c1b37e8f28249d92060006d8176a9d001c26be30c6807cb6cc08a6d61d9a' "$ouf_launch/deliver.py" | sha256sum --check -
echo "Log della sessione: $ouf_launch/run.log"
/usr/bin/python3 -I -B "$ouf_launch/deliver.py" \
  --source-commit d7bbb768970aad1a001ca4d085bcc87c58a29cec \
  --package-archive "$ouf_archive" 2>&1 | tee "$ouf_launch/run.log"
