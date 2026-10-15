#!/usr/bin/env bash
# Pinned post-grant continuation. Qualification is in the companion evidence.
# Preparation verifies retained state before IAM login; runtime needs fresh HUMAN.
set -euo pipefail
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [ ! -x "$ouf_gh" ]; then ouf_gh="$(command -v gh || true)"; fi
if [ -z "$ouf_gh" ]; then
  echo 'Client GitHub non trovato; nessuna esecuzione sudo.' >&2
  exit 1
fi
ouf_launch="$(mktemp -d "$HOME/ouf-postgrant-launch.XXXXXXXX")"
chmod 700 "$ouf_launch"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/scripts/deliver-chatbot-file-cohort.py?ref=0525c4186a5613000905ba4dfae6766827ad9f06' --jq .content |
  base64 --decode > "$ouf_launch/deliver.py"
printf '%s  %s\n' '788b7381ab642effce7786b0ca5b07a575cc01069df51c7e13c584ddf18fbce3' "$ouf_launch/deliver.py" | sha256sum --check -
/usr/bin/python3 -I -B "$ouf_launch/deliver.py" \
  --source-commit 0525c4186a5613000905ba4dfae6766827ad9f06 \
  --package-archive "$HOME/ouf-chatbot-file-delivery-126e49f3830667934bf8f8d7/cohort/cohort.zip" \
  2>&1 | tee "$ouf_launch/run.log"
