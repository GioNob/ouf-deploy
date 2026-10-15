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
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/scripts/deliver-chatbot-file-cohort.py?ref=2a122f1144579fe03d57c14e35452a8fbf6e0547' --jq .content |
  base64 --decode > "$ouf_launch/deliver.py"
printf '%s  %s\n' '2ba82089bd3a03e569204e69a3499ae710618081f90e7f7bdd49151c8a43cfdf' "$ouf_launch/deliver.py" | sha256sum --check -
/usr/bin/python3 -I -B "$ouf_launch/deliver.py" \
  --source-commit 2a122f1144579fe03d57c14e35452a8fbf6e0547 \
  --package-archive "$HOME/ouf-chatbot-file-delivery-126e49f3830667934bf8f8d7/cohort/cohort.zip" \
  2>&1 | tee "$ouf_launch/run.log"
