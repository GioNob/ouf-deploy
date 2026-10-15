#!/usr/bin/env bash
# Fixed current action: no IAM login, grant, runtime apply, token or secret read.
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [ ! -x "$ouf_gh" ]; then ouf_gh="$(command -v gh || true)"; fi
if [ -z "$ouf_gh" ]; then echo 'Client GitHub non trovato; nessuna esecuzione sudo.' >&2; exit 1; fi
ouf_read="$(mktemp -d "$HOME/ouf-mount-owner-read.XXXXXXXX")"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/scripts/read-chatbot-mount-owner-failure-20261015.py?ref=bda269b13935588c92f7803b0a5850b33a05be8d' --jq .content |
  base64 --decode > "$ouf_read/read.py"
printf '%s  %s\n' '80d2903fe5093bd0fc41cd0ea3a227d7929da6fd7b68f36c4d91fab26bd644fe' "$ouf_read/read.py" | sha256sum --check -
sudo -- /usr/bin/python3 -I -B -S "$ouf_read/read.py" | tee "$ouf_read/readback.log"
