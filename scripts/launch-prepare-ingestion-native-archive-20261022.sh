#!/usr/bin/env bash
set -euo pipefail
umask 077
if [ "$#" -ne 0 ]; then printf '%s\n' 'Solo preparazione offline esplicita; nessun argomento ammesso.' >&2; exit 2; fi
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [ ! -x "$ouf_gh" ]; then ouf_gh="$(command -v gh || true)"; fi
if [ -z "$ouf_gh" ] || [ ! -x "$ouf_gh" ]; then printf '%s\n' 'Client GitHub gia autenticato non disponibile; nessuna modifica eseguita.' >&2; exit 2; fi
ouf_output="$(mktemp -d "$HOME/ouf-native-archive.XXXXXXXX")"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/scripts/prepare-ingestion-native-archive-20261022.py?ref=7a22715eadf10d1b574e6ef4af36f2ae0c0bca48' --jq .content > "$ouf_output/operator.b64"
base64 --decode "$ouf_output/operator.b64" > "$ouf_output/operator.py"
printf '%s  %s\n' 13335a0aa4ba672c80cc2f63ca1b3e2e9d97b111f876d61c62dbda514d8d4f31 "$ouf_output/operator.py" | sha256sum -c -
set +e
sudo /usr/bin/python3 -I -B -S "$ouf_output/operator.py" prepare 2>&1 | tee "$ouf_output/operator.log"
ouf_status=${PIPESTATUS[0]}
set -e
printf 'Directory conservata: %s\nLog conservato: %s/operator.log\nDopo STOP conserva tutto: non rieseguire.\n' "$ouf_output" "$ouf_output"
exit "$ouf_status"
