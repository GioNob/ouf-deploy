#!/usr/bin/env bash
# Fetch all code before timers/consent; one read-only runtime/HUMAN preflight.
set -euo pipefail
umask 077
[[ "$#" -eq 0 ]] || exit 2
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [[ ! -x "$ouf_gh" ]]; then ouf_gh="$(command -v gh || true)"; fi
[[ -n "$ouf_gh" && -x "$ouf_gh" ]] || { printf '%s\n' 'STOP: client GitHub non disponibile; nessun sudo.' >&2; exit 2; }
ouf_cache="$(mktemp -d "$HOME/ouf-readiness-launchers.XXXXXXXX")"
trap 'printf "Directory conservata: %s\nLauncher HUMAN: %s/human.sh\nLauncher runtime: %s/runtime.sh\n" "$ouf_cache" "$ouf_cache" "$ouf_cache"' EXIT
"$ouf_gh" api 'repos/GioNob/ouf-deploy/git/blobs/7589cdc1a23c80a16ba20fa34eeee0c2cf80d9e7' --jq .content | tr -d '\n' | base64 --decode > "$ouf_cache/human.sh"
printf '%s  %s\n' '4d3d0443353181f57b49321180dd14bdf57a37c59784e587fef7f70ccb195527' "$ouf_cache/human.sh" | sha256sum -c -
"$ouf_gh" api 'repos/GioNob/ouf-deploy/git/blobs/78550f424c904b0ac9cd8c21a7e2649b33888bf5' --jq .content | tr -d '\n' | base64 --decode > "$ouf_cache/human.sh.operator.py"
printf '%s  %s\n' '73346dc48bfd1202d8cb4f6fa3d82ea53c25e8e5eeeb80c7d8bedd45c02b7cd0' "$ouf_cache/human.sh.operator.py" | sha256sum -c -
"$ouf_gh" api 'repos/GioNob/ouf-deploy/git/blobs/a7bb9a0db614c0f0ec74d5dbb037b43fc633eac2' --jq .content | tr -d '\n' | base64 --decode > "$ouf_cache/runtime.sh"
printf '%s  %s\n' 'd190246ed97a19917af59a49b73bffa3cd2cf99a5cf6c546f79b3e3e1404c846' "$ouf_cache/runtime.sh" | sha256sum -c -
"$ouf_gh" api 'repos/GioNob/ouf-deploy/git/blobs/50c89bc279b46183493cb04e4a23608d4cc2fc8c' --jq .content | tr -d '\n' | base64 --decode > "$ouf_cache/runtime.sh.operator.py"
printf '%s  %s\n' '06bc50f8037f83b2d5a4eac6ece1f7f2a18edcfbb4be3d9149a07e91aae25a32' "$ouf_cache/runtime.sh.operator.py" | sha256sum -c -
bash "$ouf_cache/runtime.sh" preflight
