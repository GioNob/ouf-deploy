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
"$ouf_gh" api 'repos/GioNob/ouf-deploy/git/blobs/e3794cf67c6c7f5246a70ca4b225be1c7f89b999' --jq .content | tr -d '\n' | base64 --decode > "$ouf_cache/human.sh"
printf '%s  %s\n' '99c5d569e007eaaa9ac9d3ccb6d91f849ae07203c0bd90ed6c7eb79ef833bd01' "$ouf_cache/human.sh" | sha256sum -c -
"$ouf_gh" api 'repos/GioNob/ouf-deploy/git/blobs/aa5a61876880f953db2ba0be4c326430f5c15198' --jq .content | tr -d '\n' | base64 --decode > "$ouf_cache/human.sh.operator.py"
printf '%s  %s\n' '0fbe4f0c52b3cdf778e06d7aebef22f2e06251cfd8a443e954ae7ddc39fc3c31' "$ouf_cache/human.sh.operator.py" | sha256sum -c -
"$ouf_gh" api 'repos/GioNob/ouf-deploy/git/blobs/7dd10b460f119fba814c0fc91d931eff46fc9d22' --jq .content | tr -d '\n' | base64 --decode > "$ouf_cache/runtime.sh"
printf '%s  %s\n' '0934192a867d6432b5d9a81cc59be51eaf1364cf77cb5a2ac7533dae672d6a4b' "$ouf_cache/runtime.sh" | sha256sum -c -
"$ouf_gh" api 'repos/GioNob/ouf-deploy/git/blobs/d101a8e773080508e3e2e241dab45a472f4282ba' --jq .content | tr -d '\n' | base64 --decode > "$ouf_cache/runtime.sh.operator.py"
printf '%s  %s\n' '42c018231ffc127edd7112309da223c8651d60992769330900c3441ed3b78d49' "$ouf_cache/runtime.sh.operator.py" | sha256sum -c -
bash "$ouf_cache/human.sh" prepare
