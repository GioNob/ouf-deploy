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
"$ouf_gh" api 'repos/GioNob/ouf-deploy/git/blobs/d2db5f51f54778246ad7accb2a1cb833d9caae42' --jq .content | tr -d '\n' | base64 --decode > "$ouf_cache/human.sh"
printf '%s  %s\n' '9e20e4d7df0a67e80ac9df4a97e05e97953a42d5d7c4303cb62b7faf0fc5b24d' "$ouf_cache/human.sh" | sha256sum -c -
"$ouf_gh" api 'repos/GioNob/ouf-deploy/git/blobs/7873b4d21de0fb253fbaa44264ae613c8c4b8697' --jq .content | tr -d '\n' | base64 --decode > "$ouf_cache/human.sh.operator.py"
printf '%s  %s\n' '4551eb63198e52cdc0520a9281bc07880f45fe2cc4c2d1a4aff292db4ad38833' "$ouf_cache/human.sh.operator.py" | sha256sum -c -
"$ouf_gh" api 'repos/GioNob/ouf-deploy/git/blobs/a0bdd9e8bbdbc328b893bc23a55cc5e1baea75ef' --jq .content | tr -d '\n' | base64 --decode > "$ouf_cache/runtime.sh"
printf '%s  %s\n' '3c81b62d526b66d5a17fa654cce0d2879c558950845b999b7fc87e5a46e50fd4' "$ouf_cache/runtime.sh" | sha256sum -c -
"$ouf_gh" api 'repos/GioNob/ouf-deploy/git/blobs/5c9c211d50e87f8c8e78853b0d61b3d906a1e3a1' --jq .content | tr -d '\n' | base64 --decode > "$ouf_cache/runtime.sh.operator.py"
printf '%s  %s\n' '7bf58a92aba162fd015bdb465d5987e5db3174e9f3d70b6724169b28c89581f2' "$ouf_cache/runtime.sh.operator.py" | sha256sum -c -
bash "$ouf_cache/runtime.sh" preflight
