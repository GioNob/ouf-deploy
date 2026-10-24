#!/usr/bin/env bash
set -euo pipefail
umask 077
work=$(mktemp -d "$HOME/ouf-v35-retained-reader.XXXXXXXX")
log="$work/operator.log"
: > "$log"
trap 'rc=$?; trap - EXIT; set +e; printf "\nExit=%s\nDirectory=%s\nLog=%s\n" "$rc" "$work" "$log" | tee -a "$log"; exit "$rc"' EXIT
{
  gh_bin="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
  if [ ! -x "$gh_bin" ]; then gh_bin=$(command -v gh || true); fi
  if [ -z "$gh_bin" ] || [ ! -x "$gh_bin" ]; then
    printf '%s\n' 'STOP: client gh esistente assente; nessun sudo eseguito.'
    exit 2
  fi
  "$gh_bin" api --hostname github.com --method GET -H 'Accept: application/vnd.github.raw+json' \
    'repos/GioNob/ouf-deploy/contents/scripts/read-onboarding-v35-created-config-20261024.py?ref=832b3fc230f5a7e4b43d2dd948b090155cead1d4' > "$work/read.py"
  printf '%s  %s\n' bf4b2bc711802b25c386f24da4e9733af79c895a9bf2b4e102749f0b69b90a32 "$work/read.py" | sha256sum -c -
  sudo -- /bin/bash -c '
    set -euo pipefail
    umask 077
    root=/etc/ouf/deploy-snapshots/onboarding-v35-retained-reader-bf4b2bc711802b25
    mkdir -m 0700 -- "$root"
    chown 0:0 -- "$root"
    install -o 0 -g 0 -m 0400 -- "$1/read.py" "$root/read.py"
    printf "%s  %s\n" bf4b2bc711802b25c386f24da4e9733af79c895a9bf2b4e102749f0b69b90a32 "$root/read.py" | sha256sum -c -
    /usr/bin/python3 -I -B -S "$root/read.py"
  ' ouf-v35-retained-reader "$work"
} 2>&1 | tee "$log"
