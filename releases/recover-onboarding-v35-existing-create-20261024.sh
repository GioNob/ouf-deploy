#!/usr/bin/env bash
# Installation-specific delivery; original journal/scope never changes with code hash.
set -euo pipefail
umask 077
work=$(mktemp -d "$HOME/ouf-v35-existing-create-recovery.XXXXXXXX")
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
  for item in \
    'scripts/recover-onboarding-v35-existing-create-20261024.py:recover.py:8791d7e34368813fb2d9c5f51b30ab915e6054e0d3a93c501c5e2178dc24aba5' \
    'tools/onboarding_v35_native/recovery.py:recovery.py:6b4f8e3dd0d10992e7f0e35f01789b6227666887c0c41be391d2511bf28abff4' \
    'tools/onboarding_v35_native/recovery_sql.py:recovery_sql.py:4e293886db276f9efcd4a32c7859836152e99230c1e447ae131daf13ff156c4a'
  do
    path="${item%%:*}"; rest="${item#*:}"; name="${rest%%:*}"; checksum="${rest#*:}"
    "$gh_bin" api --hostname github.com --method GET -H 'Accept: application/vnd.github.raw+json' \
      "repos/GioNob/ouf-deploy/contents/$path?ref=45842a2dd38a1fde1b25052d5118b9fd9621cb62" > "$work/$name"
    printf '%s  %s\n' "$checksum" "$work/$name" | sha256sum -c -
  done
  sudo -- /bin/bash -c '
    set -euo pipefail
    umask 077
    root=/etc/ouf/deploy-snapshots/onboarding-v35-created-recovery-code-b1fea93273609775
    mkdir -m 0700 -- "$root"
    chown 0:0 -- "$root"
    for name in recover.py recovery.py recovery_sql.py
    do install -o 0 -g 0 -m 0400 -- "$1/$name" "$root/$name"; done
    printf "%s  %s\n" \
      8791d7e34368813fb2d9c5f51b30ab915e6054e0d3a93c501c5e2178dc24aba5 "$root/recover.py" \
      6b4f8e3dd0d10992e7f0e35f01789b6227666887c0c41be391d2511bf28abff4 "$root/recovery.py" \
      4e293886db276f9efcd4a32c7859836152e99230c1e447ae131daf13ff156c4a "$root/recovery_sql.py" | sha256sum -c -
    /usr/bin/python3 -I -B -S "$root/recover.py"
  ' ouf-v35-existing-create-recovery "$work"
} 2>&1 | tee "$log"
