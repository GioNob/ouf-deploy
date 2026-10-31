(
  set -euo pipefail
  umask 077
  work=$(mktemp -d "$HOME/ouf-v35-native-apply.XXXXXXXX")
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
      'scripts/apply-onboarding-v35-native-20261024.py:apply.py:55addc8768319abaecfd5501c489edeb6fba18aa5ca61ee1bed9b62b0f146eb2' \
      'tools/onboarding_v35_native/protocol.py:protocol.py:034bb7572905903cca52033e9af098fdbe351d244a531302bf30831df338e43d' \
      'tools/onboarding_v35_native/ports.py:ports.py:a3997298bdb5ff0675bdf81506ec36600d7f6783f741aeff4ee7960d414881be' \
      'tools/onboarding_v35_native/quarantine.py:quarantine.py:69dcb537d1e8d6b4603078339fc7eb1b79a74a8357666d60f7937693a44f69c2' \
      'tools/ingestion_readiness_patch_execution/image_import.py:image_import.py:2e7255c7222cfe69a2fd115fcb9b05cf4f31bd6cc24af6532718621bce9f112d'
    do
      path="${item%%:*}"; rest="${item#*:}"; name="${rest%%:*}"; checksum="${rest#*:}"
      "$gh_bin" api --hostname github.com --method GET -H 'Accept: application/vnd.github.raw+json' \
        "repos/GioNob/ouf-deploy/contents/$path?ref=4cc62e49539a8e52a823ac5cba95bf92d64613fd" > "$work/$name"
      printf '%s  %s\n' "$checksum" "$work/$name" | sha256sum -c -
    done
    sudo -- /bin/bash -c '
      set -euo pipefail
      umask 077
      root=/etc/ouf/deploy-snapshots/onboarding-v35-native-code-a0ce9d7ffb2e4500
      mkdir -m 0700 -- "$root"
      chown 0:0 -- "$root"
      for name in apply.py protocol.py ports.py quarantine.py image_import.py
      do
        install -o 0 -g 0 -m 0400 -- "$1/$name" "$root/$name"
      done
      printf "%s  %s\n" \
        55addc8768319abaecfd5501c489edeb6fba18aa5ca61ee1bed9b62b0f146eb2 "$root/apply.py" \
        034bb7572905903cca52033e9af098fdbe351d244a531302bf30831df338e43d "$root/protocol.py" \
        a3997298bdb5ff0675bdf81506ec36600d7f6783f741aeff4ee7960d414881be "$root/ports.py" \
        69dcb537d1e8d6b4603078339fc7eb1b79a74a8357666d60f7937693a44f69c2 "$root/quarantine.py" \
        2e7255c7222cfe69a2fd115fcb9b05cf4f31bd6cc24af6532718621bce9f112d "$root/image_import.py" | sha256sum -c -
      /usr/bin/python3 -I -B -S "$root/apply.py"
    ' ouf-v35-native-apply "$work"
  } 2>&1 | tee "$log"
)
