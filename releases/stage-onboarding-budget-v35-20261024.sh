#!/usr/bin/env bash
set -euo pipefail
umask 077
if [ "$#" -ne 0 ]; then exit 2; fi
work=$(mktemp -d "$HOME/ouf-budget-v35-package.XXXXXXXX")
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
  for gate in \
    'GioNob/ouf-deploy:40098040577:0da27a375f18f611fc674faf751138dc2276a439' \
    'GioNob/ouf-source-onboarding:40092379187:1b1222ceaa5af85a25c20857e7c8c1b548b12dc1'
  do
    repo="${gate%%:*}"; rest="${gate#*:}"; run="${rest%%:*}"; expected="${rest#*:}"
    state=$("$gh_bin" api --hostname github.com --method GET "repos/$repo/actions/runs/$run" --jq '[.head_sha,.status,.conclusion] | @tsv')
    if [ "$state" != "$(printf '%s\tcompleted\tsuccess' "$expected")" ]; then
      printf '%s\n' 'WAIT_CI: qualifica esatta non disponibile; nessun sudo o claim OUF eseguito.'
      exit 75
    fi
  done
  /usr/bin/python3 -I -B -S - "$HOME" /etc/ouf/deploy-snapshots <<'PYSPACE'
import shutil,sys
required=3*(210895493+210893865+109135566)
if any(shutil.disk_usage(p).free<required for p in sys.argv[1:]):
    raise SystemExit('STOP: spazio insufficiente per pacchetto, JAR e margine di staging.')
PYSPACE
  for item in \
    'scripts/prepare-onboarding-v35-review-inputs-20261024.py:prepare.py:1ce4105cb54b6e9dd6ab7579f605b6270a51607f91ee871224be176ad5da83b7' \
    'scripts/verify-onboarding-v35-artifact-20261024.py:verify.py:08243e74b2ace64d974deeb7e5ca2d44710c456848d447e58bf518a1df1b3e4d' \
    'releases/onboarding-v35-image-source-contract-20261024.json:source-contract.json:4de8d18fe3cb4c3a8f8ad3e3e8448bbc0c6510c596b8964b1c7782c2b1a2a0dd'
  do
    path="${item%%:*}"; rest="${item#*:}"; name="${rest%%:*}"; checksum="${rest#*:}"
    "$gh_bin" api --hostname github.com --method GET -H 'Accept: application/vnd.github.raw+json' \
      "repos/GioNob/ouf-deploy/contents/$path?ref=0da27a375f18f611fc674faf751138dc2276a439" > "$work/$name"
    printf '%s  %s\n' "$checksum" "$work/$name" | sha256sum -c -
  done
  "$gh_bin" api --hostname github.com --method GET \
    repos/GioNob/ouf-source-onboarding/actions/artifacts/12559990549/zip > "$work/package.zip"
  printf '%s  %s\n' '074bde3ecc348c9c9481683412f2c1ac376b2b2fdae409d688d71397a8c322e8' "$work/package.zip" | sha256sum -c -
  /usr/bin/python3 -I -B -S "$work/verify.py" "$work"
  sudo -- /bin/bash -c '
    set -euo pipefail
    umask 077
    root=/etc/ouf/deploy-snapshots/onboarding-budget-v35-54d86bbcd2ea47fd
    mkdir -m 0700 -- "$root"
    chown 0:0 -- "$root"
    for name in image.tar.gz application.jar manifest.json source-contract.json prepare.py
    do
      install -o 0 -g 0 -m 0400 -- "$1/$name" "$root/$name"
    done
    printf "%s  %s\n" \
      54d86bbcd2ea47fdbda133699b914674c766bdef8554132a308eae36d38f3358 "$root/image.tar.gz" \
      70c16461ae2a381d9baf3e8788f1403e9a925d86be4802ea928477db93b84f52 "$root/application.jar" \
      63d96c781cf88f55f672ac65d86de9e7c4b87056801dfd1c32129e638ba32553 "$root/manifest.json" \
      4de8d18fe3cb4c3a8f8ad3e3e8448bbc0c6510c596b8964b1c7782c2b1a2a0dd "$root/source-contract.json" \
      1ce4105cb54b6e9dd6ab7579f605b6270a51607f91ee871224be176ad5da83b7 "$root/prepare.py" | sha256sum -c -
    /usr/bin/python3 -I -B -S "$root/prepare.py"
  ' ouf-budget-v35-package "$work"
} 2>&1 | tee "$log"

