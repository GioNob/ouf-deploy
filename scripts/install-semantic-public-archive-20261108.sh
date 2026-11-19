#!/usr/bin/env bash
# Public transport for the exact original artifact. Runtime controller unchanged.
set -euo pipefail
ouf_public=$(mktemp -d /tmp/ouf-semantic-public.XXXXXX)
trap 'rm -rf -- "$ouf_public"' EXIT
curl --fail --silent --show-error --location --max-redirs 3 \
  --proto '=https' --proto-redir '=https' --connect-timeout 20 --max-time 240 \
  --range 0-203419417 \
  'https://nightly.link/GioNob/ouf-semantic-registry/actions/artifacts/13066396654.zip' \
  -o "$ouf_public/candidate.zip"
(
  cd "$ouf_public"
  printf '%s  %s\n' \
    '1a7045ffb39486f2579fb342d7fd881f5a123f74a0810d353bce3c755bfc76ba' \
    candidate.zip | sha256sum -c -
)
curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
  --connect-timeout 10 --max-time 30 \
  'https://raw.githubusercontent.com/GioNob/ouf-deploy/b2ef4a4d343716b40ae35a409c6a910a63f88721/scripts/install-semantic-application-20261108.sh' \
  -o "$ouf_public/install.sh"
(
  cd "$ouf_public"
  printf '%s  %s\n' \
    'a60efbfd90f386ab7718dca9a3b5b8daa448122629edf318631f91af6ea3d8bd' \
    install.sh | sha256sum -c -
)
OUF_SEMANTIC_CANDIDATE_ZIP="$ouf_public/candidate.zip" bash "$ouf_public/install.sh"
