#!/usr/bin/env bash
set -euo pipefail
umask 077

# Claude fills these pins after review and commit (D-001).
ouf_commit='0324c25082c106b9405b072d830e089f70016b8a'
ouf_controller_sha='7046b6e9a09d2e7ff0667ab15f5a8208445d6a8ead9161e5f8800677f2b3ba68'
if [[ ! "$ouf_commit" =~ ^[0-9a-f]{40}$ || ! "$ouf_controller_sha" =~ ^[0-9a-f]{64}$ ]]; then
  printf '%s\n' 'Pin commit/controller A2 non compilati: consegna non eseguibile.' >&2
  exit 2
fi
case "${1-}" in
  --plan|--apply) ;;
  *) printf '%s\n' 'Uso: --plan ARGOMENTI oppure --apply --plan-sha256 HASH ARGOMENTI' >&2; exit 2 ;;
esac

ouf_repo='https://raw.githubusercontent.com/GioNob/ouf-deploy'
ouf_controller='prepare-semantic-provider-a2-20261113.py'
# Root custody prevents replacement between checksum and privileged execution.
ouf_work=$(sudo mktemp -d /var/tmp/ouf-semantic-provider-a2.XXXXXXXX)
sudo chmod 0700 "$ouf_work"
trap 'printf "OUF_SEMANTIC_PROVIDER_A2_DELIVERY=%s\n" "$ouf_work" >&2' EXIT

ouf_fetch() {
  local file=$1 expected=$2
  sudo curl --fail --silent --show-error --max-time 30 --proto '=https' --tlsv1.2 \
    "$ouf_repo/$ouf_commit/scripts/$file" -o "$ouf_work/$file"
  sudo chmod 0600 "$ouf_work/$file"
  printf '%s  %s\n' "$expected" "$ouf_work/$file" | sudo sha256sum --check --status
}

ouf_fetch "$ouf_controller" "$ouf_controller_sha"
ouf_fetch cutover-semantic-provider-20261111.py ec69f0d86d337596ad562078eee18f87189310bb08f44a4f2b3550122b0366d9
ouf_fetch upgrade-semantic-application-20261108.py 2e7e7e42367b3329f6ebd441bba665f974ea43871049d863415524610138efb1

sudo /usr/bin/python3.13 -I -B "$ouf_work/$ouf_controller" "$@"
