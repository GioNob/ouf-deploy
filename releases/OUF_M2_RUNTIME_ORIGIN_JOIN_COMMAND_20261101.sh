(
  set -euo pipefail
  umask 077
  ouf_origin_join_tmp=$(mktemp -d)
  trap 'rm -rf -- "$ouf_origin_join_tmp"' EXIT
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 3 \
    --tlsv1.2 --connect-timeout 10 --max-time 30 --retry 0 --max-filesize 16384 \
    https://raw.githubusercontent.com/GioNob/ouf-deploy/d51807fed8edc2d66a3e5a5bbde51834547184c7/scripts/launch-m2-retained-runtime-origins-20261101.sh \
    --output "$ouf_origin_join_tmp/run.sh"
  printf '%s  %s\n' b50d274cfdfa59848a99e2b1f8713c88e2c5ac45d77c67e9a106871cbda07b10 "$ouf_origin_join_tmp/run.sh" | sha256sum --check --strict
  sudo -v
  set +e
  bash "$ouf_origin_join_tmp/run.sh"
  ouf_origin_join_exit=$?
  set -e
  printf 'RuntimeOriginJoinExit=%s\n' "$ouf_origin_join_exit"
  exit "$ouf_origin_join_exit"
)
