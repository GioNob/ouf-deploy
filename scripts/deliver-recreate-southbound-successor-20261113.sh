#!/usr/bin/env bash
set -euo pipefail
umask 077

# Claude replaces these two pins after review and commit (D-001).
commit='__PIN_COMMIT__'
controller_sha='__PIN_CONTROLLER_SHA256__'
[[ "$commit" =~ ^[0-9a-f]{40}$ && "$controller_sha" =~ ^[0-9a-f]{64}$ ]]
python_sha='889c603f0d17cb54060951bcf4c4f9b8c9ebd9e52b392c70209bbb9755d797d9'
printf '%s  %s\n' "$python_sha" /usr/bin/python3.13 | sudo sha256sum --check --status

work=$(sudo mktemp -d /var/tmp/ouf-southbound-recreate.XXXXXXXX)
sudo chmod 0700 "$work"
trap 'printf "OUF_SOUTHBOUND_RECREATE_DELIVERY=%s\n" "$work"' EXIT
url="https://raw.githubusercontent.com/GioNob/ouf-deploy/$commit/scripts/recreate-southbound-successor-20261113.py"
sudo curl --fail --silent --show-error --max-time 30 --proto '=https' --tlsv1.2 \
  "$url" -o "$work/recreate-southbound-successor-20261113.py"
sudo chmod 0600 "$work/recreate-southbound-successor-20261113.py"
printf '%s  %s\n' "$controller_sha" "$work/recreate-southbound-successor-20261113.py" \
  | sudo sha256sum --check --status
printf '%s  %s\n' "$python_sha" /usr/bin/python3.13 | sudo sha256sum --check --status
sudo /usr/bin/python3.13 -I -B "$work/recreate-southbound-successor-20261113.py" "$@"
