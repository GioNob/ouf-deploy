#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
if [[ "$(id -un)" != oufadmin ]]; then
  printf '%s\n' 'OUFADMIN_ACCOUNT_REQUIRED' >&2
  exit 1
fi
if [[ ! -t 0 || ! -t 1 ]]; then
  printf '%s\n' 'INTERACTIVE_SSH_TTY_REQUIRED_BEFORE_DOWNLOAD_OR_SCOPE' >&2
  exit 1
fi
delivery=$(mktemp -d "$HOME/ouf-m2-discovery-custody-delivery.XXXXXXXX")
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
  --max-redirs 3 --connect-timeout 15 --max-time 60 --max-filesize 131072 \
  'https://raw.githubusercontent.com/GioNob/ouf-deploy/bab8d63a6d8e47cf0ae6ff0dc15841009748b417/tools/m2_discovery_installation_profile/custody_capture.py' \
  -o "$delivery/capture.py"
printf '%s  %s\n' '834dd9b0b7e9f7b02fc07c7080f6d3e51cc7b7fd541691f26942e136a08c00cf' "$delivery/capture.py" | sha256sum -c -
chmod 0400 "$delivery/capture.py"
sudo -v
set +e
sudo /usr/bin/bash -s -- "$delivery/capture.py" <<'ROOT' 2>&1 | tee "$delivery/bootstrap.log"
set -Eeuo pipefail
umask 077
candidate=$1
scope='/etc/ouf/deploy-snapshots/m2-discovery-custody-f759d397-20261029-v1'
code_root='/usr/local/lib/ouf-m2-discovery-custody-834dd9b0b7e9f7b0'
if [[ -e "$scope" || -L "$scope" ]]; then
  printf '%s\n' 'CUSTODY_CAPTURE_SCOPE_CONSUMED_NO_REPLAY' >&2
  exit 1
fi
[[ ! -L "$code_root" ]]
if [[ ! -e "$code_root" ]]; then
  install -d -m 0700 -o root -g root "$code_root"
fi
[[ "$(stat -c '%u:%g:%a' "$code_root")" = 0:0:700 ]]
if [[ ! -e "$code_root/capture.py" && ! -L "$code_root/capture.py" ]]; then
  install -m 0400 -o root -g root -- "$candidate" "$code_root/capture.py"
fi
[[ ! -L "$code_root/capture.py" ]]
[[ "$(stat -c '%u:%g:%a' "$code_root/capture.py")" = 0:0:400 ]]
printf '%s  %s\n' '834dd9b0b7e9f7b02fc07c7080f6d3e51cc7b7fd541691f26942e136a08c00cf' "$code_root/capture.py" | sha256sum -c -
printf '%s\n' "ProtectedCode=$code_root/capture.py"
set +e
env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin /usr/bin/python3 -I -B -S "$code_root/capture.py" \
  2>&1 | tee "$code_root/operator.log"
capture_exit=${PIPESTATUS[0]}
set -e
printf 'OperatorExit=%s\nOperatorLog=%s\n' "$capture_exit" "$code_root/operator.log"
exit "$capture_exit"
ROOT
delivery_exit=${PIPESTATUS[0]}
set -e
printf 'DeliveryExit=%s\nDeliveryDirectory=%s\nDeliveryLog=%s\n' "$delivery_exit" "$delivery" "$delivery/bootstrap.log"
exit "$delivery_exit"
