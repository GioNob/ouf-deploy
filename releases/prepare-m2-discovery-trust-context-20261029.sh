#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
[[ $# = 0 ]] || { printf '%s\n' 'NO_ARGUMENTS_SUPPORTED' >&2; exit 1; }
if [[ "$(id -un)" != oufadmin ]]; then
  printf '%s\n' 'OUFADMIN_ACCOUNT_REQUIRED' >&2
  exit 1
fi
if [[ ! -t 0 || ! -t 1 ]]; then
  printf '%s\n' 'INTERACTIVE_SSH_TTY_REQUIRED_BEFORE_DOWNLOAD_OR_SCOPE' >&2
  exit 1
fi
delivery=$(mktemp -d "$HOME/ouf-m2-discovery-trust-context-delivery.XXXXXXXX")
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
  --max-redirs 3 --connect-timeout 15 --max-time 60 --max-filesize 131072 \
  'https://raw.githubusercontent.com/GioNob/ouf-deploy/21c6c2f0e3563b11bfefb58419fefb7ecb461c50/releases/m2-discovery-trust-context-20261029.py' \
  -o "$delivery/prepare.py"
printf '%s  %s\n' 'c0df0cc0c9a24850c69ecfd18709b7f657bfef93f6cec7dfa17fb92e2be4bd92' "$delivery/prepare.py" | sha256sum -c -
chmod 0400 "$delivery/prepare.py"
sudo -v
set +e
sudo /usr/bin/bash -s -- "$delivery/prepare.py" <<'ROOT' 2>&1 | tee "$delivery/bootstrap.log"
set -Eeuo pipefail
umask 077
candidate=$1
scope='/etc/ouf/deploy-snapshots/m2-discovery-trust-context-68daa9c9-20261029-v1'
code_root='/usr/local/lib/ouf-m2-discovery-trust-context-c0df0cc0c9a24850'
if [[ -e "$scope" || -L "$scope" ]]; then
  printf '%s\n' 'TRUST_CONTEXT_PREPARATION_SCOPE_CONSUMED_NO_REPLAY' >&2
  exit 1
fi
[[ ! -L "$code_root" ]]
if [[ ! -e "$code_root" ]]; then
  install -d -m 0700 -o root -g root "$code_root"
fi
[[ "$(stat -c '%u:%g:%a' "$code_root")" = 0:0:700 ]]
if [[ ! -e "$code_root/prepare.py" && ! -L "$code_root/prepare.py" ]]; then
  install -m 0400 -o root -g root -- "$candidate" "$code_root/prepare.py"
fi
[[ ! -L "$code_root/prepare.py" ]]
[[ "$(stat -c '%u:%g:%a' "$code_root/prepare.py")" = 0:0:400 ]]
printf '%s  %s\n' 'c0df0cc0c9a24850c69ecfd18709b7f657bfef93f6cec7dfa17fb92e2be4bd92' "$code_root/prepare.py" | sha256sum -c -
[[ ! -e "$code_root/operator.log" && ! -L "$code_root/operator.log" ]] || {
  printf '%s\n' 'PROTECTED_TRUST_CONTEXT_INVOCATION_ALREADY_ATTEMPTED_NO_REPLAY' >&2
  exit 1
}
printf '%s\n' "ProtectedCode=$code_root/prepare.py"
set +e
env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin /usr/bin/python3 -I -B -S "$code_root/prepare.py" \
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
