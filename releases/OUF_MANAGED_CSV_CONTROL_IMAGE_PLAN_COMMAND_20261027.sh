(
  set -Eeuo pipefail
  umask 077
  ouf_control_plan_bootstrap=$(mktemp -d "$HOME/ouf-control-plan-bootstrap.XXXXXXXX")
  printf 'BootstrapDirectory=%s\n' "$ouf_control_plan_bootstrap"
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 3 --connect-timeout 15 --max-time 60 \
    "https://raw.githubusercontent.com/GioNob/ouf-deploy/d872420c44bf6ca2bdc0055201c8c332ae0f09da/releases/prepare-managed-csv-control-image-plan-20261027.sh" \
    -o "$ouf_control_plan_bootstrap/run.sh"
  printf '%s  %s\n' 'f67c8fafe4fe4c853c411c13e6fa9f35a8e616b18c8cdefc3d96928f3c8b814e' "$ouf_control_plan_bootstrap/run.sh" | sha256sum -c -
  chmod 0400 "$ouf_control_plan_bootstrap/run.sh"
  /usr/bin/bash "$ouf_control_plan_bootstrap/run.sh"
)
