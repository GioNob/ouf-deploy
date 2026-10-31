(
  set -Eeuo pipefail
  umask 077
  ouf_profile_apply_bootstrap=$(mktemp -d "$HOME/ouf-profile-v36-apply-bootstrap.XXXXXXXX")
  printf 'BootstrapDirectory=%s\n' "$ouf_profile_apply_bootstrap"
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 3 --connect-timeout 15 --max-time 60 \
    "https://raw.githubusercontent.com/GioNob/ouf-deploy/2f04dff7438b0f59c94e341d9c946f9098ba67ef/releases/apply-onboarding-profile-recovery-update-20261027.sh" \
    -o "$ouf_profile_apply_bootstrap/run.sh"
  printf '%s  %s\n' 'dc1d4312f770f2dd4b95672060d189161344dbfd0e4f454ab6a32bf69bc03c07' "$ouf_profile_apply_bootstrap/run.sh" | sha256sum -c -
  chmod 0400 "$ouf_profile_apply_bootstrap/run.sh"
  /usr/bin/bash "$ouf_profile_apply_bootstrap/run.sh"
)
