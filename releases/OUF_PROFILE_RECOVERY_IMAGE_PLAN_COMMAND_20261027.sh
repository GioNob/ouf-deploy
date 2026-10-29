(
  set -Eeuo pipefail
  umask 077
  ouf_profile_plan_bootstrap=$(mktemp -d "$HOME/ouf-profile-plan-bootstrap.XXXXXXXX")
  exec > >(tee -a "$ouf_profile_plan_bootstrap/bootstrap.log") 2>&1
  printf 'BootstrapDirectory=%s\n' "$ouf_profile_plan_bootstrap"
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 3 --connect-timeout 15 --max-time 60 \
    "https://raw.githubusercontent.com/GioNob/ouf-deploy/d015550c6fa8358e1f22a685f324b125b53c4c30/releases/prepare-onboarding-profile-recovery-image-plan-20261027.sh" \
    -o "$ouf_profile_plan_bootstrap/run.sh"
  printf '%s  %s\n' '672d161a773cceeaff04223f67aded3e2576add9d6cea03cc733ace5fd7a7845' "$ouf_profile_plan_bootstrap/run.sh" | sha256sum -c -
  chmod 0400 "$ouf_profile_plan_bootstrap/run.sh"
  /usr/bin/bash "$ouf_profile_plan_bootstrap/run.sh"
)
