#!/usr/bin/env bash
(
  set -Eeuo pipefail
  umask 077
  ouf_recovery_bootstrap=$(mktemp -d "$HOME/ouf-profile-recovery-bootstrap.XXXXXXXX")
  exec > >(tee -a "$ouf_recovery_bootstrap/bootstrap.log") 2>&1
  printf 'BootstrapDirectory=%s\n' "$ouf_recovery_bootstrap"
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 3 --connect-timeout 15 --max-time 60 \
    "https://raw.githubusercontent.com/GioNob/ouf-deploy/2981b7f009bd7072feabd78781e9b85eddfa9500/releases/capture-onboarding-profile-recovery-inputs-20261027.sh" \
    -o "$ouf_recovery_bootstrap/run.sh"
  printf '%s  %s\n' '0babe8ba8455b31e23cd768904dfdef9ccee975853bcaaa438c7da1313d99b83' "$ouf_recovery_bootstrap/run.sh" | sha256sum -c -
  chmod 0400 "$ouf_recovery_bootstrap/run.sh"
  /usr/bin/bash "$ouf_recovery_bootstrap/run.sh"
)

