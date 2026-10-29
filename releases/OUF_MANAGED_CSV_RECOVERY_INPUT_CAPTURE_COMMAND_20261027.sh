(
  set -Eeuo pipefail
  umask 077
  ouf_csv_capture_bootstrap=$(mktemp -d "$HOME/ouf-csv-recovery-bootstrap.XXXXXXXX")
  printf 'BootstrapDirectory=%s\n' "$ouf_csv_capture_bootstrap"
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 3 --connect-timeout 15 --max-time 60 \
    "https://raw.githubusercontent.com/GioNob/ouf-deploy/80b133705a00d5e643527d603205a906a1e05863/releases/capture-managed-csv-recovery-inputs-20261027.sh" \
    -o "$ouf_csv_capture_bootstrap/run.sh"
  printf '%s  %s\n' 'e1051003978685c47eee28a3b0f373e47033244783bc720bb868f54462e91ab8' "$ouf_csv_capture_bootstrap/run.sh" | sha256sum -c -
  chmod 0400 "$ouf_csv_capture_bootstrap/run.sh"
  /usr/bin/bash "$ouf_csv_capture_bootstrap/run.sh"
)
