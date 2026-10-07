#!/usr/bin/env bash
set -euo pipefail
umask 077
test "$(id -un)" = "oufadmin" || { echo "Eseguire come oufadmin."; exit 1; }
test "$(uname -s)" = "Linux" && test "$(uname -m)" = "x86_64"
command -v python3 >/dev/null
command -v curl >/dev/null
oufRunnerDir="$HOME/ouf-deploy-runner"
test ! -L "$oufRunnerDir"
mkdir -p "$oufRunnerDir"
cd "$oufRunnerDir"
if test ! -x ./config.sh; then
  oufArchive="actions-runner-linux-x64-2.337.0.tar.gz"
  curl -fL --retry 2 --connect-timeout 15 --max-time 180 -o "$oufArchive" "https://github.com/actions/runner/releases/download/v2.337.0/$oufArchive"
  printf '%s\n' "70920811a4f8ad4328818682bca5c6469c1c942fab52448868071d0063816613  $oufArchive" | sha256sum -c -
  tar -xzf "$oufArchive"
fi
if test ! -f .runner; then
  test -n "${OUF_RUNNER_REGISTRATION_TOKEN:-}" || { echo "TOKEN_REGISTRAZIONE_MANCANTE"; exit 1; }
  ./config.sh --unattended --url https://github.com/GioNob/ouf-deploy --token "$OUF_RUNNER_REGISTRATION_TOKEN" --name ouf-vps-test --labels ouf-vps-test --work _work
fi
unset OUF_RUNNER_REGISTRATION_TOKEN
python3 - <<'OUF_CHECK_BINDING'
import json
from pathlib import Path
data = json.loads(Path(".runner").read_text())
if data.get("agentName") != "ouf-vps-test" or data.get("gitHubUrl", "").rstrip("/") != "https://github.com/GioNob/ouf-deploy":
    raise SystemExit("RUNNER_BINDING_DIVERSO: nessun servizio modificato.")
print("RUNNER_BINDING=PASS")
OUF_CHECK_BINDING
sudo -v
if test ! -f .service; then
  sudo ./svc.sh install oufadmin
fi
sudo ./svc.sh start
oufUnit="$(cat .service)"
sudo systemctl is-active --quiet "$oufUnit"
echo "OUF_RUNNER_SERVICE=ACTIVE"
echo "CONTAINER_OPERATIONS=0"
