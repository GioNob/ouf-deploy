#!/usr/bin/env bash
# Exact pregrant continuation; preserve prior effects and receipts, fresh HUMAN review, new finite window.
set -euo pipefail
umask 077
OUF_COHORT_COMMIT=4a65b9326c15d9758ecba1793965617a2a92e43e
OUF_COHORT_LAUNCHER_SHA=4b6f30144055af38978f04d6eef16ddab134a890b0dcee460261ec28de5ca3dd
OUF_COHORT_ARCHIVE="$HOME/ouf-chatbot-file-delivery-126e49f3830667934bf8f8d7/cohort/cohort.zip"
OUF_COHORT_GH="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [[ ! -x "$OUF_COHORT_GH" ]]; then
  OUF_COHORT_GH="$(command -v gh || true)"
fi
[[ -x "$OUF_COHORT_GH" ]] || { printf 'GH_UNAVAILABLE_NO_SUDO_EXECUTED\n' >&2; exit 1; }
[[ -f "$OUF_COHORT_ARCHIVE" && ! -L "$OUF_COHORT_ARCHIVE" ]] || {
  printf 'EXISTING_COHORT_ARCHIVE_UNAVAILABLE_NO_SUDO_EXECUTED\n' >&2
  exit 1
}
for OUF_COHORT_PROGRAM in python3 sha256sum base64 mktemp; do
  command -v "$OUF_COHORT_PROGRAM" >/dev/null
done
OUF_COHORT_STAGE="$(mktemp -d "$HOME/ouf-file-cohort-prepare-launch.XXXXXXXX")"
"$OUF_COHORT_GH" api \
  "repos/GioNob/ouf-deploy/contents/scripts/deliver-chatbot-file-cohort.py?ref=$OUF_COHORT_COMMIT" \
  --jq '.content' > "$OUF_COHORT_STAGE/launcher.b64"
base64 --decode "$OUF_COHORT_STAGE/launcher.b64" > "$OUF_COHORT_STAGE/deliver.py"
printf '%s  %s\n' "$OUF_COHORT_LAUNCHER_SHA" "$OUF_COHORT_STAGE/deliver.py" | sha256sum --check
# Natural expiration only: no revoke, reset, service operation or authority issuance.
OUF_PREVIOUS_WINDOW_EXPIRES=1792056838
while :; do
  OUF_PREVIOUS_WAIT=$((OUF_PREVIOUS_WINDOW_EXPIRES - $(date +%s)))
  (( OUF_PREVIOUS_WAIT > 0 )) || break
  (( OUF_PREVIOUS_WAIT <= 3600 )) || { printf 'HOST_CLOCK_REVIEW_REQUIRED_NO_PREPARATION_STARTED\n' >&2; exit 1; }
  printf 'Attendo la scadenza della finestra precedente: %s secondi. Preparazione non ancora avviata.\n' "$OUF_PREVIOUS_WAIT"
  (( OUF_PREVIOUS_WAIT > 30 )) && OUF_PREVIOUS_WAIT=30
  sleep "$OUF_PREVIOUS_WAIT"
done
python3 "$OUF_COHORT_STAGE/deliver.py" --source-commit "$OUF_COHORT_COMMIT" \
  --package-archive "$OUF_COHORT_ARCHIVE"
