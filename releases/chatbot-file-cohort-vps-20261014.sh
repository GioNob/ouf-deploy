#!/usr/bin/env bash
# Corrected exact source; reuse the operator's previously verified archive.
# Current preflight and complete private terminal review precede authority.
set -euo pipefail
umask 077

OUF_COHORT_COMMIT=9f76141e4b689fa86b332b5b83cac823a87bf912
OUF_COHORT_LAUNCHER_SHA=eadb7093d04fcfad9c8f2e1baa95676ea32d76a763604f0267e682ce3ece674e
OUF_COHORT_ARCHIVE="$HOME/ouf-chatbot-file-delivery-126e49f3830667934bf8f8d7/cohort/cohort.zip"
OUF_COHORT_GH="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [[ ! -x "$OUF_COHORT_GH" ]]; then
  OUF_COHORT_GH="$(command -v gh)" || { echo 'EXISTING_GH_UNAVAILABLE_NO_SUDO_EXECUTED' >&2; exit 1; }
fi
[[ -f "$OUF_COHORT_ARCHIVE" && ! -L "$OUF_COHORT_ARCHIVE" ]] || {
  echo 'EXISTING_COHORT_ARCHIVE_UNAVAILABLE_NO_SUDO_EXECUTED' >&2
  exit 1
}
for OUF_COHORT_PROGRAM in python3 sha256sum base64 mktemp; do
  command -v "$OUF_COHORT_PROGRAM" >/dev/null
done
OUF_COHORT_STAGE="$(mktemp -d "$HOME/ouf-file-cohort-admin-launch.XXXXXXXX")"
"$OUF_COHORT_GH" api "repos/GioNob/ouf-deploy/contents/scripts/deliver-chatbot-file-cohort.py?ref=$OUF_COHORT_COMMIT" \
  --jq '.content' > "$OUF_COHORT_STAGE/launcher.b64"
base64 --decode "$OUF_COHORT_STAGE/launcher.b64" > "$OUF_COHORT_STAGE/deliver.py"
printf '%s  %s\n' "$OUF_COHORT_LAUNCHER_SHA" "$OUF_COHORT_STAGE/deliver.py" | sha256sum --check
python3 "$OUF_COHORT_STAGE/deliver.py" --source-commit "$OUF_COHORT_COMMIT" \
  --package-archive "$OUF_COHORT_ARCHIVE"
