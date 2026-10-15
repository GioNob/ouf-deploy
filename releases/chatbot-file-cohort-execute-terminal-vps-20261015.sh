#!/usr/bin/env bash
# Exact qualified source: fresh full review, explicit terminal HUMAN approval, then finite execution.
set -euo pipefail
umask 077
OUF_COHORT_COMMIT=6959b1dbaeb30ca3a838c7d6243a55e9cfc5118a
OUF_COHORT_LAUNCHER_SHA=2fae09635e3c8ba6770a267dcc512e143ce5cb4f89ca218ce396d64d9e6a1d77
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
python3 "$OUF_COHORT_STAGE/deliver.py" --source-commit "$OUF_COHORT_COMMIT" \
  --package-archive "$OUF_COHORT_ARCHIVE"
