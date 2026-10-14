#!/usr/bin/env bash
# Exact reviewed source delivery. The authenticated installer asks the operator
# to review the complete current action before issuing deployment authority.
set -euo pipefail
umask 077

OUF_COHORT_COMMIT=f9b42b8cd4358a908c7a0e88777f9e55b8400258
OUF_COHORT_LAUNCHER_SHA=811b72c739d11f613288f000e00253acb62a04fa3f56a1ce6ca5300f9bbf483b
OUF_COHORT_GH="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [[ ! -x "$OUF_COHORT_GH" ]]; then
  OUF_COHORT_GH="$(command -v gh)" || { echo 'EXISTING_GH_UNAVAILABLE_NO_SUDO_EXECUTED' >&2; exit 1; }
fi
for OUF_COHORT_PROGRAM in python3 sha256sum base64 mktemp; do
  command -v "$OUF_COHORT_PROGRAM" >/dev/null
done
OUF_COHORT_STAGE="$(mktemp -d "$HOME/ouf-file-cohort-launch-20261014.XXXXXXXX")"
"$OUF_COHORT_GH" api "repos/GioNob/ouf-deploy/contents/scripts/deliver-chatbot-file-cohort.py?ref=$OUF_COHORT_COMMIT" \
  --jq '.content' > "$OUF_COHORT_STAGE/launcher.b64"
base64 --decode "$OUF_COHORT_STAGE/launcher.b64" > "$OUF_COHORT_STAGE/deliver.py"
printf '%s  %s\n' "$OUF_COHORT_LAUNCHER_SHA" "$OUF_COHORT_STAGE/deliver.py" | sha256sum --check
python3 "$OUF_COHORT_STAGE/deliver.py" --source-commit "$OUF_COHORT_COMMIT"
