#!/usr/bin/env bash
# Immutable unsigned artifact delivery. No sudo or Docker/runtime operation.
set -euo pipefail
umask 077
PHASE=CLIENT_BINDING
STAGE=UNCREATED
blocked() {
  code=$?
  trap - ERR
  printf 'OUF_SEMANTIC_CANDIDATE_STAGE={"status":"BLOCKED","phase":"%s","reason":"DELIVERY_OR_VERIFICATION_FAILED","exitCode":%s,"evidenceLocation":"%s","automaticRetry":false,"targetApplyAuthorized":false}\n' "$PHASE" "$code" "$STAGE"
  exit "$code"
}
trap blocked ERR
GH="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [[ ! -x "$GH" ]]; then
  GH="$(command -v gh)"
fi
[[ -x "$GH" ]]
command -v python3 >/dev/null
command -v base64 >/dev/null
command -v sha256sum >/dev/null
command -v timeout >/dev/null
PHASE=PRIVATE_STAGING_DIRECTORY
STAGE="$(mktemp -d "$HOME/ouf-semantic-candidates-20261014.XXXXXXXX")"
python3 - "$STAGE" <<'PY'
import shutil,sys
if shutil.disk_usage(sys.argv[1]).free < 1073741824:
    raise SystemExit('INSUFFICIENT_STAGING_SPACE')
PY
PHASE=PINNED_VERIFIER_DOWNLOAD
timeout 60s "$GH" api 'repos/GioNob/ouf-deploy/contents/scripts/verify-semantic-proposal-candidate-archive.py?ref=506f2f4bf9980cb801908abb5f7fd9f954b9b191' --jq .content 2>/dev/null | base64 --decode > "$STAGE/verify.py"
printf '%s  %s\n' b42b3ad520251e2d2bd179c63915f14bf31a47692588b42e55628f384ef096d7 "$STAGE/verify.py" | sha256sum -c - >/dev/null
for MODULE in semantic mcp gateway; do
  case "$MODULE" in
    semantic) ARTIFACT=11868169115; DIGEST=78954f106ea1248c624bf71596785af0b2980480cd58020eb0accd5d1f2df1c6 ;;
    mcp) ARTIFACT=11868243649; DIGEST=6db692b78f1fde7bc3a30a8727afd4f581b2f8574f00c2fc117b71ea59b2aab4 ;;
    gateway) ARTIFACT=11868323361; DIGEST=74b4f974adf74401cd592df26ce62dbea9399c8c025b124ee0e11e6d06f9d73a ;;
  esac
  PHASE="ARCHIVE_DOWNLOAD_$MODULE"
  timeout 180s "$GH" api "repos/GioNob/ouf-deploy/actions/artifacts/$ARTIFACT/zip" > "$STAGE/$MODULE.zip" 2>/dev/null
  PHASE="ARCHIVE_VERIFY_$MODULE"
  printf '%s  %s\n' b42b3ad520251e2d2bd179c63915f14bf31a47692588b42e55628f384ef096d7 "$STAGE/verify.py" | sha256sum -c - >/dev/null
  timeout 60s python3 "$STAGE/verify.py" --module "$MODULE" --archive "$STAGE/$MODULE.zip" --sha256 "$DIGEST" > "$STAGE/$MODULE-receipt.json"
done
PHASE=STAGING_COMPLETE
python3 - "$STAGE" <<'PY'
import json,pathlib,sys
root=pathlib.Path(sys.argv[1])
receipts=[json.loads((root/(module+'-receipt.json')).read_text()) for module in ('semantic','mcp','gateway')]
report=dict(schema='ouf.semantic-proposal-candidate-stage.v1',status='UNSIGNED_PACKAGES_VERIFIED_NOT_APPLY_READY',
            evidenceLocation=str(root),receipts=receipts,targetApplyAuthorized=False,notReleaseAcceptance=True,
            vpsRuntimeOperations=0,privateKeyReads=0,signaturesIssued=0,budgetReset=False,r12Touched=False)
(root/'stage-receipt.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
print('OUF_SEMANTIC_CANDIDATE_STAGE='+json.dumps(report,sort_keys=True))
PY
