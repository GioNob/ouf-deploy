#!/usr/bin/env bash
# Complete readonly diagnosis, then fresh native V11 plan preparation only.
(
  set -euo pipefail
  umask 077
  OUF_DIR=not_created
  OUF_PHASE=DOWNLOAD_AND_VERIFY_BOTH_IMMUTABLE_LAUNCHERS
  trap 'OUF_CODE=$?; printf "OUF_NATIVE_V11_RESUME_EXIT=%s PHASE=%s OUTPUT=%s\n" "$OUF_CODE" "$OUF_PHASE" "$OUF_DIR"' EXIT
  OUF_GH="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
  if [ ! -x "$OUF_GH" ]; then OUF_GH="$(command -v gh || true)"; fi
  if [ -z "$OUF_GH" ] || [ ! -x "$OUF_GH" ]; then echo OUF_EXISTING_GITHUB_CLIENT_REQUIRED >&2; exit 1; fi
  OUF_DIR="$(mktemp -d "$HOME/ouf-native-v11-resume.XXXXXXXX")"
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/releases/r12-readiness-diagnosis-20261011.sh?ref=5aaa0dc3868402a9cd8b700a299c4446af81d51f' > "$OUF_DIR/diagnosis.sh"
  printf '%s  %s\n' '065827b52477ab65e88cfd82e9d77bb75990aa3387c26a567e9cadf2ea1e95f8' "$OUF_DIR/diagnosis.sh" | sha256sum -c -
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/releases/native-v11-plan-20261011.sh?ref=ac89844d6cc2cd4412a1183ce52a601dcafe6f4d' > "$OUF_DIR/plan.sh"
  printf '%s  %s\n' '69ef01ee15cd42c77337604f8142a4b9935cbfba0e0cc96eef979f7e3146b752' "$OUF_DIR/plan.sh" | sha256sum -c -
  OUF_PHASE=COMPLETE_READ_ONLY_PROTECTED_R12_DIAGNOSIS
  bash "$OUF_DIR/diagnosis.sh" | tee "$OUF_DIR/diagnosis.txt"
  OUF_PHASE=REQUIRE_CURRENT_DIAGNOSTIC_READINESS_NO_TRANSITION_AUTHORITY
  /usr/bin/python3 -I -B -c '
import json,sys
with open(sys.argv[1],"rb") as stream:
    raw=stream.read(2000001)
if len(raw)>2000000:raise SystemExit("OUF_BOUNDED_DIAGNOSTIC_REQUIRED")
rows=[line.split(b"=",1)[1] for line in raw.splitlines() if line.startswith(b"OUF_R12_READINESS_DIAGNOSIS=")]
if len(rows)!=1:raise SystemExit("OUF_EXACT_DIAGNOSTIC_RECEIPT_REQUIRED")
v=json.loads(rows[0])
checks={"schemaMatches","leaseActive","stateActive","ready","incidentMatches","applyReplayDisabled","startNotAuthorized","twoRenewalsObserved","workerPidPresent"}
ready=v.get("schema")=="ouf.r12-protected-readiness-diagnosis.v1" and v.get("status")=="R12_PRIVATE_READINESS_AND_BUDGET_CAPTURED_NO_RECOVERY_AUTHORITY"
for key in ("workerReadinessChecks","workerReadinessChecksAfter"):
    c=v.get(key)
    ready=ready and type(c) is dict and set(c)==checks and all(value is True for value in c.values())
for key in ("hostBootMatches","invocationBootMatches","invocationContextMatches","invocationPidMatchesWorker","journalContextMatchesAuthorization","journalGenerationMatchesAuthorization","serviceInvocationBindingsMatch"):
    ready=ready and v.get(key) is True
for key in ("revocationMarkerPresent","workerDenialPresent","budgetReset","diagnosisGrantsRecoveryAuthority","productionApplyReady","applicationCutoverAuthorized"):
    ready=ready and v.get(key) is False
s=v.get("service",{})
ready=ready and s.get("LoadState")=="loaded" and s.get("ActiveState")=="active" and s.get("SubState")=="running" and s.get("Restart")=="no" and s.get("NRestarts")=="0"
if not ready:raise SystemExit("OUF_DIAGNOSTIC_READY_OBSERVATION_REQUIRED_NO_PLAN_PREPARATION")
print("OUF_NATIVE_V11_RESUME_READINESS_OBSERVED_NO_TRANSITION_AUTHORITY=true")
' "$OUF_DIR/diagnosis.txt"
  # The unchanged sealed preparer must independently revalidate current custody.
  OUF_PHASE=PREPARE_FRESH_NATIVE_V11_PRIVATE_PLAN_NO_APPLICATION_APPLY
  bash "$OUF_DIR/plan.sh" | tee "$OUF_DIR/plan.txt"
)
