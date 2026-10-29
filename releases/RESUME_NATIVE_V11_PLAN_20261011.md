# Resume native V11 private-plan preparation — 11 October 2026

At the operator's23:10:34 CEST submission, the protected R12 observation reports LEASE_ACTIVE / ACTIVE / RENEWED, ready=true and all nine readiness predicates passing. PID2446150 is bound to the retained invocation and boot; claim/capsule/journal context and generation match; no revocation marker or worker denial is present. Attempts12, publicationCount1874, renewals1862 and recoveryBudgetRemainingSeconds78133.94129681587. This is a point-in-time worker observation; the diagnostic did not complete its native-service and final rereads. [Operator checkpoint](../evidence/r12-readiness-native-scope-blocked-target-20261011.json).

The diagnostic itself failed at EXACT_READ_ONLY_NATIVE_SCOPE_REQUIRED. Its systemctl properties included Result, ExecMainCode and ExecMainStatus, outside the retained helper's exact readonly scope. The correction requests precisely LoadState,ActiveState,SubState,MainPID,Restart,NRestarts,ExecStart. Neither the scope guard nor application readiness requirements are widened. Two regression tests execute the corrected call through the actual sealed prepare.native helper and reject the original expanded call before any subprocess. Earlier worker readiness failure remains a historical observation; its specific transient cause is not proven by this later active snapshot.

## One concrete operation

The resume launcher hashes both immutable child launchers before executing either. It completes the corrected root diagnostic; requires both nine-predicate worker observations, current boot/context/generation/invocation/service bindings, no revocation/denial, no restart and no authority flags; then invokes the already qualified, unchanged native V11 preparer. The diagnostic is observation evidence only. The preparer independently validates current application/input/lease/image/journal custody, freshly verifies the eight original publisher subjects and only after successful final checks creates four NEW root-owned private review documents. It never imports an image, writes the import journal, resets recovery budgets, creates a transition claim, restarts R12, changes the firewall, runs database/provider calls or applies an application cutover.

Any diagnostic, readiness gate or plan failure stops the sequence; exit codes and safe receipts are preserved. A changing healthy worker/journal during the diagnostic is explicitly reported, not represented as atomic transition authority. Plan freshness and lease validity are enforced independently by the preparer.

| Immutable artifact | Commit | SHA256 |
|---|---|---|
| Corrected diagnostic program | 57296c0eb1a8cb5c8bfc371a1bf201a39763f94a | d52fa8752dd9d37c3d950c9781ec00be1f9d8a173325049ce7eb43ceff1a607e |
| Corrected diagnostic launcher | 5aaa0dc3868402a9cd8b700a299c4446af81d51f | 065827b52477ab65e88cfd82e9d77bb75990aa3387c26a567e9cadf2ea1e95f8 |
| Original unchanged native plan launcher | ac89844d6cc2cd4412a1183ce52a601dcafe6f4d | 69ef01ee15cd42c77337604f8142a4b9935cbfba0e0cc96eef979f7e3146b752 |
| Resume launcher | 296ebbffa32633a67d9b1f520c6d19dfb641a576 | 20932811bfdeddfdd1c268759cee448b77a31e445bdfa43437f1c41e75a00f7f |

[CI38175477875](https://github.com/GioNob/ouf-deploy/actions/runs/38175477875), job114576853230 SUCCESS:19 corrected diagnosis/delivery/resume tests plus9 existing custody tests. Complete orchestration is tested with isolated child fixtures: diagnosis failure never reaches the plan, readiness failure never reaches the plan, plan failures propagate, successful gating reaches only the fresh plan child. Download/digest failure in either child prevents execution of both. [Qualification receipt](../evidence/native-v11-resume-qualified-20261011.json). Hosted fixtures establish code behavior; the corrected root operation and new native private plan remain pending on the VPS.

Root access is unavailable to the runner, so run the sealed operation once as oufadmin:

```bash
(
  set -euo pipefail
  umask 077
  OUF_GH="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
  if [ ! -x "$OUF_GH" ]; then OUF_GH="$(command -v gh)"; fi
  OUF_LAUNCH="$(mktemp "$HOME/ouf-native-v11-resume-launch.XXXXXXXX")"
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/releases/resume-native-v11-plan-20261011.sh?ref=296ebbffa32633a67d9b1f520c6d19dfb641a576' > "$OUF_LAUNCH"
  printf '%s  %s\n' '20932811bfdeddfdd1c268759cee448b77a31e445bdfa43437f1c41e75a00f7f' "$OUF_LAUNCH" | sha256sum -c -
  bash "$OUF_LAUNCH"
)
```

Return the safe OUF_R12_READINESS_DIAGNOSIS, OUF_CURRENT_NATIVE_V11_PLAN and launcher/resume exit lines. Do not publish private files or signature payloads. Four plan files are draft evidence, not atomic snapshot publication, full realized OCI proof, transport closure or application authority. The existing VERIFIED native-image import record, original package/config/layers and cumulative R12 budget remain retained. CSV Teatri→ACK→search acceptance remains OPEN.
