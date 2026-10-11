# Current V11 plan preparation and Cinema read gap — 11 October 2026

The exact new Semantic package has passed original-archive metadata compatibility at [CI38163643730](https://github.com/GioNob/ouf-deploy/actions/runs/38163643730), job114541576962. Both original archives and image config digests are verified; execution defaults and unrelated image labels match, the runtime environment is updated while retained application environment and mandatory configtree are preserved. This hosted fixture does not read the target declaration or grant target effects.

The [sealed launcher](current-durable-v11-plan-20261011.sh) creates a new private target declaration and creation request for source8a2e84b/image83635be4, using the already staged original ZIP. It first verifies all eight source files in the operator shell and again inside isolated root. The program reuses the existing R12/native custody readers, retains the current host frame and four input additions, rereads authorization/generation/lease/frame/input/package/creation intent before any new draft publication, and leaves all apply/custody/transport flags false. No existing snapshot is overwritten, no claim/budget is created/reset, no image is imported and no DB/container/firewall/provider effect is performed. The four new files are private review artifacts, not atomic installation authority; a partial publication is retained and reported as blocked.

Local15 tests cover preservation/negative default and environment cases, all seven sealed module tamper positions before execution, all16 download/tamper positions, all8 root bootstrap tamper positions, failure propagation, nine final drift boundaries, and partial draft failure. Native original-image compatibility is separate from these simulated orchestration boundaries. [Hosted delivery CI38164130910](https://github.com/GioNob/ouf-deploy/actions/runs/38164130910), job114543027739 SUCCESS, passes all15 tests and repeats actual original-package metadata compatibility. [Qualification projection](../evidence/durable-v11-current-plan-qualified-20261011.json). The initial metadata job38163519120 rejected an extra local final newline in a checksum; corrected before any target execution, failed history retained.

## Necessary root execution

The existing runner's root path was already rejected and recorded at run38161252572. The previous current-custody reader is completed: do not repeat it, the old planner or R10/R11/R12 apply. This new launcher performs only the missing private rebind/plan preparation. It uses the retained portable gh client and existing sudo; no privilege policy change or alternate escalation is attempted.

Launcher commit: `8d044bdc4d22d7b2360d2426191a6ef95a102b60`.
Launcher SHA256: `efffc25ea0c23c72c979f1d3f5a64d35febcc9ef09520685cfca23c145d6cac0`.
Program/source commit: `6b847ef56b31118af45667b6e3137fd1336d4683`.
No target execution has yet been observed.

Run on the VPS as oufadmin, once the hosted delivery qualification below is successful:

```bash
(
  set -euo pipefail
  umask 077
  OUF_GH="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
  if [ ! -x "$OUF_GH" ]; then OUF_GH="$(command -v gh)"; fi
  OUF_LAUNCH="$(mktemp "$HOME/ouf-v11-plan-launch.XXXXXXXX")"
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/releases/current-durable-v11-plan-20261011.sh?ref=8d044bdc4d22d7b2360d2426191a6ef95a102b60' > "$OUF_LAUNCH"
  printf '%s  %s\n' 'efffc25ea0c23c72c979f1d3f5a64d35febcc9ef09520685cfca23c145d6cac0' "$OUF_LAUNCH" | sha256sum -c -
  bash "$OUF_LAUNCH"
)
```

Return only the safe `OUF_CURRENT_V11_PLAN=` receipt and launcher exit/phase/output. Private declarations, creation requests, observations and credentials are not to be printed.

## Current Cinema authorization diagnostic

Governed owner reads of roles and configured grants succeeded. Current policy `ouf-lab-authorization:38`, hash `sha256:e3fee1b85a9ef669276a1af8e190729b35bb45aaa27fb685265d12f9ce426cc7`, has63 configured grants, complete page; the nominal admin role has28 permissions. Neither includes the status/history capability pair or the owner operations/lineage capabilities needed for these reads. Existing `ingestion.run.read` is a trusted-HUMAN API capability, not an equivalent MCP read grant. [Safe diagnostic projection](../evidence/cinema-governed-lineage-read-gap-20261011.json).

This confirms a configured read-access gap. The generic runtime denial does not reveal the exact rejecting cache/descriptor/scope/owner layer. Grant listings are not effective authorization decisions. No authorization proposal or change was made.

Source inspection also establishes that existing status/history return run/source/state but no UDP object IDs. Ingestion historical lineage and UDP serving lineage have separate grants; the existing legacy UDP listing is not a complete bounded MCP lineage contract. Current generic MCP invocation does not forward source resource context, so adding a SOURCE-constrained grant alone would not complete the path. An additive owner/Gateway/MCP bounded contract and exact active descriptors/actors/scopes are needed before a finite least-privilege grant proposal. Raw lineage bytes are not requested; no alternate account or database bypass is used.

Current8-object Cinema serving is proved; exact joining of those IDs to the historical run remains open. Teatri13-row CSV acceptance, new-image target custody, transport closure, migration-aware cutover and complete resilience-v3 integration remain open.

## Target preparation blocked at final journal reread — 11 October, 20:55 CEST

The operator executed the pinned launcher. It exited1 in FINAL_STABLE_RECHECK with LEASE_JOURNAL_CHANGED_DURING_READ, protectedFileWrites0 and all target effects/claim/budget flags zero or false. [Safe operator receipt](../evidence/durable-v11-current-plan-blocked-target-20261011.json). No new private declaration or plan is proved; the previous pending target preparation is now an observed blocked attempt.

The retained lease reader uses optimistic before/after journal equality during native reads, without acquiring the common lock. A concurrent journal update invalidates that particular observation. Normal renewal is a possible explanation, not a proved benign target event; revocation/state change cannot be inferred away. The equality, positive native TTL/membership, current authorization/generation and secret/config custody guards remain intact.

A new explicit operator observation may use the SAME pinned launcher and command above: this attempt performed no protected writes or transition effects and consumed no claim. It rereads all facts from the beginning, retains the blocked evidence and does not reuse partially read lease data. This is not permission to replay R10/R11/R12, reset a provider/recovery budget, or automate repeated launches. If the journal collision repeats, retain both results and diagnose the exact read window before another attempt.

A regression reproduces the exact final-read exception and asserts immediate blocking, no internal retry, no draft publication, no claim or budget effect. Local16 tests pass; the hosted checkpoint for this added case is recorded separately. Program and launcher bytes are unchanged; no new executable trust or private authority is introduced.

Hosted regression [CI38166096436](https://github.com/GioNob/ouf-deploy/actions/runs/38166096436), job114548865204 SUCCESS:16 tests, exact journal-collision refusal and original-package compatibility pass. [Qualification](../evidence/durable-v11-journal-collision-denial-qualified-20261011.json). The exception is injected in orchestration; target renewal causality and plan acceptance remain unproved. Launcher/program hashes are unchanged.

## Target V11 plan prepared — 11 October, 21:01 CEST

The operator completed a fresh execution of the unchanged pinned launcher; all eight source checks passed, exit0. [Safe success receipt](../evidence/durable-v11-current-plan-target-20261011.json). This supersedes the pending/blocked status of plan preparation, while retaining the earlier journal-collision observation. No cause for that earlier collision is inferred.

New private directory: `/etc/ouf/deploy-snapshots/semantic-durable-v11-plan-2yliy8_t`.
Declaration SHA256: `ffc02da66a08fb1f1b06c143ef0f2aa18d68a6fb7b2bfaa616a812aa37eabe0f`.
Creation request SHA256: `798de748a4fcc0d8c2b6eb70f3577430d690729a4a03bc00ebbf3adcae765836`.
Public plan SHA256: `749399d19c1fae5ad02b1c97e3d05ee04b6bdade242d107b6ab7004a5f0cf7cd`.
The exact source8a2e84b/image83635be4/ZIPb6ae1051 binding is now prepared on the target. Execution defaults, retained host fields and all four existing input files were preserved/reverified.

R12 reports PID2446150 and refreshCount1332; each native flow had one approved address and minimumTTL16seconds at this read. These are stable-reread observations, not continuous liveness or future transition authority. Exactly four new private draft files were written. No image import, container lifecycle, DB read/write, DNS/provider call, firewall change, signature, common lock, new claim or budget reset occurred. The snapshot is not atomic installation authority. All apply/image-custody/transport/full-realized-OCI flags remain false.

**This preparation is completed. Do not repeat this launcher or the previous custody reader.** Preserve all private artifacts; publish only these safe hashes/receipt. The earlier old-candidate creation request and predecessor declaration remain history, not the new executable intent.

## Next composed transition bindings

The source-bound artifacts to consume are now concrete, but the qualified Engine/journal primitives do not form an authenticated target applicator. The next work must compose the following contracts before any runtime effect:

| Required binding | Current evidence | Remaining proof |
|---|---|---|
| New package and image | Exact original ZIP, eight publisher subjects, source/JAR/migrations and target private plan | Target Engine image/layer custody, exact source-bound import reconciliation and resource/admission inventory |
| Existing authority/history | R12/native custody checks; old consumed claims and finite budgets retained | Distinct authenticated transition authority tied to the new declaration/request; no reuse of R12 activation |
| Old endpoint and DB | Retained host/network frame; candidate/current-JAR V11 compatibility in CI | Quiesced producers, revoked old traffic, fresh fenced backup, migration-aware admission and recovery |
| New OCI/peer | Creation intent and Engine/journal primitives qualified separately | Realized expanded OCI, reciprocal peer/generation and new signed driver/transport closure |
| Release | No target release performed | Authenticated checkpoints, exact paused-generation reconciliation, fresh lease/admission, runtime verification |
| CSV proof | Cinema8 ACTIVE served; Teatri13×20 profile | Bounded authorized lineage join for Cinema; published Teatro terms, approved mapping/bundle, run/ACK/lineage/search and13-row accounting |

Engine creation, pause and unpause helpers explicitly leave authority and full OCI/peer/transport checks to the caller; hash receipts alone supply none. No placeholder/no-op checkpoint may be installed on the target. Preserve post-migration writes and reconcile ambiguous effects rather than replaying or restoring an old snapshot. No target apply command is ready from this receipt.


## Exact image custody/import primitive qualified; target image-only action ready

[New implementation, scope and operator command](V11_OFFLINE_IMAGE_CUSTODY_20261011.md), [qualification](../evidence/v11-offline-image-import-qualified-20261011.json): run38168097869/job114554772062 SUCCESS,28 tests. Original publisher/ZIP and actual10 rootfs layer bytes are verified. A tagless envelope preserves the exact config/layers/image ID; actual Docker import followed by process death leaves IN_FLIGHT and a reopened journal reconciles without reimport. Six-source delivery, all8 publisher-verification failure positions and current root private-plan bindings are qualified separately. Root entry tests/authentication callbacks are fixtures; actual target execution remains pending.

Next required operator action is the image-only launcher, not a repeated plan/custody read and not an application cutover. It may import one exact untagged image and writes a distinct private import journal; no container, database, R12/firewall/provider/signature effects or application transition claim. The existing runner cannot execute the required root path. New OCI/peer/transport and migration-aware composed application installation remain open. No runtime domain grant is inferred from a hash, root image-only invocation or hosted proof.
