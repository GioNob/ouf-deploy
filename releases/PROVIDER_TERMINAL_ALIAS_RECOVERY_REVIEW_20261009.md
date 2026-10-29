# Exact runtime alias maintenance recovery — 2026-10-09

Status: implementation, ten local tests and native CI passed. Scoped target recovery approved at 16:07:45 Europe/Rome; operator success reported at 16:12:27 Europe/Rome. Provider start remains unauthorized. This is not release acceptance.

The retained options of both exact owning shims produce the same --root argument. Its SHA256 is 9f595173b01440cef244647bd9f19079b830bc582d119db5212b6e53544e49a2. It resolves to the retained canonical root, SHA256 c64c266a92b2d9ff052a8f2b817ee730406b2ddde47d550a52effb822b181342, but differs lexically. The old gate's pure argument predicate rejects it; the pure absence predicate passes. This reproduces a compatibility defect, without claiming historical argv was captured or attributing the original failure to later expiration. Old bundle error timestamps are historical; containerd runtimeError can prefer the last JSON error over current stderr.

## Proposed operation

One separate, explicitly approved recovery of the same two STOPPED tasks, southbound then adapter. Never replay the original executor or launcher. Preserve its consumed terminal-task-cleanup-claim.json and every file in semantic-terminal-task-cleanup-uoq_m_o7, plus the retained publication and advanced journals. Reserve terminal-task-alias-recovery-claim.json with exclusive create; no reset, retry or deletion of either claim. Leave the executor inert until approval is recorded.

Fresh checks require containerd client/server v2.3.5, exact wrapper, current empty native guard, the same owning shim generations, absent recorded task PIDs, exact retained container metadata, options SHA256 4828c44fcee22d0b148da07572dbca39c22af51b148ba03bea0321ab1f042abb, and persisted runtime binary matching the wrapper. Read actual options; do not guess either path.

The v2 gate compares caller --root lexically with only the observed argument, while separately validating that its resolution still equals the retained canonical root. Inventory and state-directory absence use that canonical root. Other aliases remain denied even when canonically equal. Gate window remains at most 120 seconds and never exceeds the human deadline 2026-10-09 17:20:18 Europe/Rome (1791559218). No time override.

Only ctr tasks delete CID, without force, is requested. No native runc kill/delete/create/start is delegated by the gate. Containerd may perform terminal IO/rootfs/task teardown; lifecycleOperations is therefore unknown when task-delete requests occurred, not fabricated as zero. Containers, image records, snapshots and data are preserved. No Docker/provider starts, daemon restarts, key reads or signatures.

Wrapper replacement and restoration use exact byte compare-and-swap under the existing native common lock. Recheck guard and retained evidence after failure as well as success. Keep bounded stdout/stderr privately in the new evidence directory (0600), print only hashes and safe diagnostics; original bundle logs remain untouched.

## Validation

Ten local tests passed: closed lifecycle boundaries, live PID/native state denial, observed alias acceptance, unobserved equivalent alias rejection, alias retarget rejection, traversal rejection, pending approval and absolute deadline denial before reads, exact shim review, actual-file wrapper restoration, and actual-file consumed claim preservation.

A disposable native containerd/runc fixture uses the reviewed Docker 29.8.1 static bundle, containerd v2.3.5, isolated namespace and locally built offline busybox OCI image. An actual symlink is configured with ctr run --runc-root; the old gate must emit EXACT_RETAINED_RUNTIME_ROOT_REQUIRED before the corrected gate removes only the two STOPPED residual tasks. Container metadata, image listing and snapshot metadata must remain equal. Fixture kill/setup/disposal is CI-only and confers no target authority.

Native CI [37940907012](https://github.com/GioNob/ouf-deploy/actions/runs/37940907012), job 113854740720, succeeded for code commit ccdbe282927a771b6547b3ecc3ec70d602358252. Logs explicitly report EXACT_ALIAS_DENIAL_REPRODUCED=true and EXACT_ALIAS_RECOVERY=true. Image listing and snapshot metadata assertions also passed. Executor SHA256 f07e2b7efeca863f05e11c8e1c53d56d660aa2cc413a724df483c0753f815af9; corrected gate SHA256 a23f71e7fbe29fc3df4f138f41d35b4b5a3c63f14f1f15bc1c9e3d62644c9cfe.

Historical pre-approval checkpoint: no target recovery had been executed. Before enabling the reviewed recovery, obtain a scoped acknowledgment for this separate one-use operation; the original operation already consumed its claim and explicitly records doNotRerunApply. Keep the existing 17:20:18 deadline unless the human explicitly changes it. Enabling requires only recording that acknowledgment and pinning the already reviewed files in the operator launcher.

## PET alignment

Consult AUTH-05/06/07/08/09/12: distinct human/agent/service authority, explicit least privilege, immutable active decisions, auditable new versions and fail closed on missing evidence. The unchanged consumed approval is not silently converted into automatic retry authority. L0 channel-neutral owner/Gateway mediation remains unchanged. CI evidence is not target or release acceptance.

Official source references:
- https://github.com/containerd/containerd/blob/v2.3.5/cmd/ctr/commands/commands_unix.go (runc-root -> options.Root)
- https://github.com/containerd/containerd/blob/v2.3.5/cmd/containerd-shim-runc-v2/process/init.go (NewRunc root/namespace and runtimeError)

## Scoped human acknowledgment recorded — 16:07:45 Europe/Rome

The user answered exactly “Autorizzo” to the concrete separate one-use recovery described above at 2026-10-09T16:07:45+02:00 (1791554865). Approval reference: OUF_TERMINAL_ALIAS_RECOVERY_HUMAN_APPROVAL_20261009_160745. This is operational operator authorization for this reviewed terminal maintenance, not a domain HUMAN_USER token, signature, provider-start authority or release acceptance. The unchanged absolute deadline is 2026-10-09T17:20:18+02:00 (1791559218).

Only APPROVAL_REF and APPROVED_AT changed in the reviewed executor. Approved executor commit f2219975695cc695c4798e3044756f08219a3b36; SHA256 454ba9195caa1e9ea8732ca4cd2f302bdcea5126e42d3951f642e2c184382118. Ten local tests passed after enabling. Exact approved-reference boundary checks deny before the timestamp, at the deadline and after it without loading a helper or reading the target. Native CI [37942041378](https://github.com/GioNob/ouf-deploy/actions/runs/37942041378) succeeded for this approved executor commit.

New operator launcher: releases/provider-terminal-alias-recovery-20261009.sh at commit 57b9c50d8dc8df5babae3f6c4bdbe61fa9e5ae0c, SHA256 8e42a54fc0f4939fd11ecf688a4e2686eb1d7d4f00f3c095aa77576edcaf9630. It pins the approved executor, the already reviewed corrected gate and the retained argument reader independently. The existing terminal review helper is verified by its exact SHA256. No old launcher or executor may be replayed.

Historical pre-execution checkpoint: recovery was not executed by the agent; the operator's complete result is now recorded below. Do not run twice, reset claims, extend clocks, start the provider or infer target acceptance from CI. If the result is blocked, acquire read-only diagnostics from the new evidence directory. After success, verify both tasks absent, container metadata retained, wrapperRestored=true, priorJournalsPreserved=true and empty postMaintenanceEmptyGuard before preparing any subsequent separate admission.

## Operator success reported — 16:12:27 Europe/Rome

[Complete target receipt](../evidence/provider-terminal-alias-recovery-target-success-20261009.json), user-pasted/operator-reported and not independently acquired: exit 0, TWO_TERMINAL_TASKS_REMOVED_ALIAS_RECOVERY_CONTAINERS_PRESERVED, two delete requests, wrapperRestored=true, priorJournalsPreserved=true, providerSetsEmpty=true and lockInodePreserved=true. Both candidate state hashes and configuration/kernel hashes equal prior readbacks. New evidence directory /etc/ouf/deploy-snapshots/semantic-terminal-alias-recovery-3d6pbi16. No Docker start requests/provider calls/private-key reads/signatures/daemon restarts. Historical containerLifecycleOperations remains null because terminal teardown occurred; guard observation's zero is scoped to that observation.

Both maintenance claims are consumed and retained: never rerun either launcher. The restored R5 wrapper is still tied to its consumed context. Next prepare a distinct source-bound admission review/context, preserving all accepted sixteen inputs, image/rootfs/dependency evidence, runtime source closure, old signatures/claims/journals and current empty guard. The maintenance approval does not authorize provider start or release acceptance.
