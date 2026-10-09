# Exact runtime alias maintenance recovery — 2026-10-09

Status: implementation and local tests prepared; native CI pending. Target recovery approval pending. Provider start remains unauthorized. This is not release acceptance.

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

## PET alignment

Consult AUTH-05/06/07/08/09/12: distinct human/agent/service authority, explicit least privilege, immutable active decisions, auditable new versions and fail closed on missing evidence. The unchanged consumed approval is not silently converted into automatic retry authority. L0 channel-neutral owner/Gateway mediation remains unchanged. CI evidence is not target or release acceptance.

Official source references:
- https://github.com/containerd/containerd/blob/v2.3.5/cmd/ctr/commands/commands_unix.go (runc-root -> options.Root)
- https://github.com/containerd/containerd/blob/v2.3.5/cmd/containerd-shim-runc-v2/process/init.go (NewRunc root/namespace and runtimeError)
