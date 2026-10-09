# R6 exact terminal-task cleanup review — 2026-10-09

## Observed target and attribution

[Operator receipt at 17:36:45 Europe/Rome](../evidence/provider-r6-terminal-state-read-only-target-20261009.json), exit 0: both exact containerd tasks STOPPED; recorded task PIDs absent; one exact-owned moby shim each; no native entries at the retained R6 adapter runtime root; Docker candidates remain created/never started and native provider guard empty with unchanged owner/kernel hashes and preserved lock. This is user-pasted evidence, not independently acquired. The preceding directory receipt confirmed all four producer result directories absent. R6 context/output aj1j95xl and its approval are consumed.

| Role | CID | Task PID (absent) | Shim PID | Start ticks |
| --- | --- | ---: | ---: | ---: |
| adapter | f3d59af93fc90162681cee3a7562bdff3bf2af8c05cbdb7e270d1508fff18f67 | 1770715 | 1770658 | 189951185 |
| southbound | 1fc5ae6a0db4600e0124bb1f9d2998780d533fd2b4de7cb086d8675b6afb5916 | 1770730 | 1770676 | 189951186 |

Adapter container metadata hash 32c634d6dc131f577be32caf8d80f8662437f6fb3521ed52bc3cae7bdd0e73ff; southbound a2f5559ede95345286407a66a7dc8206ba39a7cab93cf66a666f4a64ec082b0a. Current wrapper cc4645eefedb2301afb6c7ac898716950f866cc5a19086e8c8ec854d26493d8b. All exact generation/metadata/state hashes are constants in the prepared executor.

## Concrete proposed action, pending fresh human approval

Prepared executor tools/semantic_target_review/execute_r6_terminal_cleanup.py, SHA256 832ce7595f6d8470f37c5348116490f10589f88c4e924b50450ee1300b6eaaad, derives from the alias-aware delete-only maintenance that succeeded for the previous R5 residue. It is inert: APPROVAL_REF=PENDING_R6_TERMINAL_CLEANUP_APPROVAL, approved/expiry timestamps unset. A new explicit human approval will pin only those approval constants in a reviewed commit and a hash-checked operator launcher. Approval scope is these two exact task generations; root maintenance approval validity 20 minutes from approval, maximum delete-only window 120 seconds. It grants no provider start or signing authority.

One invocation:
1. Fresh integrated read_r6_terminal_state.py validates both exact stopped tasks, metadata, PID absence, shim identity/start ticks, R6 wrapper/journal/candidate hashes, versions and empty native guard. This recheck is necessary immediately before destructive task-metadata removal, not another preparation milestone.
2. Bind R6 execution claim/approval/configuration, consumed cohort denial, publication and advanced journals. Freeze hashes and persist a new maintenance evidence directory. Retained shim options supply the runtime root argument explicitly; validate canonical root custody using the existing alias-aware gate. No default or old R5 PID/options hash is inferred.
3. Hold the same native guard lock, recheck candidate generation, reserve an exclusive r6-terminal-task-cleanup-claim.json in consumed R6 context (new maintenance record; no old claim reset).
4. CAS-replace only the named runtime wrapper with a short-lived delete-only gate. The gate accepts only two exact CID delete requests without force, after checking absent recorded processes and absent native entries/state directories. It cannot delegate create/start/exec/kill/native delete.
5. Issue exactly two ctr tasks delete requests, southbound then adapter, with fresh per-CID task/shim/metadata/retained-options checks. Stop on any failure, no retry.
6. Verify task absence and preserved container metadata. Restore exactly the prior R6 wrapper in finally, verify empty native guard and preserved frozen evidence. Retain per-request hashes/exit codes and private stdout/stderr; report phase/concrete denial/exception points without secrets. Unknown lifecycle operation counts remain null after any delete request.

No Docker start, kill/force, daemon restart, image/container/persistent snapshot deletion, credential/key read, signature, provider call, existing source/config rewrite, consumed journal reset or replay. Only these terminal task records and task resources are removed by containerd; accepted Docker containers/images and R1–R6/previous maintenance evidence remain.

## Validation and next dependency

Four executor tests exercise pending/expired approval before target access, exact task/shim/metadata/guard rejection, actual file wrapper CAS/restoration, consumed-claim/evidence preservation. Five existing alias-gate tests exercise delete-only/no-force CLI, native PID/state absence, exact alias binding and retarget rejection. All pass locally. These are implementation checks, not proof of successful VPS cleanup.

A fresh provider admission is NOT ready or authorized in this scope. After cleanup readback, prepare a new context/publication using the result-directory repair from 3aff8e0, explicitly bound updated utility and entry pins, preserved accepted sixteen inputs/rootfs/images and unchanged 30-file runtime/observer source closure. Do not use the old R6 launcher or merely patch the consumed output. No repeat asset load, national Teatri job, release/lease acceptance or PR merge.

Consulted L0 Matrix v1.7 ownership and Authorization v1.5 AUTH-05/06/07/08/09/12. These document requirements do not replace human authority. A fresh approval is requested because the exact R6 and earlier maintenance authorizations are consumed and do not cover removal of these new task generations.
