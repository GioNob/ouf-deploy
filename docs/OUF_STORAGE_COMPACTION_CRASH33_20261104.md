# Generation33: observed precommit compaction crash

## Current status

Implementation prepared; native qualification PENDING. No new storage PASS or progress credit.
Starting head: `676f626814d3f3e5d42fea273a4776062758fe59`, the cloud handoff commit. PR54 and branch were checked for later work; only already-running unrelated PR checks were observed. The app's thread inventory was unavailable, so absence of another agent cannot be established from that surface. Publication uses an expected-head lease.

## Bounded experiment

The eleventh isolated scenario retains all ten previous scenarios and the exact generation33 OCI/binary. It uses the existing incomplete PUT, tombstone, baseline S3 object and native live witness. Only this scenario adds the upstream `-compactionMBps=1` volume option, including replacements. This enlarges an observation window; it is not phase evidence or a performance test.

Before the sole vacuum, an observer binds the volume PID, start ticks, network namespace, container cgroup and running executable SHA256. It observes a nonempty `.cpd`, sends one SIGSTOP, verifies every task is stopped, and records original DAT/IDX bytes, hashes, inode/device/allocation, temporary files and absence of `.cpc`. A missing window, marker, rename, changed original pair or partially stopped process is UNQUALIFIED/failed, never PASS. `.cpx` may not yet exist: the reviewed CompactByIndex path saves the new index after the data-copy traversal.

The original temporary bytes and frozen receipt are retained before SIGKILL. The existing full-service crash mechanism then kills all four services. The shell/controller terminates before any replacement; frozen file identities/hashes must persist after kill and behind fresh launch gates. No manual DAT/IDX mutation, synthetic marker, second vacuum or mutating retry is allowed.

Recovery must remove abandoned temporaries while preserving the old DAT/IDX pair, blocks, live witness offset/body/identity, logical orphan absence, complete S3 baseline/body/hash/metadata and unselected volumes. Old tombstoned bytes and old witness offset are expected rollback behavior. Fresh namespaces, pre-exec firewalls, real service response counters and all network positive/negative probes remain required.

The source-binding step verifies all 33 ordered source/dependency patch hashes against the candidate manifest, rejects any patch touching reviewed compaction paths and downloads those exact upstream files by pinned commit/hash. It binds their unchanged bytes to the build manifest and candidate; it is not a new binary rebuild. The running executable hash is independently checked before injection.

## Validation and custody

- 12 new local unit tests PASS: actual phase predicates, stale marker, rename with identical bytes, changed originals, empty/header-only/missed copy, partial stop, stale work, correct rollback, wrong generation, leftovers and exclusive fixture mode.
- Python syntax and workflow YAML parsing PASS.
- The previous Linux-specific local suite could not qualify on this Windows sandbox: `cc` absent and loopback socket test denied. Docker Linux daemon unavailable; WSL denied. These environment failures are not counted as product regressions or native PASS. Full Linux regression and native evidence must come from the existing hosted workflow.
- All previous source/evidence archives are retained unchanged. The workflow exports new source binding, frozen/stopped/gated/recovered receipts and temporary bytes even on failure, with checksums and the existing private-key exclusion.

Post-marker and between-renames crashes remain OPEN. Process SIGKILL with live host/page cache does not qualify power loss, host reboot, disk loss, secure erasure or representative RPO/RTO. MiniPET remains **18.3/46 = 39.78% (~40% +/-10), 0/8 gates, 0/21 AT, 0/120 real objects**. MinIO and target unchanged; no merge/deploy/admission/runtime authority.
