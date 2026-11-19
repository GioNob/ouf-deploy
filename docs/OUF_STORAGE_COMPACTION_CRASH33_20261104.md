# Generation33: observed precommit compaction crash

## Verified result — 4 November 2026

Native run [41859638833](https://github.com/GioNob/ouf-deploy/actions/runs/41859638833), job126677564586, exact producer `6db28abd0e83f95e45b1d8e4c921b69ed5a2ac96`: **146 tests and eleven native scenarios PASS**. Independent original-archive readback [41861664588](https://github.com/GioNob/ouf-deploy/actions/runs/41861664588), job126684809823, verifier `aedcec769c33e02334711a59d62b039840b5e14c`: **PASS**.

Observed volume7/PID25075, start56874 and exact container cgroup/executable; all eight threads T. Frozen `.cpd`1048688bytes and `.cpx`16bytes exist; `.cpc` absent. Original DAT5243072bytes/hash/inode9439852 and IDX48bytes/hash/inode9439859 remain identical. The original temporary bytes are retained and rehashed. Frozen, killed and gated file identities/hashes match exactly.

**Observed phase is precommit with both temporary copies already present.** This does not establish interruption halfway through copying a needle. The native compaction rate option is conditional (the upstream throttler first checks elapsed time above100ms), so no guaranteed or measured widening of the window is claimed; the frozen evidence establishes the phase.

After four non-OOM SIGKILL137 deaths and fresh gated service replacements, abandoned temporary files disappear and the old data/index generation, allocation and unselected volumes remain exact. The native1048593-byte witness `7,0100000000002133aabbcc`, SHA256`88750de893a15f19daabf07592666678d399ed4c10feba3bf1d93c2a1d10cd6c`, retains header offset4194392 and full GET parity. The8388865-byte S3 baseline and complete filer metadata recover on the first read. New filer response counter0→1954bytes and volume0→8398318bytes support real reads. Orphan direct404/S3 absence persist; retained tombstone bytes are correct rollback behavior, not a failed reclamation claim.

All ten prior regressions also pass. Eleven network removals,55 actual clean final stopped-state records,43 reported intentional deaths and98 reported distinct containers; the latter two totals are summed from native scenario receipts. The eleventh case repeats11 allowed links and36 measured denials. No second vacuum, reseed or mutating retry.

### Evidence and explicit custody

- [Original native ZIP](https://github.com/GioNob/ouf-deploy/actions/runs/41859638833/artifacts/13340730378):2227404bytes, SHA256`4a20535663dc6881bf533a13416152112c3c0441fa815d39c1ca6f9a355dd42c`.
- [Independent readback plus unchanged original ZIP](https://github.com/GioNob/ouf-deploy/actions/runs/41861664588/artifacts/13340131675): outer archive1932132bytes, SHA256`5630dd3df4f807d1dbacc5ed790d1ece2a0d9b546c6e5a8a2cc1b7d15106e85a`.
- [Repository receipt](../evidence/storage-compaction-precommit33-hosted-readback-20261104.json):1177members/1176checksums/34exact producer-source bindings verified by a separate hosted job. This is not a second native execution or local ZIP/publisher-signature verification.
- Failed first readback [41860752790](https://github.com/GioNob/ouf-deploy/actions/runs/41860752790), artifact13339722820,2547bytes, SHA256`91eb9f44f99193954dad34914191a2793cf5f316bde69c4095f4134d41c3bf97`, remains retained. Its urllib download received401 after redirect. The correction uses curl's default cross-origin Authorization stripping; no broader permission or native retry.
- Both new ZIP copies are in GitHub Actions custody until **2 February2027**; they have not been copied into Git history. Durable archive custody remains OPEN. All previously committed evidence archives are unchanged.

**Next bounded step:** qualify a crash after the `.cpc` marker, then the interval between DAT and IDX renames, with equally exact phase evidence. These remain OPEN, as do power loss and representative RPO/RTO. Progress remains18.3/46 (~40%±10),0/8gates,0/21AT,0/120real objects. MinIO/target unchanged.

## Implementation checkpoint (historical, before the successful run)

Implementation prepared; native qualification PENDING. No new storage PASS or progress credit.
Starting head: `676f626814d3f3e5d42fea273a4776062758fe59`, the cloud handoff commit. PR54 and branch were checked for later work; only already-running unrelated PR checks were observed. The app's thread inventory was unavailable, so absence of another agent cannot be established from that surface. Publication uses an expected-head lease.

## Bounded experiment

The eleventh isolated scenario retains all ten previous scenarios and the exact generation33 OCI/binary. It uses the existing incomplete PUT, tombstone, baseline S3 object and native live witness. Only this scenario adds the upstream `-compactionMBps=1` volume option, including replacements. This conditional throttle does not guarantee an observation window and is not phase evidence or a performance test.

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
