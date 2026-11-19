### Storage 2026-11-04 — marker-only crash qualified

**189 tests /14 native scenarios PASS.** [Native41886227100](https://github.com/GioNob/ouf-deploy/actions/runs/41886227100), producer b293a490, and [independent readback41886345188](https://github.com/GioNob/ouf-deploy/actions/runs/41886345188), verifier341abfe3, both completed/success. Original ZIP independently downloaded and verified locally with identical results: **1757 members /1756 checksums /40 exact sources**;70 clean final stops,137 containers/67 intentional deaths,14 removed networks.

Both DAT/IDX renames returned0 and directory fsync succeeded; exact CPC unlink held at entry with9threads stopped. Four SIGKILLs, gated recovery: only marker removed, **already-promoted pair unchanged at first readiness**, full baseline/metadata/witness parity.4194384 DAT bytes /4194304 allocated bytes reclaimed, witness4194392→8; no additional vacuum, recovery PUT or mutating retry. Original artifact13352193356 (20598958bytes,SHA256 b9db34fd…), nested copy in13351279481 retained until2027-02-02. No new durable Git ZIP custody claim.

Checkpoint [74f28277](https://github.com/GioNob/ouf-deploy/commit/74f28277337b009e5658e2cdaa664191f072ddeb) · [dossier](https://github.com/GioNob/ouf-deploy/blob/74f28277337b009e5658e2cdaa664191f072ddeb/docs/OUF_STORAGE_MARKERONLY_CRASH33_20261104.md) · [complete receipt, local verification and preserved negatives](https://github.com/GioNob/ouf-deploy/blob/74f28277337b009e5658e2cdaa664191f072ddeb/evidence/storage-markeronly33-hosted-readback-20261104.json). Native41878669053/41882562646 and their readbacks remain FAILED. Corrected offset/thread assumptions; deterministic Linux cross-thread test passes, but the earlier compound error's exact operands were not retained.

**MiniPET39.78%, MinIO and target unchanged.** Process-crash qualification covers four commit phases, not power loss, continuous concurrent workload or production RPO/RTO. Next: review existing common-cut33 evidence before selecting the remaining coordinated recovery/writer-fencing gap. Historical pending statements below are superseded.

---

### Current storage checkpoint — witness-offset test defect corrected (2026-11-04)

Producer `84706b4fa014df74fdbd3685a56d2aba16934c84`. Original native41878669053: **183 Linux tests / first12 scenarios PASS**, inter-rename FAILED, marker-only SKIPPED; original readback41878956434 correctly failed for absent marker-only receipt. Both artifacts preserved. [Negative receipt and diagnosis](https://github.com/GioNob/ouf-deploy/blob/84706b4fa014df74fdbd3685a56d2aba16934c84/evidence/storage-markeronly33-first-failure-diagnosis-20261104.json).

Local verification of the original ZIP:1483 members/1482 checksums. Live data preceding the witness gives offset12583096→8388712, exactly4194384 bytes reclaimed; the observer wrongly required offset8. Correction requires aligned actual offset, exact DAT shrink and unchanged body/identity/inode/phase checks. Three regressions cover the live prefix and reject wrong shrink/index;27 pure tests PASS locally. [Corrected native run 41882562646](https://github.com/GioNob/ouf-deploy/actions/runs/41882562646), job126758546819, is in progress. Verifier `e5e59d027826d9727fdab51557215fee81986e12` binds this exact run/job/attempt1 and actual relocation offsets. [Readback41883215358](https://github.com/GioNob/ouf-deploy/actions/runs/41883215358), job126760754240, is waiting for the original archive. New **186-test/14-scenario qualification PENDING**, unchanged OCI33/MinIO/MiniPET39.78%. The failed run remains failed; delayed queued observations below are historical. Resume the new run after this actual code correction, not a retry of unchanged code.

---

### Current storage work — marker-only crash qualification started (2026-11-04)

**Queue checkpoint — 4 November, 18:44 Europe/Rome:** native run 41878669053/job 126745091191 and readback 41878956434/job 126746115330 remain queued; native runner unassigned, zero steps and no original artifact. Branch head `3767de36cb23876739bbb255e088e74dd2ca92fb`; all nine published files read back exactly. Resume by checking these existing runs, without resubmission. No native PASS is claimed and no platform outage cause is asserted.

Producer `87fc66ca9a2b24fb55e983392f573c0c1f54d96c`: fourteenth scenario, unchanged OCI33/binary. Observe both native rename exits 0, successful post-rename directory fsync, then hold exact marker unlink entry. Require already-promoted DAT/IDX identities, no temporary copies, original marker present. Recovery must remove only the marker and preserve the complete pair at first readiness before fixture reads.

46 pure phase tests PASS locally; 3 Linux ptrace tests skipped on Windows and mandatory in CI. Full local suite stopped at Windows compiler/socket limitations, documented without weakening Linux checks. Expected **183 tests / 14 scenarios**; native and independent readback **PENDING**. [Readback 41878956434](https://github.com/GioNob/ouf-deploy/actions/runs/41878956434), verifier `3767de36cb23876739bbb255e088e74dd2ca92fb`, is bound to original run/attempt 1/job 126745091191. [Native run 41878669053](https://github.com/GioNob/ouf-deploy/actions/runs/41878669053). [Dossier](https://github.com/GioNob/ouf-deploy/blob/87fc66ca9a2b24fb55e983392f573c0c1f54d96c/docs/OUF_STORAGE_MARKERONLY_CRASH33_20261104.md). Prior evidence preserved; MiniPET39.78%, MinIO and target authority unchanged.

---

### Latest storage checkpoint — crash between DAT/IDX renames PASS (2026-11-04)

Checkpoint `1a471e57c6073851918eea1d926cd76aca7180a9` on `feat/m2-discovery-complete-profile-20261029`. [Dossier](https://github.com/GioNob/ouf-deploy/blob/1a471e57c6073851918eea1d926cd76aca7180a9/docs/OUF_STORAGE_INTERRENAME_CRASH33_20261104.md) · [complete evidence receipt](https://github.com/GioNob/ouf-deploy/blob/1a471e57c6073851918eea1d926cd76aca7180a9/evidence/storage-interrename33-hosted-readback-20261104.json) · [updated MiniPET](https://github.com/GioNob/ouf-deploy/blob/1a471e57c6073851918eea1d926cd76aca7180a9/docs/OUF_MINIO_SEAWEEDFS_MINIPET_v1_0_20261102.md).

**170 tests / 13 native scenarios PASS.** Producer `5ac67de14e4aaf17808b12f95040ed297aef37dc`, [native run 41870302570](https://github.com/GioNob/ouf-deploy/actions/runs/41870302570), job 126715227789, attempt 1 completed/success. Unchanged OCI33/binary: real DAT rename observed returning 0, IDX rename held at entry with all nine threads stopped. New DAT/old IDX, pending .cpx and durable marker retained; old witness offset 4194392 is beyond the new DAT length 1048688, pending index points to the intact body at 8.

Four SIGKILLs, retained roots and gated replacements: new DAT preserved, exact pending IDX promoted, marker/temporaries removed. **Coherent pair at first readiness before fixture application reads**; S3/metadata/witness intact at recovery attempt 1. Reclaimed 4194384 DAT bytes / 4194304 allocated bytes; 11 permitted links / 36 denials repeated. No additional vacuum, recovery PUT or mutating retry.

[Independent readback 41871254673](https://github.com/GioNob/ouf-deploy/actions/runs/41871254673), verifier `15d6ac5b13c25866e61b8969c005dfe4355eb9e8`, job 126718618427: completed/success. **1559 members / 1558 checksums / 38 exact source bindings**, including independent decoding of retained IDX/cpx/DAT bytes. 65 clean final states, 124 distinct containers / 59 intentional deaths reported, 13 removed networks. Native terminal success confirmed separately; no native resubmission.

Original artifact 13345276270: 5727470 bytes, SHA256 `a47304daa0ade0357972e714205fc70b01f02486773265011d70ae68b3cda73c`. Unchanged original nested in readback artifact 13345266273; both retained until 2027-02-02. Receipt committed; no new durable Git custody of ZIPs or local ZIP verification claimed. All previous evidence and historical observations below preserved; their pending/next-step statements are superseded by this checkpoint.

**Next single step:** crash after both DAT/IDX renames, before .cpc removal, to test idempotent finalization with only the marker remaining. This phase, power loss, continuous concurrent workload and RPO/RTO remain OPEN.

MiniPET **18.3/46 = 39.78%**, 0/8 gates, 0/21 AT, 0/120 real objects; MinIO unchanged. No merge/deploy/admission/replay/reset/grant/target operation.

---

### Current storage work — inter-rename crash qualification started (2026-11-04)

Producer`5ac67de14e4aaf17808b12f95040ed297aef37dc`: thirteenth scenario on unchanged OCI33/binary. Capture the full post-marker pair, observe successful first DAT rename, hold IDX rename entry with every thread stopped, and retain the actual mixed bytes. Require the old witness offset outside the new DAT and the pending index bound to the exact body. Recovery must preserve the new DAT, promote the exact pending IDX, and show a coherent pair at first readiness before fixture reads, then full S3/metadata/witness/network parity without another vacuum.

34 local pure tests PASS; two Linux mechanics tests skipped on Windows and required in CI. Expected170 tests/13 native scenarios; new qualification and readback **PENDING**. [Dossier](https://github.com/GioNob/ouf-deploy/blob/5ac67de14e4aaf17808b12f95040ed297aef37dc/docs/OUF_STORAGE_INTERRENAME_CRASH33_20261104.md). Previous qualified evidence retained; MiniPET39.78%, MinIO and target authority unchanged.

---

### Latest storage checkpoint — post-marker crash PASS (2026-11-04)

Checkpoint `aa19c4684e6bedaad38c7bb560a73168a73ef642` on `feat/m2-discovery-complete-profile-20261029`. [Dossier](https://github.com/GioNob/ouf-deploy/blob/aa19c4684e6bedaad38c7bb560a73168a73ef642/docs/OUF_STORAGE_POSTMARKER_CRASH33_20261104.md) · [durable receipt and provenance](https://github.com/GioNob/ouf-deploy/blob/aa19c4684e6bedaad38c7bb560a73168a73ef642/evidence/storage-postmarker33-hosted-readback-20261104.json).

**157 tests / 12 native scenarios PASS**, producer18b93a7f [run41864590947](https://github.com/GioNob/ouf-deploy/actions/runs/41864590947). Unchanged OCI33/binary: volume4/PID28516, nine traced threads held at renameat264 entry after marker/directory fsync0, `.cpc` present, old DAT/IDX untouched. Joint SIGKILL137/non-OOM; recovery promoted the exact temporary inodes and removed marker/copies, reclaimed4194384 DAT bytes /4194304 allocated bytes, preserved every live needle/unselected volume, and relocated the1048593-byte witness4194392→8 with unchanged identity/body/GET. S38388865 bytes and full metadata recovered at attempt1;11 links/36 denials repeated; no second vacuum or recovery PUT.

[Strict readback41865783844](https://github.com/GioNob/ouf-deploy/actions/runs/41865783844) and [additional evidence verification41867565360](https://github.com/GioNob/ouf-deploy/actions/runs/41867565360) both PASS with identical results:1364 members/1363 checksums/36 source bindings,60 actual clean final stops,111 containers/51 intentional deaths reported,12 networks removed. Original artifact13343120116 (3447908bytes,SHA256`be6f6164165c07bf1e8982cc0a14b8371c46177ba109135cea26134a48e7a4e0`), exact nested copies13342372982/13343535815 retained until2027-02-02; no durable Git custody of these ZIPs or local ZIP readback claimed. All previous evidence preserved.

Initial Actions metadata discrepancy is reconciled: native run/job **completed/success** confirmed; no native resubmission and strict verification unchanged. Earlier queued/pending notes below are historical.

**Next single step: crash between DAT and IDX renames.** That phase, power loss and RPO/RTO remain OPEN. MiniPET18.3/46=39.78%,0/8gates,0/21AT,0/120real objects; MinIO unchanged. No merge/deploy/admission/replay/reset/grant/target operation.

---

### Verified crash before compaction commit — 4 November 2026

[Native run41859638833](https://github.com/GioNob/ouf-deploy/actions/runs/41859638833), job126677564586, exact source `6db28abd0e83f95e45b1d8e4c921b69ed5a2ac96`: **146 tests and eleven native scenarios PASS**. Independent original-archive [readback41861664588](https://github.com/GioNob/ouf-deploy/actions/runs/41861664588), verifier `aedcec769c33e02334711a59d62b039840b5e14c`: **1177members /1176checksums /34exact sources verified**.

The unchanged generation33 binary is bound to the observed PID/start/container cgroup. All8threads are stopped; volume7 has `.cpd`1048688bytes and `.cpx`16bytes, no `.cpc`, and unchanged original DAT5243072bytes/IDX48bytes with identical hashes and inodes. These are already-present temporary copies before commit; interruption midway through copying is not claimed. The native throttle option does not itself prove timing or phase.

One subsequent SIGKILL per service, all4non-OOM exits137 before replacements, fresh namespace pins/gates/firewalls and retained roots. Frozen/stopped/gated temporary identities/hashes match. Recovery removes the abandoned copies, preserves the old data/index/allocation and all unselected volumes, and retains native witness1048593bytes at offset4194392 with the same identity/hash and full GET. Baseline S38388865bytes and complete filer metadata recover on the first read; orphan direct404/S3absence persist. No second vacuum, reseed or mutating retry. New response counters: filer0→1954bytes, volume0→8398318bytes;11allowed links/36denials repeated.

All ten previous scenarios remain PASS.55clean final stopped-state records verified; native receipts report98distinct containers/43intentional deaths and11removed networks. Original ZIP2227404bytes, SHA256`4a20535663dc6881bf533a13416152112c3c0441fa815d39c1ca6f9a355dd42c`. [Original](https://github.com/GioNob/ouf-deploy/actions/runs/41859638833/artifacts/13340730378) and [independent readback with unchanged original](https://github.com/GioNob/ouf-deploy/actions/runs/41861664588/artifacts/13340131675) are retained through **2027-02-02**; no durable Git custody of this new ZIP is claimed. Previously committed archives are unchanged.

First readback41860752790 FAILED401 at signed-storage redirect is retained with its artifact13339722820. Downloader corrected to strip cross-origin Authorization using curl; native qualification was not rerun. Readback was hosted, not a second local Docker execution or local publisher-signature verification.

[Checkpoint23fc41f5 / dossier](https://github.com/GioNob/ouf-deploy/blob/23fc41f569007432ac861c856d9d777ddc74def7/docs/OUF_STORAGE_COMPACTION_CRASH33_20261104.md) · [Repository receipt](https://github.com/GioNob/ouf-deploy/blob/23fc41f569007432ac861c856d9d777ddc74def7/evidence/storage-compaction-precommit33-hosted-readback-20261104.json).

**Next single step:** crash after the `.cpc` marker; then between DAT/IDX renames. Both remain OPEN. Process loss with live host/page cache does not qualify power loss/RPO/RTO. MiniPET remains18.3/46=39.78% (~40%±10),0/8gates,0/21AT,0/120real objects. MinIO and target unchanged; no merge/deploy/admission/runtime authority.

**Cloud continuation handoff (4 November 2026):** [Read this first](https://github.com/GioNob/ouf-deploy/blob/676f626814d3f3e5d42fea273a4776062758fe59/docs/handoffs/OUF_STORAGE_CLOUD_HANDOFF_20261104.md). Preserves this session's source review, exact status, next crash-compaction protocol and limits. Documentation only; no additional test PASS or percentage increase.

This draft develops and qualifies a SeaweedFS replacement for MinIO. MinIO remains active. Work is confined to repository development and disposable qualification laboratories; no target cutover, deployment, merge, admission or runtime authority is performed.

### Continuation review — 4 November 2026 (design only; no new native run)

The GitHub Actions API independently reports run41845769045 **completed/success** on exact producer28c4890956dc74813dd3642042575799fa4d3a8b. The retained dossier remains the source for134 tests/ten scenarios; this review has not rerun Docker or reverified the original ZIP. Current checkpoint is f039927a42bc2d51c9604dc9508f133b7c02f8e3, not the historical default-branch README.

The generation33 lock binds upstream **4.52 / 984eac6a790be89e2a11de175a7413e1e3e32dd3**. Inspection of [volume_vacuum.go at that exact upstream](https://github.com/seaweedfs/seaweedfs/blob/984eac6a790be89e2a11de175a7413e1e3e32dd3/weed/storage/volume_vacuum.go) identifies two distinct recovery decisions. Before a .cpc commit marker exists, reconcileCompactState abandons temporary .cpd/.cpx; with the marker, finishCompactSwap completes whichever rename remains. In particular, a crash between .cpd→.dat and .cpx→.idx must not pair relocated data with the previous index. This is source analysis, not execution evidence or proof of the final patched binary.

Next implementation/qualification must:
- Bind the actual patched generation33 source and unchanged OCI before selecting the injection point.
- First qualify an observed in-progress precommit interruption: freeze/identify the exact volume process, prove temporary work exists and no commit marker/rename has occurred, kill once, retain stopped-state evidence, then recover without resubmitting vacuum.
- Separately qualify post-marker and between-rename interruption. A timed sleep or successful restart alone does not establish either phase; a missed phase is unqualified, never PASS. Any instrumented build must be identified separately from the admitted candidate.
- Require full baseline S3 body/hash/metadata parity, the native relocation witness identity/hash, orphan logical absence, DAT/IDX consistency and unchanged unselected volumes. Precommit recovery may legitimately retain the tombstoned bytes and old witness offset; reclamation/relocation must not be falsely required for rollback. Postcommit recovery must finish the matching new pair.
- Retain failed/ambiguous evidence; no automatic mutating resend, manual storage repair or cleanup before readback. Preserve fresh namespace/firewall gates and all ten existing regressions. Process-kill evidence does not establish power-loss durability or representative RPO/RTO.

**Progress unchanged:18.3/46=39.78% (~40%±10),0/8 gates,0/21 AT,0/120 real objects.** Crash-during-compaction implementation and native qualification remain OPEN. MinIO and target state are unchanged; no merge/deploy/runtime authority. Teatri/M1 remains8/8 technical+6/6 functional; Farmacie61rows/10OPEN/STRING retained. Storage completion precedes residual M2, then graph/search, then vertical/API scheduler/delta.

### Verified live-needle relocation across a tombstoned record — 4 November 2026

[Run 41845769045](https://github.com/GioNob/ouf-deploy/actions/runs/41845769045), job 126628727934, source `28c4890956dc74813dd3642042575799fa4d3a8b`: **134 tests and ten native scenarios PASS**. The tenth fixture appends one 1048593-byte native witness after the orphan tombstone in the exact same volume, then verifies relocation during vacuum and persistence after another full service crash/recovery. All nine prior scenarios remain qualified.

Witness `1,0100000000002133aabbcc`, SHA256 `88750de893a15f19daabf07592666678d399ed4c10feba3bf1d93c2a1d10cd6c`: reserved fixture ID absent across every live/deleted index and direct GET404 before the single POST201. Exact old DAT and IDX prefixes, existing needles and unselected volumes are preserved. No mutating retry, master assignment or direct DAT/IDX edit.

The witness header moves **4194392→8**, and remains **8 after restart**; payload offset4194412→28. The **4194384-byte offset reduction exactly matches DAT shrink**. Needle ID/cookie/size/hash remain identical, with native GET200 and complete body parity before vacuum, after vacuum and after restart. Total DAT length13632128→9437744 bytes and allocation13660160→9465856 bytes: **4194304 allocated bytes recovered**, retained after restart. Orphan payload/tombstone are removed, with no compaction leftovers or deleted-open fixture handles.

The acknowledged8388865-byte S3 baseline and complete filer metadata remain intact; recovered on the first read. New filer response counter0→1952bytes and volume0→8398162bytes precede final witness reads; topology and registrations recover on the first probe. Orphan direct404 and S3 GET/HEAD404/complete baseline-only LIST persist. Four SIGKILL137/non-OOM deaths precede every replacement, namespaces/gates are fresh, all firewalls precede exec, client unchanged;11 allowed links/36 denials are repeated.

Original ZIP975697bytes, SHA256 `5d72e91a59dd82b48bb3978e8e4e59b87e122b05064fce31fbcabc38a91ba26c`:990 members/989 checksums/31 exact sources verified;85 distinct containers,50 clean final stops,35 intentional SIGKILL deaths and ten removed networks. Readback verifies original archive and source-bound native summaries, not a second local Docker execution or local publisher-signature verification.

[Dossier](https://github.com/GioNob/ouf-deploy/blob/f039927a42bc2d51c9604dc9508f133b7c02f8e3/docs/OUF_STORAGE_RELOCATION33_20261104.md) · [Readback](https://github.com/GioNob/ouf-deploy/blob/f039927a42bc2d51c9604dc9508f133b7c02f8e3/evidence/storage-relocation33-readback-20261104.json) · [Original ZIP](https://github.com/GioNob/ouf-deploy/blob/f039927a42bc2d51c9604dc9508f133b7c02f8e3/evidence/artifacts/storage-relocation33-41845769045.zip)

The witness is **native-only and not linked to filer metadata**, separate from the preserved S3 baseline. Its reserved ID is limited to a fixture without concurrent writes; this does not define production allocation or internal method authorization. No crash during vacuum/rename, power loss, host reboot, disk failure, secure erase or RPO/RTO qualification. MiniPET remains18.3/46=39.78% (about40%±10),0/8 gates,0/21 AT,0/120 real objects; MinIO and target unchanged. **Next single step:** interrupt the volume during compaction and reconcile retained state without automatic mutating resubmission.

### Verified full service restart after compaction — 4 November 2026

[Run 41840445331](https://github.com/GioNob/ouf-deploy/actions/runs/41840445331), job126614148697, source `6aa6d73b3096a4b2de8c7f2300751a0f8019118c`: **122 tests and nine native scenarios PASS**. The ninth scenario completes the existing orphan cleanup and exact-volume vacuum, then kills all four services and recovers them behind fresh gates/firewalls using the same storage roots. All four deaths precede every replacement; old namespaces are retained until identity comparison, pins released before exec, and client unchanged. No recovery PUT, second vacuum or mutating retry.

The **4194304 allocated bytes reclaimed remain reclaimed** after restart: total DAT allocation12611584→8417280 bytes and remains8417280; DAT length12583448→8389064 and remains8389064. Every compacted DAT/IDX hash, length, live/deleted needle map and allocated block matches at gated, recovered and final snapshots. The selected volume2 contains one live4194304-byte needle3 alongside orphan4; the live needle's hash/cookie/size survive vacuum and restart, index48→16bytes. The orphan followed the live record, so relocation across an earlier deleted record is not claimed.

Baseline8388865bytes is recovered on the first read with identical complete filer metadata. New filer response counter0→1954bytes and new volume0→8398110bytes establish actual service reads. Topology/peer registration recovers on the first probe. Direct chunk404, S3 GET/HEAD404 and complete baseline-only LIST persist; no compaction residue or deleted-open fixture file. All11 allowed links and36 denials are repeated after the second restart, followed by final storage/body/absence parity.

Original ZIP802573bytes, SHA256 `7241c26b7552bff51cc959d4730d84f993b0810552bd398806dd94aaf784a70c`:810 members/809 checksums/29 exact source hashes verified;72 distinct containers,45 clean final stops,27 intentional SIGKILL deaths and nine removed networks. Local verification checks source-bound native summaries and the original archive, not a second local Docker run or local publisher-signature verification.

Initial [run41840244896](https://github.com/GioNob/ouf-deploy/actions/runs/41840244896) also passed. Its producer4189dbec accidentally included two local synthetic TLS CA/key files; these were immediately removed from the branch in6aa6d73b, remain in prior Git history, and are absent from native evidence. The recorded final run uses the corrected tree; subsequent publication uses explicit file lists and private-key checks.

[Dossier](https://github.com/GioNob/ouf-deploy/blob/bc528908310e8dceff00bdd5661c5391169a58be/docs/OUF_STORAGE_COMPACTION_RESTART33_20261104.md) · [Readback](https://github.com/GioNob/ouf-deploy/blob/bc528908310e8dceff00bdd5661c5391169a58be/evidence/storage-compaction-restart33-readback-20261104.json) · [Original ZIP](https://github.com/GioNob/ouf-deploy/blob/bc528908310e8dceff00bdd5661c5391169a58be/evidence/artifacts/storage-compaction-restart33-41840445331.zip)

This qualifies process loss **after completed vacuum**, with host and page cache alive. It does not qualify failure during compaction/rename, power loss, host reboot, disk loss, secure erasure or RPO/RTO. MiniPET remains18.3/46=39.78% (about40%±10),0/8 gates,0/21 AT,0/120 real objects; MinIO and target unchanged. **Next single step:** place a deleted record before a live needle in the same volume and verify its offset relocation, integrity and persistence.

### Verified exact-volume compaction and allocated DAT reclamation — 4 November 2026

[Run 41837272317](https://github.com/GioNob/ouf-deploy/actions/runs/41837272317), job 126599309665, source `b07df7eceda9036aa53ba1b328ca9d1a3e6fcb60`: **114 tests and eight native scenarios PASS**. The eighth scenario performs one locked native vacuum on exact collection/volume7 after the existing cleanup, restart and network checks; no mutating retry or added network link.

Total DAT length falls **12583448→8389064 bytes** and allocated DAT blocks **12611584→8417280 bytes**, recovering **4194304 allocated bytes (4 MiB)**. Target index32→0; orphan payload and tombstone disappear. Direct chunk404, S3 GET/HEAD404 and complete baseline-only LIST persist; the acknowledged8388865-byte baseline and complete filer metadata remain identical. All unselected DAT/IDX files are unchanged, with no temporary compaction files or deleted-open fixture handles in the volume process. Service identities and starts remain unchanged during compaction.

The selected volume contained only the tombstoned orphan; all three live baseline needles were in unchanged volume2. This run does **not** qualify copying live needles within the compacted volume, restart after compaction, crash during commit, power loss or secure erasure. The prior restart precedes compaction and is not credited as post-compaction persistence.

The first [run41836677592](https://github.com/GioNob/ouf-deploy/actions/runs/41836677592) remains **FAILED and preserved**: initial volume launcher exit65/non-OOM with empty log, before seed or compaction. Marker bytes were not exported. The fixture now publishes a complete marker through exclusive temporary-file creation and atomic rename, eliminating a possible partial-marker exposure without weakening exact-marker/symlink checks; two regressions cover publication and all-gates prevalidation.

Original successful ZIP630916bytes, SHA256 `07fb939d1dcc490d494a2158935767dba58696bf3ecfd8bdedbb53792e59ec82`:639 members/638 checksums/28 exact sources verified;59 distinct containers,40 clean final stops,19 intentional SIGKILL deaths and eight removed networks. Local readback verifies source-bound summaries and archive integrity, not a second Docker execution or local publisher-signature verification.

[Dossier](https://github.com/GioNob/ouf-deploy/blob/bd1dec94747cb13058c740672701f2213c5d01a1/docs/OUF_STORAGE_COMPACTION33_20261104.md) · [Readback](https://github.com/GioNob/ouf-deploy/blob/bd1dec94747cb13058c740672701f2213c5d01a1/evidence/storage-compaction33-readback-20261104.json) · [Original ZIP](https://github.com/GioNob/ouf-deploy/blob/bd1dec94747cb13058c740672701f2213c5d01a1/evidence/artifacts/storage-compaction33-41837272317.zip) · [Failed readback](https://github.com/GioNob/ouf-deploy/blob/bd1dec94747cb13058c740672701f2213c5d01a1/evidence/storage-compaction33-failed-readback-20261104.json) · [Failed ZIP](https://github.com/GioNob/ouf-deploy/blob/bd1dec94747cb13058c740672701f2213c5d01a1/evidence/artifacts/storage-compaction33-failed-41836677592.zip)

MiniPET remains18.3/46=39.78% (about40%±10),0/8 gates,0/21 AT,0/120 real objects. MinIO and target unchanged. **Next single step:** full restart after compaction, checking retained allocation/index/absence and baseline without reseeding.

### Verified native orphan logical cleanup — 4 November 2026

[Run 41824890871](https://github.com/GioNob/ouf-deploy/actions/runs/41824890871), job 126557006058, source `01431f652f75c737d18534708ca0e7f17535814b`: **100 tests and seven native scenarios PASS**. The additional cleanup scenario permits exactly S3→volume gRPC28080 from its initial launch gates; all six original scenarios retain their prior policy.

The exact 4194304-byte orphan chunk is identified from native volume bytes/header and read completely via direct GET200/hash before interrupting a single incomplete PUT. Automatic gateway cleanup produces a 16→32-byte index transition with the original record and one exact tombstone(-1), observed on the first poll. The same chunk returns404 after cleanup, after all four services restart, and after network probes. Index hash/records persist. Dedicated gRPC traffic rises0→677 bytes from S3 and0→579 from volume; the controller issues no DELETE or mutating retry. S3 GET404/NoSuchKey, empty HEAD404 and baseline-only LIST remain consistent; the acknowledged 8388865-byte baseline is recovered intact on the first read.

The initial [run41823561384](https://github.com/GioNob/ouf-deploy/actions/runs/41823561384) remains **FAILED and preserved**: logical cleanup succeeded, but a historical namespace-inode check blocked replacement before post-restart qualification. That run did not retain the conflicting replacement inode. The fixture now bind-pins each old namespace before SIGKILL, compares replacement identities while old namespaces remain alive, and releases all pins before replacement execution. Namespace separation assertions remain strict; three new pin tests and all seven native paths pass.

The cleanup case has11 permitted links/36 measured denials; six regressions retain10/37 each. Fifty distinct containers,35 clean final stops,15 intentional non-OOM SIGKILLs, seven removed networks and all namespace pins released. Successful original artifact13318842839:518542 bytes, SHA256 `e6838878d7428ac07586d671d88881ef4adab9c57c40f542f83363f9741a7761`;518 members/517 checksums/26 exact source bindings verified locally. Failed original:456 members/455 checksums/26 source bindings separately retained and verified.

[Dossier and both archives](https://github.com/GioNob/ouf-deploy/blob/ae01a2757d8f49f03c06cace6e1d5e0e0e3cacae/docs/OUF_STORAGE_ORPHAN_CLEANUP33_20261104.md), [successful readback](https://github.com/GioNob/ouf-deploy/blob/ae01a2757d8f49f03c06cace6e1d5e0e0e3cacae/evidence/storage-orphan-cleanup33-readback-20261104.json), [failed-run readback](https://github.com/GioNob/ouf-deploy/blob/ae01a2757d8f49f03c06cace6e1d5e0e0e3cacae/evidence/storage-orphan-cleanup33-failed-readback-20261104.json). Evidence checkpoint `ae01a2757d8f49f03c06cace6e1d5e0e0e3cacae`.

**Scope is logical deletion, not physical space reclamation.** DAT bytes remain with the tombstone; no vacuum or per-method gRPC authorization/internal mTLS is qualified. No production/target changes, merge, deploy or new authority. Progress remains18.3/46 (~40% ±10),0/8 gates,0/21 AT,0/120 real objects. Next bounded step: qualify fixture volume compaction while preserving the baseline and deleted-chunk absence.

### Verified native incomplete PUT reconciliation — 4 November 2026

[Run 41821487900](https://github.com/GioNob/ouf-deploy/actions/runs/41821487900), job 126545451454, source `9c0f2968dba8528ced7c98643f30a7c5740ce400`: **86 tests and six native scenarios PASS**. A single signed TLS PUT declares 8388865 bytes and sends only 4259841. Before client disconnect, the first native-volume observation finds the exact 4194304-byte fixture chunk (offset28); the S3 log then records connection reset while reading the next 65537 bytes. No response/ACK is read and no mutating retry occurs.

GET404/NoSuchKey, empty HEAD404 and complete baseline-only LIST agree before the crash, after all four services restart, and after network probes. The acknowledged 8388865-byte baseline remains exact on the first recovery read. Four non-OOM SIGKILL deaths precede every replacement; fresh processes/namespaces/gates reuse the retained roots, with all firewall rules installed before execution. All six scenarios retain 37 denied/10 permitted network probes each:41 distinct containers,30 clean final stops,11 intentional deaths, six networks removed.

**Observed cleanup limitation:** the gateway attempts to delete one orphan chunk, but the fixture denies S3→volume gRPC28080; the log records cleanup failure with no route to host. S3 object absence is verified; chunk reclamation is not qualified. No policy expansion was made. Next bounded step: qualify orphan cleanup and the minimum required gRPC link inside the isolated fixture.

Original artifact 13316679288:415546 bytes, SHA256 `6597d90489dc330ce7a4e8bf98c818827ec3f85185972bdb63c21e43a4bc8484`;400 members/399 checksums/24 exact source bindings verified locally. [Dossier](https://github.com/GioNob/ouf-deploy/blob/bf040e975ac0ea8060f6d2450205eb7b3b460da3/docs/OUF_STORAGE_STREAM_INTERRUPTION33_20261104.md), [readback receipt](https://github.com/GioNob/ouf-deploy/blob/bf040e975ac0ea8060f6d2450205eb7b3b460da3/evidence/storage-stream-interruption33-readback-20261104.json), [original ZIP](https://github.com/GioNob/ouf-deploy/blob/bf040e975ac0ea8060f6d2450205eb7b3b460da3/evidence/artifacts/storage-stream-interruption33-41821487900.zip). Evidence checkpoint `bf040e975ac0ea8060f6d2450205eb7b3b460da3`.

Scope: a new-key fixed Content-Length PUT interrupted by client disconnect, then a full process restart. This does not qualify server crash during upload, streaming-chunked/multipart, overwrite/versioning, orphan GC, power loss, host reboot or RPO/RTO. Progress remains18.3/46 (~40% ±10),0/8 gates,0/21 AT,0/120 real objects. No target/VPS, merge, deploy, replay, reset or grant; MinIO and existing application scope remain unchanged.

### Verified native SeaweedFS joint service SIGKILL recovery — 4 November 2026

[Run 41819462147](https://github.com/GioNob/ouf-deploy/actions/runs/41819462147), job 126538678956, source `1a8a868fc4361b567127fe898e36c5da2b51d4e2`: **74 tests and five native scenarios PASS**. A single bounded Docker batch kills master, volume, filer and S3 after the fixture object's acknowledged PUT. All four exit137/non-OOM states and FinishedAt timestamps precede every replacement's creation. This does not assert physically simultaneous signals. Four fresh service containers/namespaces/gates retain their disk roots/IPs/read-only configuration, while the client retains identity/start time/restart count. All firewall rules and eight closed listeners are checked before any replacement process is released.

Stopped/gated hashes match for **master 4 files / 1,335 bytes; filer 40 files / 5,274 bytes; volume 7 DAT files / 8,389,064 bytes**. Original DAT prefixes also survive recovery. The first topology probe verifies the same TopologyId/chunk locations and new peer registrations; direct filer metadata is identical. The first signed TLS S3 GET/HEAD/LIST recovers the exact **8,388,865-byte object with zero new PUTs**. New filer response traffic rises **0→1,954 bytes**, and new volume response traffic **0→8,397,434 bytes**. TCP counters include overhead and are not payload-size or RTO measurements.

Each of five paths preserves 10 allowed links and **37 measured denials**, with zero catch-all denied traffic and unchanged object parity. Original archive readback verifies **307 members / 306 checksums / 22 exact sources**, 32 distinct containers, 25 clean final stops and seven intentional SIGKILLs. [Evidence and limits](https://github.com/GioNob/ouf-deploy/blob/009ab862d0966905be9e449d98948bb7dca2a443/docs/OUF_STORAGE_ALL_CRASH33_20261104.md). Checkpoint `009ab862d0966905be9e449d98948bb7dca2a443` adds documentation, readback and the original ZIP only.

Scope is joint application-process loss after a completed PUT, with retained disk and kernel page cache. It does not establish power-loss durability, host reboot, disk/quorum loss, HA, in-flight write recovery or production RPO/RTO. MiniPET remains **18.3/46 (~40% ±10)**, **0/8 gates, 0/21 acceptance tests, 0/120 real objects**; no target changes. Next bounded step: interrupt a PUT while its body is still transferring, reconcile using real reads and reject partial valid objects or automatic mutating resends.

### Verified native SeaweedFS master SIGKILL recovery — 4 November 2026

[Run 41818110341](https://github.com/GioNob/ouf-deploy/actions/runs/41818110341), job 126534003917, source `85f2d40e35e4ba2db1a5aa47b616b45bc99e5e0e`: **64 tests and four native paths (normal, volume, filer and master crashes) PASS**. Only the master receives SIGKILL after S3 acknowledges the 8,388,865-byte fixture object: exit137/non-OOM, fresh container/namespace/gate, same disk/IP and unchanged peer IDs/start times/restart counts. Firewall rules precede execution and both master listeners are verified closed before release.

Four persisted master files / **1,335 bytes** retain identical stopped/gated hashes. The replacement recovers the same TopologyId; direct loopback readiness/status/lookup probes verify identical locations for the three chunk volume IDs, independent of peer caches. Its own log records filer, S3 and volume registration. The first lookup returns **503 warming up with Retry-After14**; the controller waits **14 seconds** and the **second topology probe succeeds**. No assign/grow or other mutating probe is used.

Complete filer metadata remains identical. Signed TLS S3 GET/HEAD/LIST succeeds on the **first recovery read, with zero additional PUTs** and exact body/hash/MIME. Volume HTTP response traffic rises **13,035→8,411,665 TCP bytes**; this includes overhead and is not an RTO or payload-size measurement. Each of the four paths preserves 10 allowed links and **37 measured network denials**, with zero catch-all denied traffic.

Original archive readback verifies **221 members / 220 checksums / 21 exact sources**, 23 distinct containers, 20 clean stops and three intentional SIGKILLs. [Evidence and limits](https://github.com/GioNob/ouf-deploy/blob/b4cf88b7dec220fb831787313097efdf6708962d/docs/OUF_STORAGE_MASTER_CRASH33_20261104.md). Checkpoint `b4cf88b7dec220fb831787313097efdf6708962d` adds documentation, readback and the original ZIP only.

This is single-master process recovery on retained same-host storage/page cache, not multi-master HA, quorum loss, power loss, host reboot, disk loss or production RPO/RTO. MiniPET remains **18.3/46 (~40% ±10)**, **0/8 gates, 0/21 acceptance tests, 0/120 real objects**; no VPS/target changes. Next bounded step: kill the master/volume/filer/S3 process set in the isolated fixture and restart from retained roots with fresh gates/firewall boundaries and no reseeding.

### Verified native SeaweedFS filer SIGKILL recovery — 4 November 2026

[Run 41816733896](https://github.com/GioNob/ouf-deploy/actions/runs/41816733896), job 126529247006, source `3ec6473670168b524ac06ca7015aca2416b837ae`: **52 tests and three native paths (normal, volume crash, filer crash) PASS**. After S3 acknowledges the 8,388,865-byte object, the filer alone receives SIGKILL (exit137, non-OOM), before any object body read. Master, volume, S3 and client retain IDs/start times/restart counts. A fresh filer container/namespace/gate reuses the same metadata root and IP; rules are installed and both listeners verified closed before process release.

**40 LevelDB2 files / 5,272 bytes** retain identical hashes between stopped storage and the gated replacement. The new filer returns the **entire original metadata JSON**, including timestamps, inode, owner/ACL/ETag/write-id and all three chunk references (4,194,304 + 4,194,304 + 257 bytes), via a direct metadata-only GET from the allowed S3 namespace. Its HTTP response counter rises **0→1,951 TCP bytes**. Full signed TLS S3 GET/HEAD/LIST succeeds on the **first recovery read, with zero new PUTs**; volume HTTP response traffic increases **12,515→8,409,733 bytes**. These counters include network overhead and are not payload-size or performance/RTO measurements.

All three paths preserve 10 allowed links and **37 measured denials each**, with zero catch-all denied traffic. Original archive readback verifies **158 members / 157 checksums / 20 exact sources**, 17 distinct containers, 15 clean final stops and two intentional SIGKILLs. [Evidence and limits](https://github.com/GioNob/ouf-deploy/blob/4bc315fc25d2edb5b87105806fc1216bbdd061d1/docs/OUF_STORAGE_FILER_CRASH33_20261104.md). Checkpoint `4bc315fc25d2edb5b87105806fc1216bbdd061d1` retains documentation, readback results and the original ZIP only.

Scope is process-crash recovery with same-host storage/page cache, not power loss, disk loss, HA or production RPO/RTO. LevelDB physical equality is checked before restart execution; logical metadata equality is checked after reopening. MiniPET remains **18.3/46 (~40% ±10)**, **0/8 gates, 0/21 acceptance tests, 0/120 real objects**; no target changes. Next bounded step: SIGKILL the master in the isolated lab, verify registration/topology recovery and the acknowledged object with retained peer roles, no reseeding and firewall rules before execution.

### Verified native SeaweedFS volume SIGKILL recovery — 4 November 2026

[Run 41814532710](https://github.com/GioNob/ouf-deploy/actions/runs/41814532710), job 126521953635, source `c3eb9b8d267463557c872ad278713321ae8a1dc8`: **42 tests plus normal and volume-crash native qualification PASS**. After S3 acknowledges the 8,388,865-byte object, the volume process receives SIGKILL (exit 137, non-OOM), before any body read. Master, filer, S3 and client retain their identities and start times. The replacement volume uses the same data and IP, a fresh container/namespace/gate, and firewall rules installed with both listeners closed before process release.

Recovery succeeds on the **first read, with zero recovery PUTs**, preserving exact body SHA-256, MIME, HEAD and complete LIST results. The restored volume's response counter rises from **0 to 8,398,214 TCP response bytes**, demonstrating traffic from that volume; this is network traffic including headers, not an exact payload or performance measurement. Seven stopped volume data files total 8,389,064 bytes and retain their original hashed prefixes after recovery.

Both paths preserve 10 allowed links and all **37 measured network denials**; catch-all denied counters remain zero. Independent readback verifies the original archive's **101 members / 100 checksums / 19 exact sources**, 11 distinct containers, ten clean final stops and the intentional SIGKILL. [Evidence and limits](https://github.com/GioNob/ouf-deploy/blob/c0322cf5ee334474bd7867207c9f7c759924aa5a/docs/OUF_STORAGE_VOLUME_CRASH33_20261104.md). Checkpoint `c0322cf5ee334474bd7867207c9f7c759924aa5a` adds documentation, readback results and the original evidence archive only.

This proves process-crash recovery on retained same-host storage, with the host page cache preserved. It does not establish power-loss durability, host reboot recovery, disk-loss recovery or production RPO/RTO. MiniPET remains **18.3/46 (~40% ±10)**, **0/8 gates, 0/21 acceptance tests, 0/120 real objects**; no VPS or target changes. Next bounded step: SIGKILL the filer in this isolated laboratory, then recover metadata and the acknowledged object without reseeding, with firewall rules installed before restart.

### Verified native SeaweedFS role network isolation — 4 November 2026

[Run 41812944892](https://github.com/GioNob/ouf-deploy/actions/runs/41812944892), job 126516457297, source `57c9959eda87542c8ac327467e0c30c74718c4ee`: **32 tests and native isolation qualification PASS**. Four services plus a client use five distinct non-host network namespaces on an internal bridge, with no published ports or container capabilities. A bounded static fixture launcher waits until all namespace firewall rules are installed before executing the exact OCI33 weed binary.

Eight live listeners underpin the complete matrix: **10 required links succeed and 22 forbidden inter-role links fail**. Another **15 DNS/host-gateway probes fail**, including Docker's embedded resolver; every one of the **37 denials** has both a socket error and an increased dedicated nft counter. Rules remain unchanged, and the catch-all denied counter remains zero during observation. Signed TLS S3 PUT followed by GET/HEAD/complete LIST preserves the same 50-byte object before/after probes, with zero mutating retries. Five clean stops and bridge removal verified.

Original archive read back: **49 members / 48 checksums / 18 exact sources**, namespace/container identities, pre/post rules and counters, launcher/compiler digest and hosted S3 parity. [Evidence and limits](https://github.com/GioNob/ouf-deploy/blob/a70dd177b48cbbddf1765fcb116301a7c74fdabd/docs/OUF_STORAGE_LATERAL_ISOLATION33_20261104.md). Checkpoint `a70dd177b48cbbddf1765fcb116301a7c74fdabd` adds documentation and original evidence only.

Scope is IPv4 connection isolation in this single-node-per-role fixture, not authorization of methods on allowed internal ports, internal mTLS, IPv6, host-compromise isolation or production topology. MiniPET remains **18.3/46 (~40% ±10)**, **0/8 gates, 0/21 acceptance tests, 0/120 real objects**; no target changes. Next bounded step: force-stop the volume role and verify recovery of the acknowledged object with network rules restored before service execution.

### Verified S3 fixture credential rotation — 4 November 2026

[Run 41811147933](https://github.com/GioNob/ouf-deploy/actions/runs/41811147933), job 126510424981, source `69680f3e2ca42515110ac3d6ee4f6b1b27dd5415`: **22 tests and native OLD → OLD+NEW → NEW → restart NEW qualification PASS**. Application identity, prefix policy, TLS CA/certificate and storage roots remain unchanged. Only S3 gateways are replaced; master, volume and filer retain their IDs, start times and zero restart counts.

The retired key is rejected for GET, HEAD, LIST, new PUT, overwrite and DELETE, before and after the final restart. **19 expected denials** include unissued/retired keys, unchanged policy boundaries and a wrong new-key secret. HEAD403 is recorded without inventing an absent XML error code. The new key writes one object and reads it back; the original 50-byte object remains unchanged, with two final objects / 91 bytes. Two successful object PUTs plus one bucket creation, zero mutating retries or reseeding.

Original archive verified: **46 members / 45 checksums / 15 exact sources**, four effective public fixture configurations, one TLS fingerprint and seven distinct cleanly stopped containers. [Evidence and limits](https://github.com/GioNob/ouf-deploy/blob/813df331aebf5cd1e3d9b3290da2c4cdd30c9921/docs/OUF_STORAGE_CREDENTIAL_ROTATION33_20261104.md). Checkpoint `813df331aebf5cd1e3d9b3290da2c4cdd30c9921` adds documentation and original evidence only.

This qualifies public synthetic keys and controlled gateway replacement, not hot reload, zero downtime, owner/admin rotation, STS sessions, in-flight revocation or production secret custody. MiniPET stays **18.3/46 (~40% ±10)**, **0/8 gates, 0/21 acceptance tests, 0/120 real objects**; no target changes. Next bounded step: native inter-role lateral isolation in the disposable SeaweedFS laboratory; the current shared loopback namespace does not qualify that boundary.

### Verified unresolved-object freeze blocking — 4 November 2026

[Run 41809311981](https://github.com/GioNob/ouf-deploy/actions/runs/41809311981), job 126504250931, source `2d3d8a41121751abad9da9ab4849fa1112dd1676`: **54 tests PASS; three positive restore regressions and two native negative cases PASS**. Missing objects require complete LIST plus explicit GET404 NoSuchKey and HEAD404. Same-length corruption is detected from actual bytes despite apparently valid hash metadata; PostgreSQL rejects the observed corrupt hash with CONFLICT.

Both negative cases retain DRAINING epoch2/version1, the original ACK, PENDING intent and four exact events across an immediate PostgreSQL restart. Native SQL confirms EXISTING_PENDING, FENCED and RECONCILE_REQUIRED before and after restart. No recovery PUT, common cut, dump or restore is produced for unresolved states. These are constructed negative fixture states, not another HTTP response-loss injection.

Original archive verified: **616 members / 615 checksums / 28 exact source and input hashes**, SQL/recovery logs and 52 distinct cleanly stopped containers across five paths. [Evidence and limits](https://github.com/GioNob/ouf-deploy/blob/320827d2bab425dd742bfc2e99178c529470365e/docs/OUF_STORAGE_UNRESOLVED33_20261104.md). Checkpoint `320827d2bab425dd742bfc2e99178c529470365e` adds documentation and original evidence only.

MiniPET remains **18.3/46 (~40% ±10)**, **0/8 gates, 0/21 acceptance tests, 0/120 real objects**. No target operation or production recovery claim. Next bounded SW-WP3 step: S3 credential rotation in the disposable fixture, validating the new key, rejection of the retired key and unchanged object reads.

### Verified HTTP response loss after S3 PUT — 4 November 2026

[Run 41807405448](https://github.com/GioNob/ouf-deploy/actions/runs/41807405448), job 126497752202, source `0bd31c7507571f6a0538130805d546ced624292d`: **42 tests PASS; normal, SIGKILL and response-loss paths all PASS**. A single-use loopback relay forwards one 45-byte PUT, consumes upstream HTTP200 and closes the client connection without sending any response bytes. The client observes RemoteDisconnected; the durable intent stays PENDING. Re-reservation returns EXISTING_PENDING, preserves the ledger, and issues zero recovery PUTs. Reconciliation uses actual S3 GET/HEAD/LIST before the quiesced cut and independent restore.

Original archive verified: **423 members / 422 checksums / 26 exact source and input hashes**, three dump/ledger pairs and 36 distinct cleanly stopped containers. Each path reconciles two synthetic objects / 77 bytes and six AccessDenied results. Evidence includes the suppressed response, preserved event prefix, original crash recovery and restored SQL diagnostics.

[Evidence and limits](https://github.com/GioNob/ouf-deploy/blob/e79ddfdc8d487453f3797108fcbf8342a9a3a8a1/docs/OUF_STORAGE_RESPONSE_LOSS33_20261104.md). Checkpoint `e79ddfdc8d487453f3797108fcbf8342a9a3a8a1` adds documentation and original evidence only. Scope is one completed PUT on an unversioned fixture bucket; no streaming/multipart, general exactly-once, target fencing, second local restore or production RPO/RTO claim. MiniPET remains **18.3/46 (~40% ±10)**; **0/8 gates, 0/21 acceptance tests, 0/120 real objects**. Next bounded step: unresolved outcome without a valid readback must keep the intent pending and block freeze without automatic resend.

### Verified post-PUT crash recovery — 4 November 2026

[Run 41805145586](https://github.com/GioNob/ouf-deploy/actions/runs/41805145586), job 126490204017, source `8b109725e8f7424e59d799c29e3a2550ee539ad7`: **33 tests PASS; normal and crash paths PASS**. A distinct worker receives SIGKILL after one completed S3 PUT and before catalog ACK. PostgreSQL immediate restart preserves the original ACK, pending intent and event history; re-reservation returns EXISTING_PENDING and recovery issues no further PUT. Both paths complete the quiesced common cut and independent PostgreSQL/S3 restore.

Original successful archive read back: **284 members / 283 checksums / 24 exact source and artifact hashes**, two dump/ledger pairs, native PostgreSQL crash-recovery log and 24 distinct cleanly stopped SeaweedFS containers. Each path reconciles two synthetic objects / 77 bytes and six S3 AccessDenied results. Restored SQL diagnostics now preserve both query and denial.

First run 41803868175 remains FAILED and retained. It exposed an incorrect gapless-event-ID assertion; the correction requires strictly increasing IDs, all six exact event payloads and an unchanged committed prefix, with regression against the original failed archive. No production schema or data changed.

[Evidence, original archives and limits](https://github.com/GioNob/ouf-deploy/blob/257fedc163738aadaecf55a6af6020a7b19678a5/docs/OUF_STORAGE_CRASH33_20261104.md). Checkpoint `257fedc163738aadaecf55a6af6020a7b19678a5` contains documentation/evidence only. Scope is post-completed-PUT worker death on an unversioned fixture, not HTTP-response loss, in-flight/multipart failure, versioned deduplication, host power loss or target acceptance. Progress remains 18.3/46 = 39.78%, approximately 40% ±10.

### Generation33 candidate qualification

[Commit 9fbe9ef7](https://github.com/GioNob/ouf-deploy/commit/9fbe9ef71ba296523e904686d7409b4c9150209f) binds the verified generation33 image, cohort and runtime evidence into the current plan, retains original archives, and introduces physical PostgreSQL PITR and generation33 TLS rotation laboratories. All 53 workflows on the previous checkpoint completed successfully before this update.

**Generation33 is the current technical candidate, not admitted.** Its image [41782068047](https://github.com/GioNob/ouf-deploy/actions/runs/41782068047) and cohort/runtime [41794344274](https://github.com/GioNob/ouf-deploy/actions/runs/41794344274) passed all jobs. The complete historical generation32 plan is preserved at canonical SHA256 `228760f4c060831aada7b3bcb200a01e9c3681fbdced59ca9ca1ea9c53021326`, including earlier qualifications and failures.

### Verified generation33 evidence

- Binary `c301b4f487f17f4d9b8dfe1b26885ec4ea6141e1ace73b8dfaadff70bd714dfc`; OCI `sha256:5bfda2ef577b3c33216b82fb3eb1bed3ad76842ed13fc0a114ef94084b20da4d`.
- 214 modules / 1,532 compiled packages; all ten originally identified archived modules are absent. Fresh raw vulnerability counts are zero in all five severities. This does not establish complete maintenance/support.
- Main hosted regression events: 6,656 PASS / 12 skip; server 984, storage 58, shell 306, race 185, DB compatibility 3, root IAM 24 and nested IAM 18.
- Exact cohort receipt `5b28de1dd43fca337064d41439d302d53dc7f470640fe3fc0d8d1292b1ec02dc` reproduced locally and hosted. 214 authentic original ZIPs, 302 legal texts, seven upstream MPL archives, six modified local MPL files and separately retained original/modified Iceberg provenance. Vendor build-info h1 fields remain empty; original input hashes are not claimed for modified code.
- Runtime original ZIP: 68 members, 67 internal checksums and 18 exact source bindings verified. Five synthetic objects / 8,388,702 bytes, 110 backup files / 8,417,383 bytes, independent cold restore, complete body/MIME GET/HEAD comparisons, 23 S3 cases, two TLS rejections and two egress denials; 12 distinct containers stopped cleanly.
- Independent publisher verification is hosted. Full OCI archive remains temporary CI custody; no durable-image-custody claim. Lifecycle metadata covers 213 modules at 173 non-archived/non-disabled repositories; current modernc.org/b GitLab status and complete version/patch support remain unresolved.

### Recovery and new qualification

[Generation32 coordinated recovery 41782068196](https://github.com/GioNob/ouf-deploy/actions/runs/41782068196) restored PostgreSQL17.11 into an independent cluster and reconciled three synthetic S3 objects / 1,064 bytes. Its result is historical and is not transferred to generation33.

[Native PostgreSQL publication fence 41794344238](https://github.com/GioNob/ouf-deploy/actions/runs/41794344238) passed 23 native checks and seven offline tests. Two concurrent clients, persistent epoch/version CAS, rejection of late publication, restart, and complete-byte reconciliation before freeze are verified. The original ZIP contains 104 members / 103 checksums / ten source bindings. This is a fixture with two local synthetic file effects, not external S3 or production-writer fencing.

### Latest verified checkpoint — 4 November 2026

[Readback and limits](https://github.com/GioNob/ouf-deploy/blob/2e341933c3e5969864e4519373d440b0b48eebe1/docs/OUF_STORAGE_PITR_TLS_READBACK_20261104.md).

- Physical PostgreSQL PITR [41796664103](https://github.com/GioNob/ouf-deploy/actions/runs/41796664103): SUCCESS, confirmed by the current GitHub run record. Retained readback records named-point recovery, two of three rows recovered and rejection of missing required WAL. The later acknowledged write is deliberately outside the recovery point: no RPO-zero or coordinated S3 recovery claim.
- Exact generation33 TLS rotation [41796664091](https://github.com/GioNob/ouf-deploy/actions/runs/41796664091): SUCCESS, confirmed by the current GitHub run record. Retained readback records four positive and four negative trust cases, unchanged body/MIME and unchanged storage containers. No hot-reload, zero-downtime, mTLS, S3-credential-rotation or lateral-isolation claim.
- Reporting correction on exact head `2e341933c3e5969864e4519373d440b0b48eebe1`: [41800483496](https://github.com/GioNob/ouf-deploy/actions/runs/41800483496), job `126474734202`, SUCCESS. The job log was read: **71 tests PASS**, input manifest/checksums, attestation and artifact retention steps succeeded. This closes the pending hosted check for the percentage projection; weights and credits remain unchanged. Other workflows on this head were still running at this observation; no complete-head all-green claim.
- This continuation checked GitHub run records and the plan job log; it did not independently download/reverify the original PITR/TLS archives or inspect the VPS.

Completed single step: generation33 quiesced common-cut fixture **PASS** in [run 41802094297](https://github.com/GioNob/ouf-deploy/actions/runs/41802094297), job 126480073815, exact source `a31b2be7cfdea1ddaaa0c7e0902a6f325c974ddc`. 22 tests PASS. Independent local readback verified the retained original ZIP: 136 members / 135 checksums / 22 source hashes, exact dump and common-cut manifest, identical source/restored ledger and 12 distinct cleanly stopped containers. Two PostgreSQL17.11 clusters are independent and stopped cleanly.

Two synthetic objects / 77 bytes are reconciled; 104 cold-copy files / 22,275 bytes. The original ACK is preserved and an ambiguous external effect is reconciled without resending. Six S3 AccessDenied results cover new PUT, overwrite and DELETE before and after restore. This proves a stopped/restarted **sole fixture identity** with Read/List permissions and a quiesced logical-dump/cold-copy cut; not online target fencing, coordinated physical PITR, production RPO/RTO or acceptance.

[Scope, original archive, readback and limits](https://github.com/GioNob/ouf-deploy/blob/d19999152763edfc9dc2dbf277dfcb1645392fdf/docs/OUF_STORAGE_COMMON_CUT33_20261104.md). Hosted body/MIME evidence and indices are verified; S3/cold payloads are not exported for a second local restore. The restored cluster reuses one SQL diagnostic slot; explicit ledger snapshots are preserved, and no complete raw SQL transcript is claimed. Checkpoint `d19999152763edfc9dc2dbf277dfcb1645392fdf` changes documentation/evidence only. No additional progress credit and no target operation.

Next single step: lose the S3 HTTP response after the write and reconcile the same durable intent without blindly resending PUT.

### Progress and limits

Engineering estimate **40% ±10 points: 18.3/46 weighted credits**. Only recovery work-package credit changes from 35 to 45, grounded in the retained coordinated-recovery and native-fence proofs. The separately verified PITR/TLS laboratories receive no additional credit at this checkpoint; target-wide coordinated recovery and acceptance remain open.

**0/8 gates, 0/21 acceptance tests, 0/120 real objects copied.** Licence/redistribution review, complete maintenance and patch ownership, durable custody, coordinated physical PITR and target recovery cut, target fencing, representative RPO/RTO, lateral isolation and target bindings remain OPEN. Original PET/Matrix authority and append-only checkpoint history are preserved.

Preserved: **17 consumed scopes / 52 cumulative Engine GET; Teatri/M1 8/8 technical + 6/6 functional; Farmacie 61 rows / 10 OPEN / STRING**. No replay, reset, grant or target operation.


### Storage33 — post-marker crash implementation and exact readback queued (2026-11-04)

Producer `18b93a7f6f704a6b9f7c959c9f6c088eb5b1cb31`: twelfth bounded scenario holds the unchanged volume binary at the first DAT rename syscall entry, after successful marker and directory fsync. External read-only ptrace tracks all threads including clones; marker, both copies and old DAT/IDX must be retained before the joint SIGKILL. Recovery must roll forward the exact temporary inodes, relocate the live witness, and preserve S3, metadata and network boundaries without another vacuum. Ten new pure tests and twelve existing precommit tests PASS locally; Linux mechanics test skipped on Windows and required in CI.

- Native run [41864590947](https://github.com/GioNob/ouf-deploy/actions/runs/41864590947), job126695427394: **QUEUED**, no runner assigned/no steps executed at last observation. Post-marker native qualification remains **OPEN**, no new native PASS claimed.
- Independent readback source `9493fb952256f00f0c06dbc37521c132a6e33340`, run [41865783844](https://github.com/GioNob/ouf-deploy/actions/runs/41865783844): **QUEUED**. Pinned to the exact producer/run/attempt1; bounded observation, full original ZIP/member/source verification, precommit plus post-marker evidence, 157 tests without skips/12 scenarios/60 clean final stops required. No second native lab. Original and receipt retained for90days if produced; no durable Git custody of the future ZIP claimed.
- [Dossier](https://github.com/GioNob/ouf-deploy/blob/9493fb952256f00f0c06dbc37521c132a6e33340/docs/OUF_STORAGE_POSTMARKER_CRASH33_20261104.md). Previous evidence and precommit PASS retained. Resume by inspecting these exact two runs before any rerun or further phase.

MiniPET18.3/46=39.78%,0/8gates,0/21AT,0/120real objects unchanged. Inter-rename/power loss/RPO/RTO remain OPEN. No deployment/admission/merge/target operation; MinIO unchanged.

### Storage33 — original artifact acquired; Actions status discrepancy (2026-11-04)

Native producer `18b93a7f`, run41864590947/job126695427394 has completed log output through 16:22:07Z: **157 tests PASS**, including the actual Linux ptrace/clone/SIGKILL mechanics test; successful evidence attestation and original artifact upload. Original artifact [13343120116](https://github.com/GioNob/ouf-deploy/actions/runs/41864590947/artifacts/13343120116):3447908bytes, SHA256`be6f6164165c07bf1e8982cc0a14b8371c46177ba109135cea26134a48e7a4e0`. Native run/job metadata still reports queued with no runner/steps, so terminal CI success is **not yet confirmed**.

GitHub reports an [Actions/Pages incident](https://www.githubstatus.com/incidents/xr3myzj7ms51), Actions partial outage at16:17Z. This is consistent with the observed discrepancy; causation for this individual run is not independently established. Strict readback41865783844 remains unchanged and waits for native terminal success.

Commit`5436f3fe633f27f2cb45782ac8559f784c2bd7c5` adds a separate read-only [artifact evidence run41867565360](https://github.com/GioNob/ouf-deploy/actions/runs/41867565360), pinned to exact original artifact ID/size/digest/producer. It verifies the same complete contents while retaining native run/job snapshots and explicitly separating `nativeTerminalSuccessConfirmed` from content verification. No native resubmission, no relaxed gate and no evidence deletion. Full post-marker result remains pending this readback and CI reconciliation. MiniPET/MinIO/target authority unchanged.

### Inter-rename execution tracking (2026-11-04)

Native [run41870302570](https://github.com/GioNob/ouf-deploy/actions/runs/41870302570), producer5ac67de1/job126715227789 is executing the preserved suite; Linux ptrace mechanics tests passed. Exact-source [readback41871254673](https://github.com/GioNob/ouf-deploy/actions/runs/41871254673), verifier15d6ac5b/job126718618427, acquires the original artifact before waiting for terminal metadata, independently reconstructs the mixed IDX/DAT bytes and requires successful native run/job afterward. No native resubmission. Final inter-rename qualification remains PENDING.