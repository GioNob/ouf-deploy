This draft implements and qualifies a SeaweedFS replacement for MinIO, including removal of legacy AWS SDK dependencies and exact candidate/source/cohort bindings. MinIO remains active. Work is confined to repository development and disposable qualification laboratories; no target cutover, deployment, merge or admission is performed.

### Latest verified checkpoint — coordinated physical recovery

[Checkpoint 3c4a9c1e](https://github.com/GioNob/ouf-deploy/commit/3c4a9c1e2658270020531c605ab54efe5ef911b9) · [dossier](https://github.com/GioNob/ouf-deploy/blob/3c4a9c1e2658270020531c605ab54efe5ef911b9/docs/OUF_STORAGE_PHYSICAL_COMMON_CUT33_20261104.md) · [full evidence receipt](https://github.com/GioNob/ouf-deploy/blob/3c4a9c1e2658270020531c605ab54efe5ef911b9/evidence/storage-physical-cut33-hosted-readback-20261104.json).

**35 Linux tests, native coordinated recovery and missing-WAL rejection PASS.** [Run41914041465](https://github.com/GioNob/ouf-deploy/actions/runs/41914041465), exact producer7444df03, attempt1: native job126868857170 and separate original-readback job126870953332 completed/success.

PostgreSQL17.11 physical basebackup plus post-base WAL recover the FROZEN catalog at the named point bound to stopped SeaweedFS33 cold roots. Exact ACK/event history and physical system identity are preserved. A post-target diagnostic canary is excluded; no object acknowledgement is deliberately lost. After promotion, persistent SQL fencing rejects reserve/finish, and S3 still rejects new PUT, overwrite and DELETE. Two objects/77bytes and complete body/metadata parity match.

A separate fresh copy with required WAL missing terminates before any restored S3 process starts. Positive recovery uses complete original backups and independent directories.12clean storage stops,2clean PostgreSQL stops and1expected failed-recovery termination verified.

Independent hosted and local readback agree: **214members/213checksums/30exact sources**, all **1391 packaged backup files /114017011bytes** checked. Original artifact13362874826 (6018250bytes,SHA25633b5a712…), unchanged nested copy13364970618 retained until2027-02-02. No second native restore from the exported package or new durable Git ZIP custody is claimed.

First run41913004716 remains FAILED and preserved with artifacts13364540297/13363806513 and [complete diagnosis](https://github.com/GioNob/ouf-deploy/blob/3c4a9c1e2658270020531c605ab54efe5ef911b9/evidence/storage-physical-cut33-first-failure-20261104.json). pg_ctl startup success preceded SQL availability; bounded read-only pg_isready probes corrected that assumption without relaxing target/ledger/fence checks.

### Preserved qualifications and next bounded step

Previous checkpoint74f28277:189tests/14native scenarios PASS, including four compaction crash points; native41886227100/readback41886345188 and all negative attempts are unchanged. Candidate generation33 remains SeaweedFS4.52, binary c301b4f4…, OCI5bfda2ef…. Existing logical common-cut, ambiguous outcomes, image/cohort/runtime, TLS/credential rotation, role isolation and other evidence retain their exact sources and scope.

**Next:** execute recovery on a fresh runner using only the exported basebackup/WAL/cold-backup package and the exact candidate, with no producer working directories. The current second runner verifies every packaged byte; it does not execute that second restore.

### Progress and original scope

MiniPET **18.3/46=39.78%**,0/8gates,0/21acceptance tests,0/120real objects. Target writer bindings, representative RPO/RTO, online/concurrent/power-loss coverage, durable custody, maintenance/licence review and migration acceptance remain open. Separate lateral-isolation results are not automatically composed with this common-cut fixture.

Storage completion precedes residual M2 E2E, graph/search and later vertical/API scheduling. Preserved: Teatri/M1 8/8technical+6/6functional; Farmacie61rows/10OPEN/STRING;17consumed scopes/52cumulative Engine GET. No replay/reset/grant/target operation.

[Complete prior PR description and evidence history, preserved verbatim](https://github.com/GioNob/ouf-deploy/blob/3c4a9c1e2658270020531c605ab54efe5ef911b9/docs/handoffs/OUF_PR54_STORAGE_HISTORY_BEFORE_PHYSICAL_CUT_20261104.md) · [updated MiniPET](https://github.com/GioNob/ouf-deploy/blob/3c4a9c1e2658270020531c605ab54efe5ef911b9/docs/OUF_MINIO_SEAWEEDFS_MINIPET_v1_0_20261102.md) · [initial cloud handoff](https://github.com/GioNob/ouf-deploy/blob/676f626814d3f3e5d42fea273a4776062758fe59/docs/handoffs/OUF_STORAGE_CLOUD_HANDOFF_20261104.md).
