This draft implements and qualifies a SeaweedFS replacement for MinIO, including removal of legacy AWS SDK dependencies and exact candidate/source/cohort bindings. MinIO remains active. Work is confined to repository development and disposable qualification laboratories; no target cutover, deployment, merge or admission is performed.

### Latest verified checkpoint — restore from exported backups

[Checkpoint 8e829f08](https://github.com/GioNob/ouf-deploy/commit/8e829f0879d4b5e75f3312676a45f875a0f6acdc) · [dossier](https://github.com/GioNob/ouf-deploy/blob/8e829f0879d4b5e75f3312676a45f875a0f6acdc/docs/OUF_STORAGE_EXPORTED_RESTORE33_20261105.md) · [full evidence receipt](https://github.com/GioNob/ouf-deploy/blob/8e829f0879d4b5e75f3312676a45f875a0f6acdc/evidence/storage-exported-restore33-hosted-readback-20261105.json).

**44 Linux tests and fresh hosted restore PASS.** [Run41976132880](https://github.com/GioNob/ouf-deploy/actions/runs/41976132880), exact producer c096897c, attempt1 completed/success. Native job127075295372 and independent readback127076271029 both succeeded; local readback reproduces the hosted result exactly.

The new execution restores the immutable export from physical-cut producer7444df03/run41914041465: PostgreSQL basebackup, required post-base WAL and SeaweedFS cold backup. No producer working directories, new source cluster, replacement basebackup or object seeding. All1391files/114017011bytes verified;15empty PostgreSQL directories reconstructed, zero state files generated; native pg_verifybackup passed.

PostgreSQL reaches the same named target, physical system identity and FROZEN ledger/ACK/event history. Three bounded read-only readiness probes precede SQL. After promotion, reserve/finish remain FENCED. S3 starts only after the DB gate passes:2objects/77bytes and complete body/metadata parity,3explicit denied mutations. Four storage containers and one PostgreSQL clone stop cleanly; original ZIP and extracted inputs remain unchanged.

Independent and local readback: **86members/85checksums/34exact current sources**, plus213checksums/30original sources and every packaged backup byte. Restore artifact13391179599,6128331bytes,SHA25695b82813…; readback copy13391443633,6121194bytes,SHA256274ab261…. Both retained until2027-02-03 and preserve the original backup export unchanged. No new durable Git ZIP custody is claimed.

### Preserved qualifications

Physical common-cut checkpoint3c4a9c1e:35tests, coordinated PITR and missing-WAL rejection PASS, original artifact13362874826. Required-WAL failure stops before any restored S3 starts. The original readiness failure run41913004716 and its diagnosis/artifacts remain preserved.

Compaction checkpoint74f28277:189tests/14native scenarios PASS, including four crash points; native41886227100/readback41886345188 and all negative attempts unchanged. Candidate generation33 remains SeaweedFS4.52, binary c301b4f4…, OCI5bfda2ef…. Logical common-cut, ambiguous outcomes, image/cohort/runtime, TLS/credential rotation and role isolation retain their exact source and scope.

### Remaining scope and next bounded step

The fixture gap “restore from exported backups on a fresh hosted execution” is now closed. Next: review residual MiniPET gates and map actual OUF PostgreSQL/S3 application writers and their fence integration requirements, without changing the target.

MiniPET **18.3/46=39.78%**,0/8gates,0/21acceptance tests,0/120real objects. Target writer bindings, representative RPO/RTO, online/concurrent/power-loss coverage, durable custody, maintenance/licence review and migration acceptance remain open. Separate lateral-isolation results are not automatically composed with this fixture.

Storage completion precedes residual M2 E2E, graph/search and later vertical/API scheduling. Preserved: Teatri/M1 8/8technical+6/6functional; Farmacie61rows/10OPEN/STRING;17consumed scopes/52cumulative Engine GET. No replay/reset/grant/target operation.

[Previous PR description preserved verbatim](https://github.com/GioNob/ouf-deploy/blob/8e829f0879d4b5e75f3312676a45f875a0f6acdc/docs/handoffs/OUF_PR54_STORAGE_HISTORY_BEFORE_EXPORTED_RESTORE_20261105.md) · [earlier complete evidence history](https://github.com/GioNob/ouf-deploy/blob/3c4a9c1e2658270020531c605ab54efe5ef911b9/docs/handoffs/OUF_PR54_STORAGE_HISTORY_BEFORE_PHYSICAL_CUT_20261104.md) · [updated MiniPET](https://github.com/GioNob/ouf-deploy/blob/8e829f0879d4b5e75f3312676a45f875a0f6acdc/docs/OUF_MINIO_SEAWEEDFS_MINIPET_v1_0_20261102.md).
