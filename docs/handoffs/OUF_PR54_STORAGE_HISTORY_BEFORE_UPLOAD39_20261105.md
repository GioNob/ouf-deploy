This draft qualifies a SeaweedFS replacement for MinIO and the associated SDK/dependency changes. MinIO remains active. Repository work and isolated qualification do not grant target deployment, cutover, merge or admission.

### Latest checkpoint — application writer source map

[Checkpoint 783f883e](https://github.com/GioNob/ouf-deploy/commit/783f883e66403a860d913e0c72f036b9dd37f7c4) · [writer dossier](https://github.com/GioNob/ouf-deploy/blob/783f883e66403a860d913e0c72f036b9dd37f7c4/docs/OUF_STORAGE_APPLICATION_WRITER_MAP_20261105.md) · [full readback receipt](https://github.com/GioNob/ouf-deploy/blob/783f883e66403a860d913e0c72f036b9dd37f7c4/evidence/storage-writer-map-hosted-readback-20261105.json).

**Pinned source-map readback PASS:** [run41986479752](https://github.com/GioNob/ouf-deploy/actions/runs/41986479752), producer10658bdd, job127108301839 completed/success. All256files/1519734bytes verified:248production Java files (Onboarding100,UDP88,Ingestion60),7SQL migrations and1administrative bootstrap. Eight lexical mutation callsites are reviewed; they are not eight proven active writers. Six key Onboarding files match the exact source reported installed by V38; no fresh target observation is claimed.

Hosted and local results match. Original artifact13396580480,24957bytes,SHA256e9216d08…,10members/9checksums/3verifier source bindings; retention until2027-02-03. The complete source index and hashes are committed.

**Concrete integration gap:** Onboarding generates the object UUID inside PUT and records the delegated upload attempt only after the storage effect. The delegated callback runs inside a database transaction holding an advisory lock. Next bounded implementation: durable upload intent and stable object identity before PUT, short reserve/finish transactions, and reconciliation of ambiguous effects in the existing Onboarding owner. Preserve tenant/capability/idempotency/file/job contracts.

The map also covers indirect Ingestion lake writes, outbox ACK/watermarks, Onboarding profile DB writes, UDP shadow rebuild, reconciliation, implemented purge/compaction methods and privileged administration. Existing local lease/version checks are retained; their composition with a global storage drain/fence remains unqualified. Runtime writer inventory and external-consumer absence remain OPEN.

### CI follow-up, with failures preserved

Checkpoint8e829f08 had49general workflows SUCCESS and1FAILED:41976789581/job127077493752. The negative authorization test recomputed an expiry using a later clock value, violating the original finite window/authority binding before reaching its intended stage-history check.

Test-only correction ef093e41 samples initial time once, restores the exact original decision and exercises +120seconds deterministically. **All13tests in the affected suite passed**, including the former failure, in41985050242/job127103721017. That workflow was subsequently cancelled by the next push under existing concurrency policy; no full-workflow PASS is claimed. General CI on the final documentation head remains pending. Production authorization checks were not relaxed. [Original failure diagnosis](https://github.com/GioNob/ouf-deploy/blob/783f883e66403a860d913e0c72f036b9dd37f7c4/evidence/chatbot-cohort-clock-fixture-failure-20261105.json).

### Preserved storage qualifications

Fresh-runner restore from immutable exports:44Linux tests PASS; native41976132880 and independent/local readback agree. PostgreSQL basebackup/WAL and SeaweedFS cold backup restore the same named point, physical identity, FROZEN ledger and ACK history without producer working directories or reseeding. Two objects/77bytes, persistent SQL fences, three S3 denials and clean shutdowns verified. Artifacts13391179599/13391443633 preserve the original export unchanged.

Physical common-cut:35tests, positive PITR and missing-WAL rejection PASS (41914041465), original13362874826. Initial readiness failure41913004716 remains preserved. Compaction:189tests/14native scenarios PASS, including four crash points; native41886227100/readback41886345188 and all negative attempts unchanged. Candidate generation33 remains SeaweedFS4.52/binary c301b4f4…/OCI5bfda2ef….

### Remaining acceptance

MiniPET **18.3/46=39.78%**,0/8gates,0/21acceptance tests,0/120real objects. Application writer integration, complete current runtime bindings, representative RPO/RTO, concurrent/power-loss coverage, durable custody, maintenance/licence review and migration acceptance remain open.

Teatri/M1 8/8technical+6/6functional and the same Farmacie61rows/10OPEN/STRING remain preserved. No new upload/profiling, replay/reset/grant/target operation. Storage completion precedes residual M2 E2E, graph/search and later vertical/API work.

[Previous PR description preserved verbatim](https://github.com/GioNob/ouf-deploy/blob/783f883e66403a860d913e0c72f036b9dd37f7c4/docs/handoffs/OUF_PR54_STORAGE_HISTORY_BEFORE_WRITER_MAP_20261105.md) · [updated MiniPET](https://github.com/GioNob/ouf-deploy/blob/783f883e66403a860d913e0c72f036b9dd37f7c4/docs/OUF_MINIO_SEAWEEDFS_MINIPET_v1_0_20261102.md).
