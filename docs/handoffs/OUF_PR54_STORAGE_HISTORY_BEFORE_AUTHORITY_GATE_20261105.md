# PR54 e handoff prima del gate autorità — copia storica del 5 novembre 2026

## Onboarding PR54

Managed-file uploads now reserve durable intent and a stable key before S3 I/O. Repeats reconcile the same object without a second PUT. The new owner-local recovery protocol drains uploads, reconciles pending effects with the existing finite budget, and refuses a frozen cut while any intent remains unresolved. Generation and deadline are checked again before ACK, including after storage I/O.

Both upload routes retain their existing ownership/idempotency semantics and V38 receipts. Network I/O remains outside database transactions. The coordinated fixture now exercises the actual owner tables through physical PostgreSQL recovery alongside the frozen SeaweedFS33 objects.

Validation on source `bf6bcf926727b5ea738155ac70a71b73f1b21f68`:
- [Owner regressions 41995519285](https://github.com/GioNob/ouf-source-onboarding/actions/runs/41995519285): **24 native owner scenarios + 8 API/storage tests PASS**, with no failures, errors or skips. Includes drain during PUT, concurrent reconciliation, missing/corrupt objects, stale generations, durable budgets and expiry during GET.
- [Physical common cut and independent readback 41995519200](https://github.com/GioNob/ouf-source-onboarding/actions/runs/41995519200): **both jobs SUCCESS**. Basebackup precedes actual V39 intents; named WAL target and frozen cold storage are restored from exported tar files into new directories. Missing WAL blocks S3 startup; restored owner tables match exactly before S3 starts. Two synthetic objects/36 bytes preserved, six obsolete-writer PUTs denied, twelve storage and two PostgreSQL clean stops.
- Independent runner verified **32 ZIP members, 31 checksums, 263 source bindings and all 1,671 backup files**. Five semantically altered copies were rejected even after outer checksums were recalculated. This readback is not a second native restore.
- **Final source CI 8/8 SUCCESS**, including [full PR CI41995525291](https://github.com/GioNob/ouf-source-onboarding/actions/runs/41995525291) and [push CI41995519218](https://github.com/GioNob/ouf-source-onboarding/actions/runs/41995519218), blocking image scan and container boot. General module suite:365 executed PASS;24 native cases skipped there and executed in the dedicated job.

[Dossier](https://github.com/GioNob/ouf-deploy/blob/fd5e774c48b00c410ba203bf407b9373640a3bb2/docs/OUF_STORAGE_ONBOARDING_COMMON_CUT_20261105.md), [exact qualification receipt](https://github.com/GioNob/ouf-deploy/blob/fd5e774c48b00c410ba203bf407b9373640a3bb2/evidence/onboarding-common-cut-qualified-20261105.json), [handoff](https://github.com/GioNob/ouf-deploy/blob/fd5e774c48b00c410ba203bf407b9373640a3bb2/docs/handoffs/OUF_STORAGE_ONBOARDING_RECOVERY_HANDOFF_20261105.md), [prior PR descriptions preserved](https://github.com/GioNob/ouf-deploy/blob/fd5e774c48b00c410ba203bf407b9373640a3bb2/docs/handoffs/OUF_PR54_STORAGE_HISTORY_BEFORE_OWNER_CUT_20261105.md).

Both failed attempts remain preserved: initial recovery response projection mismatch, and Python formatting of PostgreSQL WAL placeholders. The earlier successful cut and subsequent deadline hardening are recorded separately. Original artifacts and unchanged independent copies are retained in Actions until2027-02-03; no third local ZIP readback is claimed.

Limits: recovery methods are internal and introduce no operational endpoint, scheduler or reopen authority. The fixture physically stops storage and restricts its S3 identity; Java alone does not revoke credentials or fence UDP/Ingestion. Operational authority/quiescence binding, mixed rollout, other writers and representative RPO/RTO remain open. No merge, deployment, target operation, source-lock promotion, replay, reset or grant. MinIO and MiniPET18.3/46=39.78% remain unchanged.

## Deploy PR54

## Two-step continuation completed: actual Onboarding owner common cut

1. Implemented owner drain/reconciliation/freeze against the real V39 upload intents, with no duplicate PUT and deadline enforcement through I/O.
2. Qualified the named physical PostgreSQL/SeaweedFS cut, exported-backup restore and obsolete-writer rejection in the isolated fixture.

Application changes remain reviewable in [Onboarding PR54](https://github.com/GioNob/ouf-source-onboarding/pull/54). Deploy evidence checkpoint: `fd5e774c48b00c410ba203bf407b9373640a3bb2`. The previous deploy checkpoint99594c8 completed50/50 workflows successfully; automatic checks triggered by this documentation/evidence checkpoint are separate.

Validation on source `bf6bcf926727b5ea738155ac70a71b73f1b21f68`:
- [Owner regressions 41995519285](https://github.com/GioNob/ouf-source-onboarding/actions/runs/41995519285): **24 native owner scenarios + 8 API/storage tests PASS**, with no failures, errors or skips. Includes drain during PUT, concurrent reconciliation, missing/corrupt objects, stale generations, durable budgets and expiry during GET.
- [Physical common cut and independent readback 41995519200](https://github.com/GioNob/ouf-source-onboarding/actions/runs/41995519200): **both jobs SUCCESS**. Basebackup precedes actual V39 intents; named WAL target and frozen cold storage are restored from exported tar files into new directories. Missing WAL blocks S3 startup; restored owner tables match exactly before S3 starts. Two synthetic objects/36 bytes preserved, six obsolete-writer PUTs denied, twelve storage and two PostgreSQL clean stops.
- Independent runner verified **32 ZIP members, 31 checksums, 263 source bindings and all 1,671 backup files**. Five semantically altered copies were rejected even after outer checksums were recalculated. This readback is not a second native restore.
- **Final source CI 8/8 SUCCESS**, including [full PR CI41995525291](https://github.com/GioNob/ouf-source-onboarding/actions/runs/41995525291) and [push CI41995519218](https://github.com/GioNob/ouf-source-onboarding/actions/runs/41995519218), blocking image scan and container boot. General module suite:365 executed PASS;24 native cases skipped there and executed in the dedicated job.

[Dossier](https://github.com/GioNob/ouf-deploy/blob/fd5e774c48b00c410ba203bf407b9373640a3bb2/docs/OUF_STORAGE_ONBOARDING_COMMON_CUT_20261105.md), [exact qualification receipt](https://github.com/GioNob/ouf-deploy/blob/fd5e774c48b00c410ba203bf407b9373640a3bb2/evidence/onboarding-common-cut-qualified-20261105.json), [handoff](https://github.com/GioNob/ouf-deploy/blob/fd5e774c48b00c410ba203bf407b9373640a3bb2/docs/handoffs/OUF_STORAGE_ONBOARDING_RECOVERY_HANDOFF_20261105.md), [prior PR descriptions preserved](https://github.com/GioNob/ouf-deploy/blob/fd5e774c48b00c410ba203bf407b9373640a3bb2/docs/handoffs/OUF_PR54_STORAGE_HISTORY_BEFORE_OWNER_CUT_20261105.md).

Both failed attempts remain preserved: initial recovery response projection mismatch, and Python formatting of PostgreSQL WAL placeholders. The earlier successful cut and subsequent deadline hardening are recorded separately. Original artifacts and unchanged independent copies are retained in Actions until2027-02-03; no third local ZIP readback is claimed.

Limits: recovery methods are internal and introduce no operational endpoint, scheduler or reopen authority. The fixture physically stops storage and restricts its S3 identity; Java alone does not revoke credentials or fence UDP/Ingestion. Operational authority/quiescence binding, mixed rollout, other writers and representative RPO/RTO remain open. No merge, deployment, target operation, source-lock promotion, replay, reset or grant. MinIO and MiniPET18.3/46=39.78% remain unchanged.

Next pair: bind the internal protocol to existing operational authority and a proven storage-quiescence boundary, then qualify revocation/concurrency/expiry and refusal to reopen without fresh authority. Persistent preference: two steps per continuation, no subagents. All previous storage qualifications are preserved.

## Handoff precedente

# Ripresa storage Onboarding — 5 novembre 2026

Continuare per due passi alla volta, senza subagenti. Prima controllare i branch e i run; non rilanciare prove già concluse senza una modifica o un motivo documentato.

- Deploy:PR54,branch `feat/m2-discovery-complete-profile-20261029`; checkpoint antecedente99594c878a3130a353531841e91c53c38741dbd0 con50/50CI verde. Leggere l'HEAD effettivo del commit che contiene questo handoff.
- Onboarding:PR54,branch `feat/storage-upload-intent-20261105`,fonte qualificata bf6bcf926727b5ea738155ac70a71b73f1b21f68.
- [Dossier completo](../OUF_STORAGE_ONBOARDING_COMMON_CUT_20261105.md) e [ricevuta](../../evidence/onboarding-common-cut-qualified-20261105.json):24scenari owner+8test API/storage PASS;common cut fisico e readback separato PASS,1671file dei backup verificati. Conservati entrambi i fallimenti e il successo precedente.
- Il componente interno ManagedFileStorageRecovery implementa drain/reconcile/freeze; nessun endpoint/scheduler o riapertura è ammesso da questa modifica. La fixture prova l'arresto storage, la restrizione Read/List e il ripristino FROZEN; non qualifica la gestione operativa di tutti i writer.

Prossima coppia delimitata:1) riesaminare i contratti operativi owner già esistenti e collegare il protocollo a una prova autorizzata di quiescenza;2) qualificarne revoca, concorrenza, scadenza e blocco della riapertura senza nuova autorità. Non inventare una nuova HUMAN authority o eseguire azioni sul target dalla sola delega di sviluppo. UDP/Ingestion e rollout misto restano da integrare.

MinIO,source-lock,18,3/46=39,78%,0/8gate,0/21AT e0/120oggetti reali invariati. Nessun deployment,merge,nuova acquisizione,replay,reset o grant effettuato. Il readback dello ZIP è stato eseguito sul secondo runner; nessun terzo download locale dichiarato.
