# PR54 e handoff prima della qualifica del restore Authorization — 5 novembre 2026

Contenuti acquisiti prima dell'aggiornamento; i nuovi stati sono nei dossier successivi.

## Onboarding PR54

Durable uploads and frozen recovery now have an internal bridge to the existing Authorization registry. A distinct candidate `installation.storage.recovery` capability evaluates a server-built installation resource; it does not reuse file-profiling or installation-configuration permissions.

V40 persists bounded prepared decisions, versioned delivery and immutable audit. Repeating a command or delivery after a lost result preserves its original identity/deadline/version. Replacement and explicit revocation permanently invalidate old decisions. Owner transactions share the registry's policy-activation lock, so policy changes and revocation cannot bypass ACK fencing. Policy and decision are checked again after GET; custody stays separate and upload budgets are never reset.

[Same-database contract and limits](https://github.com/GioNob/ouf-source-onboarding/blob/f909fbfbc3f060f2cb83238cb94c8d7b710f77dc/docs/STORAGE_RECOVERY_AUTHORIZATION_DELIVERY.md).

Validation on source `f909fbfbc3f060f2cb83238cb94c8d7b710f77dc`:

- [Native owner 42006721416](https://github.com/GioNob/ouf-source-onboarding/actions/runs/42006721416): **57 owner scenarios + 8 API/storage tests PASS**, zero failures/errors/skips. Fifteen new cases cover actual policy evaluation, fresh HUMAN requirements, descriptor drift, lost-response reconciliation, concurrent preparation/delivery, stale CAS, terminal revocation, policy changes during GET and unchanged exhausted budgets.
- [Physical cut and readback 42006721313](https://github.com/GioNob/ouf-source-onboarding/actions/runs/42006721313): **both jobs SUCCESS**, including the prior runtime/current-authority regressions. V40 tables are included and verified **empty/ungranted** in this drill; this is not yet physical recovery of populated V40 decision history.
- Independent readback verified **38 ZIP members, 37 checksums, 270 source bindings and all 1,695 backup files**; nine semantic corruptions rejected with recomputed outer checksums. Two synthetic objects/36 bytes, six PUT denials, twelve storage and two PostgreSQL clean stops.
- **Source CI 8/8 SUCCESS**, including [PR 42006730177](https://github.com/GioNob/ouf-source-onboarding/actions/runs/42006730177) and [push 42006721272](https://github.com/GioNob/ouf-source-onboarding/actions/runs/42006721272), blocking image scan and container boot. General module suite: 422 reported minus 57 native skipped = 365 executed PASS; the 57 native cases run separately.

[Dossier](https://github.com/GioNob/ouf-deploy/blob/254228b5f96130cc072a80e17079a2bbd2747513/docs/OUF_STORAGE_AUTHORIZATION_DELIVERY_20261105.md), [exact receipt and artifact metadata](https://github.com/GioNob/ouf-deploy/blob/254228b5f96130cc072a80e17079a2bbd2747513/evidence/storage-authorization-delivery-qualified-20261105.json), [handoff](https://github.com/GioNob/ouf-deploy/blob/254228b5f96130cc072a80e17079a2bbd2747513/docs/handoffs/OUF_STORAGE_ONBOARDING_RECOVERY_HANDOFF_20261105.md), [previous PR descriptions preserved](https://github.com/GioNob/ouf-deploy/blob/254228b5f96130cc072a80e17079a2bbd2747513/docs/handoffs/OUF_PR54_STORAGE_HISTORY_BEFORE_AUTHORIZATION_DELIVERY_20261105.md).

First qualification attempt passed. Local diff, Python syntax and WAL-placeholder regression passed; Java/PostgreSQL/S3 ran on Linux CI. Artifacts 13404369761/13404698522/13404454808 retained until 2027-02-03. No third local archive readback claimed.

**Boundary:** this is an explicitly constructed, same-PostgreSQL integration, with no bean/endpoint or automatic capability registration/grant. Production Gateway/THS/session validation, complete writer custody, durable denial audit and distributed revocation remain open. Restored local policy is not automatically current: the independent restore-generation/authority boundary is still required. Populated V40 physical recovery, logical rollback fencing, UDP/Ingestion, mixed rollout, reopening and representative RPO/RTO remain open. No merge, deployment, target operation, source-lock promotion or runtime grant. MinIO and MiniPET 18.3/46=39.78%, 0/8 gates, 0/21 AT, 0/120 real objects are unchanged.


## Deploy PR54

Two further development steps are complete: define a distinct internal storage-recovery contract against the actual Authorization registry, then qualify durable delivery/revocation and stale/concurrent outcomes in the same database.

Implementation: [Onboarding PR54](https://github.com/GioNob/ouf-source-onboarding/pull/54). Evidence checkpoint: `254228b5f96130cc072a80e17079a2bbd2747513`. Prior deploy 18810180 completed 50/50 workflows successfully; checks triggered by this documentation checkpoint are separate.

Validation on source `f909fbfbc3f060f2cb83238cb94c8d7b710f77dc`:

- [Native owner 42006721416](https://github.com/GioNob/ouf-source-onboarding/actions/runs/42006721416): **57 owner scenarios + 8 API/storage tests PASS**, zero failures/errors/skips. Fifteen new cases cover actual policy evaluation, fresh HUMAN requirements, descriptor drift, lost-response reconciliation, concurrent preparation/delivery, stale CAS, terminal revocation, policy changes during GET and unchanged exhausted budgets.
- [Physical cut and readback 42006721313](https://github.com/GioNob/ouf-source-onboarding/actions/runs/42006721313): **both jobs SUCCESS**, including the prior runtime/current-authority regressions. V40 tables are included and verified **empty/ungranted** in this drill; this is not yet physical recovery of populated V40 decision history.
- Independent readback verified **38 ZIP members, 37 checksums, 270 source bindings and all 1,695 backup files**; nine semantic corruptions rejected with recomputed outer checksums. Two synthetic objects/36 bytes, six PUT denials, twelve storage and two PostgreSQL clean stops.
- **Source CI 8/8 SUCCESS**, including [PR 42006730177](https://github.com/GioNob/ouf-source-onboarding/actions/runs/42006730177) and [push 42006721272](https://github.com/GioNob/ouf-source-onboarding/actions/runs/42006721272), blocking image scan and container boot. General module suite: 422 reported minus 57 native skipped = 365 executed PASS; the 57 native cases run separately.

[Dossier](https://github.com/GioNob/ouf-deploy/blob/254228b5f96130cc072a80e17079a2bbd2747513/docs/OUF_STORAGE_AUTHORIZATION_DELIVERY_20261105.md), [exact receipt and artifact metadata](https://github.com/GioNob/ouf-deploy/blob/254228b5f96130cc072a80e17079a2bbd2747513/evidence/storage-authorization-delivery-qualified-20261105.json), [handoff](https://github.com/GioNob/ouf-deploy/blob/254228b5f96130cc072a80e17079a2bbd2747513/docs/handoffs/OUF_STORAGE_ONBOARDING_RECOVERY_HANDOFF_20261105.md), [previous PR descriptions preserved](https://github.com/GioNob/ouf-deploy/blob/254228b5f96130cc072a80e17079a2bbd2747513/docs/handoffs/OUF_PR54_STORAGE_HISTORY_BEFORE_AUTHORIZATION_DELIVERY_20261105.md).

First qualification attempt passed. Local diff, Python syntax and WAL-placeholder regression passed; Java/PostgreSQL/S3 ran on Linux CI. Artifacts 13404369761/13404698522/13404454808 retained until 2027-02-03. No third local archive readback claimed.

**Boundary:** this is an explicitly constructed, same-PostgreSQL integration, with no bean/endpoint or automatic capability registration/grant. Production Gateway/THS/session validation, complete writer custody, durable denial audit and distributed revocation remain open. Restored local policy is not automatically current: the independent restore-generation/authority boundary is still required. Populated V40 physical recovery, logical rollback fencing, UDP/Ingestion, mixed rollout, reopening and representative RPO/RTO remain open. No merge, deployment, target operation, source-lock promotion or runtime grant. MinIO and MiniPET 18.3/46=39.78%, 0/8 gates, 0/21 AT, 0/120 real objects are unchanged.

Next pair: include populated V40 decisions/projections/audit in the physical common cut, then qualify post-cut revocation and refusal to reattest restored obsolete policy/projections using authority independent of the backup. Persistent preference: two steps per continuation, no subagents.


## Handoff precedente

# Ripresa storage — consegna/revoca Authorization, 5 novembre 2026

Continuare per due passi alla volta, senza subagenti. Verificare branch e CI prima di modificare; non ripetere prove concluse senza modifiche o motivo documentato.

- Deploy:PR54 draft,branch `feat/m2-discovery-complete-profile-20261029`; leggere l'HEAD che contiene questo handoff. Precedente18810180ca0e6db6dcf866b5fdc5ca49916abb82 con50/50CI SUCCESS.
- Onboarding:PR54 draft,branch `feat/storage-upload-intent-20261105`,fonte `f909fbfbc3f060f2cb83238cb94c8d7b710f77dc`.
- [Dossier](../OUF_STORAGE_AUTHORIZATION_DELIVERY_20261105.md),[ricevuta](../../evidence/storage-authorization-delivery-qualified-20261105.json).57scenari nativi+8API/storage PASS;common-cut/readback SUCCESS,38membri/37checksum/270sorgenti/1695file backup,9negativi.
- `StorageRecoveryAuthorization` usa il registry Authorization reale già presente nel repository. Capability candidata `installation.storage.recovery`,HUMAN,scope omonimo,risorsa installation-storage-recovery server-side. Nessuna registrazione/grant automatica;HUMAN fresco e deadline massimo15minuti. V40 crea tabelle vuote e proiezioneversione0.
- Preparazione idempotente per chiave/hash;consegna con versione attesa e audit atomico;risposta persa riconciliata sullo stesso ID/versione. Sostituzione/revoca terminale,nessun rinnovo implicito di decisioni o budget. Gate reale rivalida policy/decisione dopo GET;lock condiviso741093 confligge con attivazione policy esclusiva e lockproiezione con revoca esplicita.
- `PolicyStorageRecoveryGate` e servizio sono interni,nonbean/nonendpoint. Integrazione qualificata SOLO nello stesso PostgreSQL. Custodia separata test-only;nessun servizio di revoca remota distribuita o sessione Gateway/THS installato.
- Il common-cut conserva le nuove tabelle V40 nello stato vuoto/senza autorità. NON è ancora il restore di una storia V40 popolata. Restano validi runtime/installazione/postmaster e precedente prova di decisione corrente esterna revocata;un bundle Authorization vecchio ripristinato NON è automaticamente corrente.

Prossima coppia:1) integrare decisioni/consegne/audit V40 popolati nel common-cut;2) qualificare ripristino con revoca dopo il taglio e blocco della riattestazione su policy/proiezioni obsolete,usando autorità corrente indipendente dal backup. Nessun grant target. Riesaminare il fence di generazione e il confine Authorization/THS/Gateway prima di collegare il percorso operativo.

MinIO/source-lock,MiniPET18,3/46=39,78%,0/8gate,0/21AT,0/120oggetti reali invariati. Nessun merge/deploy/target/admission/replay/reset/grant. Produzione,custodia completa,audit dinieghi,revoca distribuita,rollback logico,UDP/Ingestion,rollout misto,riapertura,RPO/RTO OPEN. Prove precedenti preservate;nessun terzo readback locale degli ZIP.
