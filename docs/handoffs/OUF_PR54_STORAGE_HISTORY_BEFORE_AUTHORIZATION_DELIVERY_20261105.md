# PR54 e handoff prima della consegna Authorization — copia storica del 5 novembre 2026

## Onboarding PR54

Uploads persist intent before S3 I/O and reconcile the same object without another PUT. Recovery requires current authority and quiescence, now bound to the configured installation, a fresh worker session created outside the database, and the observed PostgreSQL postmaster start time. An old backup projection cannot authorize a restarted worker; a surviving worker also rejects a physically restarted/restored database.

Authority and custody have separate runtime bindings. A fresh authority binding cannot refresh old quiescence, extend the decision window, reset the intent budget or reopen FROZEN. Existing pre/post-GET checks, atomic audit, finite transaction/lock limits and final expiry check remain in force. [Internal platform binding contract](https://github.com/GioNob/ouf-source-onboarding/blob/c1d0dd22eebbd27565ccbc86a225ea4a69c8a1f9/docs/STORAGE_RECOVERY_PLATFORM_BINDING.md).

Validation on source `c1d0dd22eebbd27565ccbc86a225ea4a69c8a1f9`:

- [Native owner42003559195](https://github.com/GioNob/ouf-source-onboarding/actions/runs/42003559195): **42 owner scenarios + 8 API/storage tests PASS**, zero failures/errors/skips. Seven new cases cover missing/stale runtime, wrong installation, old custody after authority rebinding, exhausted budgets across runtimes, revocation and runtime change during GET.
- [Physical restore42003559164](https://github.com/GioNob/ouf-source-onboarding/actions/runs/42003559164): **producer and independent readback SUCCESS**. Current synthetic authority and its local projection are revoked after the named cut. PITR deliberately restores the old unrevoked projection; a fresh JVM refuses it, and current attestation against revoked or missing authority also fails.
- A separate JVM remains alive while the source PostgreSQL container is stopped/removed and the exported backup is restored. It rejects the changed postmaster before gate lookup. Owner/audit snapshots remain unchanged by rejected operations.
- Readback verified **38 ZIP members, 37 checksums, 266 source bindings and all 1,680 backup files**. Nine semantic corruptions rejected with recalculated outer checksums. Two objects/36bytes, six PUT denials, twelve storage and two PostgreSQL clean stops.
- **Source CI8/8 SUCCESS**, including [PR42003566793](https://github.com/GioNob/ouf-source-onboarding/actions/runs/42003566793) and [push42003559325](https://github.com/GioNob/ouf-source-onboarding/actions/runs/42003559325), blocking image scan and container boot. General module suite407 reported minus42 native skipped=365 executed PASS;42 native executed separately.

[Dossier](https://github.com/GioNob/ouf-deploy/blob/18810180ca0e6db6dcf866b5fdc5ca49916abb82/docs/OUF_STORAGE_ONBOARDING_RUNTIME_BINDING_20261105.md), [exact receipt and artifact metadata](https://github.com/GioNob/ouf-deploy/blob/18810180ca0e6db6dcf866b5fdc5ca49916abb82/evidence/onboarding-runtime-binding-qualified-20261105.json), [handoff](https://github.com/GioNob/ouf-deploy/blob/18810180ca0e6db6dcf866b5fdc5ca49916abb82/docs/handoffs/OUF_STORAGE_ONBOARDING_RECOVERY_HANDOFF_20261105.md), [previous PR descriptions preserved](https://github.com/GioNob/ouf-deploy/blob/18810180ca0e6db6dcf866b5fdc5ca49916abb82/docs/handoffs/OUF_PR54_STORAGE_HISTORY_BEFORE_RUNTIME_BINDING_20261105.md).

The first qualification attempt passed. Local diff, Python syntax and WAL-placeholder regression passed; Java/PostgreSQL/S3 ran on Linux CI. Original/readback/native artifacts13403058364/13403337484/13404530154 retained until2027-02-03. No third local ZIP readback claimed.

**Boundary:** the current-authority file and PostgreSQL gate adapter are test-only. No production Authorization/THS/Gateway adapter, global storage capability grant or reopen endpoint is installed. Distributed revocation, all-writer custody, denied-command audit, logical rollback under an unchanged postmaster, UDP/Ingestion, mixed rollout and representative RPO/RTO remain open. MinIO/source-lock and MiniPET18.3/46=39.78%,0/8gates,0/21AT,0/120real objects remain unchanged. No merge, deployment, target operation or runtime grant.

## Deploy PR54

This storage replacement checkpoint completes two further development steps: define and enforce the internal platform/runtime binding, then qualify that process/database restart and physical restore cannot reuse obsolete authority or quiescence.

Implementation is in [Onboarding PR54](https://github.com/GioNob/ouf-source-onboarding/pull/54). Evidence checkpoint:`18810180ca0e6db6dcf866b5fdc5ca49916abb82`. Prior deploy8f210c07 completed50/50 workflows successfully; automatic checks triggered by this documentation checkpoint are separate.

Validation on source `c1d0dd22eebbd27565ccbc86a225ea4a69c8a1f9`:

- [Native owner42003559195](https://github.com/GioNob/ouf-source-onboarding/actions/runs/42003559195): **42 owner scenarios + 8 API/storage tests PASS**, zero failures/errors/skips. Seven new cases cover missing/stale runtime, wrong installation, old custody after authority rebinding, exhausted budgets across runtimes, revocation and runtime change during GET.
- [Physical restore42003559164](https://github.com/GioNob/ouf-source-onboarding/actions/runs/42003559164): **producer and independent readback SUCCESS**. Current synthetic authority and its local projection are revoked after the named cut. PITR deliberately restores the old unrevoked projection; a fresh JVM refuses it, and current attestation against revoked or missing authority also fails.
- A separate JVM remains alive while the source PostgreSQL container is stopped/removed and the exported backup is restored. It rejects the changed postmaster before gate lookup. Owner/audit snapshots remain unchanged by rejected operations.
- Readback verified **38 ZIP members, 37 checksums, 266 source bindings and all 1,680 backup files**. Nine semantic corruptions rejected with recalculated outer checksums. Two objects/36bytes, six PUT denials, twelve storage and two PostgreSQL clean stops.
- **Source CI8/8 SUCCESS**, including [PR42003566793](https://github.com/GioNob/ouf-source-onboarding/actions/runs/42003566793) and [push42003559325](https://github.com/GioNob/ouf-source-onboarding/actions/runs/42003559325), blocking image scan and container boot. General module suite407 reported minus42 native skipped=365 executed PASS;42 native executed separately.

[Dossier](https://github.com/GioNob/ouf-deploy/blob/18810180ca0e6db6dcf866b5fdc5ca49916abb82/docs/OUF_STORAGE_ONBOARDING_RUNTIME_BINDING_20261105.md), [exact receipt and artifact metadata](https://github.com/GioNob/ouf-deploy/blob/18810180ca0e6db6dcf866b5fdc5ca49916abb82/evidence/onboarding-runtime-binding-qualified-20261105.json), [handoff](https://github.com/GioNob/ouf-deploy/blob/18810180ca0e6db6dcf866b5fdc5ca49916abb82/docs/handoffs/OUF_STORAGE_ONBOARDING_RECOVERY_HANDOFF_20261105.md), [previous PR descriptions preserved](https://github.com/GioNob/ouf-deploy/blob/18810180ca0e6db6dcf866b5fdc5ca49916abb82/docs/handoffs/OUF_PR54_STORAGE_HISTORY_BEFORE_RUNTIME_BINDING_20261105.md).

The first qualification attempt passed. Local diff, Python syntax and WAL-placeholder regression passed; Java/PostgreSQL/S3 ran on Linux CI. Original/readback/native artifacts13403058364/13403337484/13404530154 retained until2027-02-03. No third local ZIP readback claimed.

**Boundary:** the current-authority file and PostgreSQL gate adapter are test-only. No production Authorization/THS/Gateway adapter, global storage capability grant or reopen endpoint is installed. Distributed revocation, all-writer custody, denied-command audit, logical rollback under an unchanged postmaster, UDP/Ingestion, mixed rollout and representative RPO/RTO remain open. MinIO/source-lock and MiniPET18.3/46=39.78%,0/8gates,0/21AT,0/120real objects remain unchanged. No merge, deployment, target operation or runtime grant.

Next pair: prepare the application storage-recovery contract in the Authorization/platform owner without runtime grants; qualify decision delivery/revocation to the owner projection, including ambiguous outcomes and stale generations. Read the original contracts and current repository state first. Persistent preference:two steps per continuation,no subagents.

## Handoff precedente

# Ripresa storage Onboarding — restart, restore e autorità corrente, 5 novembre 2026

Continuare per due passi alla volta, senza subagenti. Controllare branch e CI prima di modificare; nessuna ripetizione di prove già concluse senza una modifica o un motivo documentato.

- Deploy:PR54 draft,branch `feat/m2-discovery-complete-profile-20261029`; leggere l'HEAD che contiene questo handoff. Precedente8f210c07fd1673eec20a49cf73911dede9540047 con50/50CI SUCCESS.
- Onboarding:PR54 draft,branch `feat/storage-upload-intent-20261105`,fonte `c1d0dd22eebbd27565ccbc86a225ea4a69c8a1f9`.
- [Dossier](../OUF_STORAGE_ONBOARDING_RUNTIME_BINDING_20261105.md),[ricevuta](../../evidence/onboarding-runtime-binding-qualified-20261105.json).42scenari nativi+8API/storage PASS;recupero fisico e readback indipendente PASS,38membri/37checksum/266sorgenti/1680file backup,9negativi.
- `StorageRecoveryRuntime` crea una sessione nuova fuori dal DB e osserva l'avvio PostgreSQL. L'owner controlla installazione,sessione,incarnazione DB e binding separato della quiescenza. Niente sessioni ripristinate,reset budget o riapertura.
- La fixture revoca una decisione esterna dopo il cut e ripristina volutamente la proiezione locale non revocata:nuova JVM bloccata,attestazione corrente revocata/assente respinta. Una JVM rimasta viva attraverso la distruzione e il restore DB è bloccata dal cambio postmaster. Owner/audit restano identici al cut. Fonte corrente modellata da file test-only fuori dai backup,non da un servizio Authorization produttivo.
- Restano invariati i controlli del gate precedente:128letture/24h,transazioni12s/lock2s/SQL5s,esatto binding pre/post GET,audit atomico e controllo scadenza finale. Il nuovo runtime non rinnova decisioni o prove di custodia.

Prossima coppia delimitata:1) predisporre il contratto applicativo di recovery storage nell'owner Authorization/piattaforma,senza assegnare grant runtime;2) qualificare consegna/revoca della decisione fra autorità e proiezione owner,con esiti ambigui e generazioni obsolete. Riesaminare prima PET/Matrix e stato dei repository coinvolti. Non riciclare i permessi HUMAN di profiling o configurazione d'installazione come autorità storage globale.

Binding produttivo,revoca distribuita concorrente,custodia completa dei writer,audit dei dinieghi,fence per rollback logico a postmaster invariato,UDP/Ingestion,rollout misto,riapertura e RPO/RTO rimangono OPEN. MinIO/source-lock,MiniPET18,3/46=39,78%,0/8gate,0/21AT,0/120oggetti reali invariati. Nessun merge/deploy/target/admission/replay/reset/grant. Prove precedenti preservate;nessun terzo readback locale degli ZIP.
