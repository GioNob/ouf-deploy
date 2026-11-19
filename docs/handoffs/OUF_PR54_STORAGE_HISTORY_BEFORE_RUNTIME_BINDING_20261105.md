# PR54 e handoff prima del binding runtime — copia storica del 5 novembre 2026

## Onboarding PR54

Managed-file uploads persist intent before S3 I/O and reconcile the same object without a second PUT. Recovery now fails closed without a trusted authority/quiescence adapter. It rechecks the exact decision binding after GET and commits ACK plus audit atomically; revoked, replaced, expired or unproven evidence blocks publication.

Transactions are limited to12s, lock waits2s and SQL statements5s. An additional deadline check after writes/audit rolls back expired transitions. The original128-read/24h intent budget and existing upload ownership semantics are retained.

Validation on source `5d9ba774b0d8b38c2acab36e1736803a1158059d`:

- [Native owner41998933870](https://github.com/GioNob/ouf-source-onboarding/actions/runs/41998933870): **35 owner scenarios + 8 API/storage tests PASS**, no failures/errors/skips. Includes revocation during paused GET, changed decision/custody, expiry during GET and audit, audit rollback, lock contention, concurrent reconciliation and refusal to reopen.
- [Physical common cut41998934118](https://github.com/GioNob/ouf-source-onboarding/actions/runs/41998934118): **native restore and independent readback SUCCESS**. Synthetic gate/audit tables are preserved alongside actual owner tables. Quiescence is recorded only after physical fixture storage stops, the same identity is restricted to Read/List and three native PUT denials pass.
- Readback verified **32 ZIP members,31 checksums,265 source bindings and all1,680 backup files**; five semantic corruptions rejected with recalculated outer checksums. Two synthetic objects/36bytes and six PUT denials preserved. This is an independent archive readback, not a second native restore.
- **Source CI8/8 SUCCESS**, including [PR41998940250](https://github.com/GioNob/ouf-source-onboarding/actions/runs/41998940250) and [push41998933767](https://github.com/GioNob/ouf-source-onboarding/actions/runs/41998933767), image scan and container boot. General module suite400 reported minus35 native skipped=365 executed PASS;35 native run separately.

[Dossier](https://github.com/GioNob/ouf-deploy/blob/8f210c07fd1673eec20a49cf73911dede9540047/docs/OUF_STORAGE_ONBOARDING_AUTHORITY_GATE_20261105.md), [exact receipt and artifact digests](https://github.com/GioNob/ouf-deploy/blob/8f210c07fd1673eec20a49cf73911dede9540047/evidence/onboarding-authority-gate-qualified-20261105.json), [handoff](https://github.com/GioNob/ouf-deploy/blob/8f210c07fd1673eec20a49cf73911dede9540047/docs/handoffs/OUF_STORAGE_ONBOARDING_RECOVERY_HANDOFF_20261105.md), [previous PR descriptions and handoff preserved](https://github.com/GioNob/ouf-deploy/blob/8f210c07fd1673eec20a49cf73911dede9540047/docs/handoffs/OUF_PR54_STORAGE_HISTORY_BEFORE_AUTHORITY_GATE_20261105.md).

First increment050a5a2a (33native+8API and physical/readback PASS) remains preserved;5d9ba774 additionally closes expiry during lock/audit work. Artifacts retained until2027-02-03. Python regression PASS locally after using a writable workspace temp directory; no local Java/Docker or third local ZIP readback is claimed.

**Boundary:** this prepares and qualifies the internal integration port, with a test-only PostgreSQL adapter. No production authority adapter, capability grant, endpoint, scheduler or reopen command is installed. Per-file HUMAN/profile permissions do not authorize global storage recovery. Platform policy/THS/Gateway binding, all-writer quiescence, denied-command audit, authority revalidation after restore, UDP/Ingestion, mixed rollout and representative RPO/RTO remain open. No merge, deployment, target operation, source-lock promotion or runtime grant. MinIO and MiniPET18.3/46=39.78%,0/8gates,0/21AT,0/120real objects remain unchanged.

## Deploy PR54

The storage replacement qualification now includes the actual Onboarding upload owner and a mandatory internal authority/quiescence boundary for its frozen recovery protocol. This checkpoint records two development steps: implement the boundary without inventing production authority, then qualify adverse concurrency/revocation/expiry/audit cases and physical restore.

Application implementation: [Onboarding PR54](https://github.com/GioNob/ouf-source-onboarding/pull/54). Evidence checkpoint:`8f210c07fd1673eec20a49cf73911dede9540047`. Prior deployfd5e774c completed50/50 workflows SUCCESS; automatic checks of this documentation checkpoint are separate.

Validation on source `5d9ba774b0d8b38c2acab36e1736803a1158059d`:

- [Native owner41998933870](https://github.com/GioNob/ouf-source-onboarding/actions/runs/41998933870): **35 owner scenarios + 8 API/storage tests PASS**, no failures/errors/skips. Includes revocation during paused GET, changed decision/custody, expiry during GET and audit, audit rollback, lock contention, concurrent reconciliation and refusal to reopen.
- [Physical common cut41998934118](https://github.com/GioNob/ouf-source-onboarding/actions/runs/41998934118): **native restore and independent readback SUCCESS**. Synthetic gate/audit tables are preserved alongside actual owner tables. Quiescence is recorded only after physical fixture storage stops, the same identity is restricted to Read/List and three native PUT denials pass.
- Readback verified **32 ZIP members,31 checksums,265 source bindings and all1,680 backup files**; five semantic corruptions rejected with recalculated outer checksums. Two synthetic objects/36bytes and six PUT denials preserved. This is an independent archive readback, not a second native restore.
- **Source CI8/8 SUCCESS**, including [PR41998940250](https://github.com/GioNob/ouf-source-onboarding/actions/runs/41998940250) and [push41998933767](https://github.com/GioNob/ouf-source-onboarding/actions/runs/41998933767), image scan and container boot. General module suite400 reported minus35 native skipped=365 executed PASS;35 native run separately.

[Dossier](https://github.com/GioNob/ouf-deploy/blob/8f210c07fd1673eec20a49cf73911dede9540047/docs/OUF_STORAGE_ONBOARDING_AUTHORITY_GATE_20261105.md), [exact receipt and artifact digests](https://github.com/GioNob/ouf-deploy/blob/8f210c07fd1673eec20a49cf73911dede9540047/evidence/onboarding-authority-gate-qualified-20261105.json), [handoff](https://github.com/GioNob/ouf-deploy/blob/8f210c07fd1673eec20a49cf73911dede9540047/docs/handoffs/OUF_STORAGE_ONBOARDING_RECOVERY_HANDOFF_20261105.md), [previous PR descriptions and handoff preserved](https://github.com/GioNob/ouf-deploy/blob/8f210c07fd1673eec20a49cf73911dede9540047/docs/handoffs/OUF_PR54_STORAGE_HISTORY_BEFORE_AUTHORITY_GATE_20261105.md).

First increment050a5a2a (33native+8API and physical/readback PASS) remains preserved;5d9ba774 additionally closes expiry during lock/audit work. Artifacts retained until2027-02-03. Python regression PASS locally after using a writable workspace temp directory; no local Java/Docker or third local ZIP readback is claimed.

**Boundary:** this prepares and qualifies the internal integration port, with a test-only PostgreSQL adapter. No production authority adapter, capability grant, endpoint, scheduler or reopen command is installed. Per-file HUMAN/profile permissions do not authorize global storage recovery. Platform policy/THS/Gateway binding, all-writer quiescence, denied-command audit, authority revalidation after restore, UDP/Ingestion, mixed rollout and representative RPO/RTO remain open. No merge, deployment, target operation, source-lock promotion or runtime grant. MinIO and MiniPET18.3/46=39.78%,0/8gates,0/21AT,0/120real objects remain unchanged.

Next pair: define the platform binding and separation between restored backups and current authority; qualify that restart/restore cannot revive revoked decisions or stale quiescence evidence. Persistent preference:two steps per continuation,no subagents.

## Handoff precedente

# Ripresa storage Onboarding — autorità e quiescenza, 5 novembre 2026

Continuare per due passi alla volta, senza subagenti. Prima controllare branch e CI; non ripetere prove concluse senza una modifica o un motivo documentato.

- Deploy: PR54 draft, branch `feat/m2-discovery-complete-profile-20261029`. Leggere l'HEAD che contiene questo handoff; precedente fd5e774c48b00c410ba203bf407b9373640a3bb2 con50/50CI SUCCESS.
- Onboarding: PR54 draft, branch `feat/storage-upload-intent-20261105`, fonte qualificata `5d9ba774b0d8b38c2acab36e1736803a1158059d`.
- [Dossier](../OUF_STORAGE_ONBOARDING_AUTHORITY_GATE_20261105.md), [ricevuta](../../evidence/onboarding-authority-gate-qualified-20261105.json).35scenari nativi+8API/storage PASS;common-cut fisico/readback PASS,265sorgenti/1680file backup;CI sorgente8/8SUCCESS.
- Il protocollo interno richiede `StorageRecoveryGate`; senza adattatore è negato. Autorità/azione/scope/epoch/scadenza e quiescenza controllati prima e dopo GET, stesso binding, audit atomico, limiti12s/2s/5s e controllo scadenza dopo audit. Non esiste un adattatore di autorità produttivo: quello PostgreSQL è test-only. Nessun permesso per-file è diventato un grant storage globale.
- Il ripristino preserva le tabelle sintetiche di autorità/audit ma NON dimostra validità produttiva dei grant ripristinati. Il futuro binding deve usare autorità corrente e prova di quiescenza su tutti i writer, non fidarsi del solo backup.

Prossima coppia delimitata:1) definire il binding di piattaforma e separare l'autorità corrente dal backup recuperato, partendo dai contratti Authorization/THS/Gateway e di installazione;2) qualificare che restart/restore non resuscitino decisioni revocate o prove di quiescenza obsolete. Nessuna nuova HUMAN authority implicita né operazione target dalla sola delega di sviluppo. UDP/Ingestion,rollout misto,riapertura e RPO/RTO restano aperti.

MinIO,source-lock,MiniPET18,3/46=39,78%,0/8gate,0/21AT,0/120oggetti reali invariati. Nessun merge/deploy/target/admission/replay/reset/grant. La prova precedente bf6bcf9 e la prima di questa coppia050a5a2a restano conservate; readback dello ZIP sul secondo runner, nessun terzo download locale dichiarato.
