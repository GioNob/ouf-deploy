# Archivio prima della riconciliazione governata — 5 novembre 2026

Testi PR54 e handoff precedenti, preservati integralmente. I conteggi pendenti in questi testi sono storici; il nuovo dossier riporta gli esiti aggiornati.

## Onboarding PR54

A restored Authorization history must not revive an old worker after independent platform revocation, including across process restart. This PR now supplies an explicit internal `FilePlatformRecoveryAuthority` for the existing transaction-bound authority adapter: protected local POSIX state, expected-generation publication, exact idempotent replay without renewal, atomic persistence and a stable exclusive OS guard.

Before granting a lease the provider persists `lease.active`. Known commit/rollback clears it before releasing the guard; process death or UNKNOWN leaves a durable denial for readers and publishers across restart. No PID, timeout or automatic provisioning clears that state. The provider accepts already-approved proofs and is not a Spring bean, endpoint, issuer or grant. Existing policy/HUMAN/expiry and installation/tenant/admission-generation checks remain cumulative.

The broader upload/recovery, policy delivery and rollback protections from this draft PR remain; the full previous description is archived below.

Validation at source `bf8bb65cf353dc60c9482dd6fe50e4416b2eefe6`:

- [Native 42024429070](https://github.com/GioNob/ouf-source-onboarding/actions/runs/42024429070): **80 owner scenarios + 8 API/storage tests = 88 PASS**, zero failures/errors/skips. Nine new provider cases cover separate-JVM restart, revocation across actual owner commit, killed-holder persistent denial, publisher halt before response, logical Authorization replay, competing publications, invalid state/permissions, stale guard and injected UNKNOWN completion.
- Native archive readback: **125 members, 124 checksums, 273 exact Git source blobs**, nine provider receipts, eight child JVM logs; qualified filesystem ext4. This verification does not repeat native execution.
- [Physical regression/readback 42024429052](https://github.com/GioNob/ouf-source-onboarding/actions/runs/42024429052): both jobs SUCCESS; 39 members, 38 checksums, 276 source bindings, 1,695 backup files, 15 semantic corruptions rejected. This remains the earlier sequential external-file drill; it does not integrate the new provider or provide a second independent native restore.
- **Source CI 8/8 SUCCESS**; general suite 445 reported minus 80 native skips = 365 executed PASS, blocking image scan and container boot successful. Previous deploy checkpoint `ee2d208` has **50/50 SUCCESS**; new documentation-commit checks are separate.

The first candidate `ba18f0c` passed 87 tests and eight workflows. Review identified that OS lock release after JVM death can precede resolution of a sent PostgreSQL COMMIT. The final candidate adds a durable unresolved lease latch and UNKNOWN handling; the first qualification is preserved but superseded.

Scope: same-host cooperating processes on a protected local POSIX store. Process kill/halt is not host power-loss testing; UNKNOWN is injected, not a real database/network failure. No multi-host, authority-store rollback, operational mount qualification, automatic reconciliation or production wiring is claimed.

MinIO/source-lock unchanged; MiniPET **18.3/46 = 39.78%, 0/8 gates, 0/21 AT, 0/120 real objects**. No merge, deployment, target operation, runtime grant or automatic re-admission. Remaining work includes observable unresolved state and governed owner-outcome reconciliation/resume, custody/authenticated publication, full owner-budget rollback, UDP/Ingestion and RPO/RTO.

[Dossier](https://github.com/GioNob/ouf-deploy/blob/105a35cd55b0db3822f12188dd0d5e958ca22156/docs/OUF_STORAGE_DURABLE_LOCAL_AUTHORITY_20261105.md), [qualification receipt](https://github.com/GioNob/ouf-deploy/blob/105a35cd55b0db3822f12188dd0d5e958ca22156/evidence/storage-durable-local-authority-qualified-20261105.json), [native archive verifier](https://github.com/GioNob/ouf-deploy/blob/105a35cd55b0db3822f12188dd0d5e958ca22156/scripts/readback-durable-authority-native-20261105.py), [handoff](https://github.com/GioNob/ouf-deploy/blob/105a35cd55b0db3822f12188dd0d5e958ca22156/docs/handoffs/OUF_STORAGE_ONBOARDING_RECOVERY_HANDOFF_20261105.md), [previous PR descriptions and handoff](https://github.com/GioNob/ouf-deploy/blob/105a35cd55b0db3822f12188dd0d5e958ca22156/docs/handoffs/OUF_PR54_STORAGE_HISTORY_BEFORE_DURABLE_AUTHORITY_20261105.md).

## Deploy PR54

Record the durable local authority implementation and separate-JVM qualification for Onboarding PR54. The evidence now covers restart, cross-process revocation through actual owner commit, lost publication response and persistent denial after holder death or UNKNOWN completion. This documentation checkpoint includes the reproducible archive verifier, machine-readable receipts, current handoff and preserved prior PR/handoff history.

The provider remains an internal candidate. The owner must stay paused when a durable lease is unresolved; governed reconciliation and controlled resume are the next pair, with no automatic latch removal.

Validation at source `bf8bb65cf353dc60c9482dd6fe50e4416b2eefe6`:

- [Native 42024429070](https://github.com/GioNob/ouf-source-onboarding/actions/runs/42024429070): **80 owner scenarios + 8 API/storage tests = 88 PASS**, zero failures/errors/skips. Nine new provider cases cover separate-JVM restart, revocation across actual owner commit, killed-holder persistent denial, publisher halt before response, logical Authorization replay, competing publications, invalid state/permissions, stale guard and injected UNKNOWN completion.
- Native archive readback: **125 members, 124 checksums, 273 exact Git source blobs**, nine provider receipts, eight child JVM logs; qualified filesystem ext4. This verification does not repeat native execution.
- [Physical regression/readback 42024429052](https://github.com/GioNob/ouf-source-onboarding/actions/runs/42024429052): both jobs SUCCESS; 39 members, 38 checksums, 276 source bindings, 1,695 backup files, 15 semantic corruptions rejected. This remains the earlier sequential external-file drill; it does not integrate the new provider or provide a second independent native restore.
- **Source CI 8/8 SUCCESS**; general suite 445 reported minus 80 native skips = 365 executed PASS, blocking image scan and container boot successful. Previous deploy checkpoint `ee2d208` has **50/50 SUCCESS**; new documentation-commit checks are separate.

The first candidate `ba18f0c` passed 87 tests and eight workflows. Review identified that OS lock release after JVM death can precede resolution of a sent PostgreSQL COMMIT. The final candidate adds a durable unresolved lease latch and UNKNOWN handling; the first qualification is preserved but superseded.

Scope: same-host cooperating processes on a protected local POSIX store. Process kill/halt is not host power-loss testing; UNKNOWN is injected, not a real database/network failure. No multi-host, authority-store rollback, operational mount qualification, automatic reconciliation or production wiring is claimed.

MinIO/source-lock unchanged; MiniPET **18.3/46 = 39.78%, 0/8 gates, 0/21 AT, 0/120 real objects**. No merge, deployment, target operation, runtime grant or automatic re-admission. Remaining work includes observable unresolved state and governed owner-outcome reconciliation/resume, custody/authenticated publication, full owner-budget rollback, UDP/Ingestion and RPO/RTO.

[Dossier](https://github.com/GioNob/ouf-deploy/blob/105a35cd55b0db3822f12188dd0d5e958ca22156/docs/OUF_STORAGE_DURABLE_LOCAL_AUTHORITY_20261105.md), [qualification receipt](https://github.com/GioNob/ouf-deploy/blob/105a35cd55b0db3822f12188dd0d5e958ca22156/evidence/storage-durable-local-authority-qualified-20261105.json), [native archive verifier](https://github.com/GioNob/ouf-deploy/blob/105a35cd55b0db3822f12188dd0d5e958ca22156/scripts/readback-durable-authority-native-20261105.py), [handoff](https://github.com/GioNob/ouf-deploy/blob/105a35cd55b0db3822f12188dd0d5e958ca22156/docs/handoffs/OUF_STORAGE_ONBOARDING_RECOVERY_HANDOFF_20261105.md), [previous PR descriptions and handoff](https://github.com/GioNob/ouf-deploy/blob/105a35cd55b0db3822f12188dd0d5e958ca22156/docs/handoffs/OUF_PR54_STORAGE_HISTORY_BEFORE_DURABLE_AUTHORITY_20261105.md).

## Handoff precedente

# Ripresa storage — autorità durevole locale, 5 novembre 2026

Continuare **due passi alla volta, senza subagenti**. Leggere HEAD e CI prima di modificare; non ripetere prove concluse senza cambiamenti o motivi documentati.

## Checkpoint 2026-11-05 — autorità durevole locale e blocco dopo esito owner incerto

- Due passi completati: provider indipendente `FilePlatformRecoveryAuthority`; qualifica nativa tra JVM separate di restart/revoca/crash. Fonte Onboarding `bf8bb65cf353dc60c9482dd6fe50e4416b2eefe6`, PR54 draft.
- Store POSIX privato esterno al backup owner/Authorization; guard OS esclusivo stabile, generazione attesa, replay identico senza rinnovo, pubblicazione atomica con fsync. Prima della lease viene persistito `lease.active`; solo commit/rollback noto lo rimuove. Morte processo o UNKNOWN bloccano lettori e publisher anche dopo restart. Nessuna cancellazione automatica o riconciliazione operativa implementata.
- **80 scenari nativi + 8 API/storage = 88 PASS**, nove nuovi casi; **CI sorgente 8/8 SUCCESS**. Suite generale 445 − 80 skip nativi = 365 PASS, scan immagine e boot riusciti. Readback nativo: 125 membri, 124 checksum, 273 blob Git verificati.
- Regressione fisica/readback SUCCESS: 39 membri, 38 checksum, 276 sorgenti, 1.695 file backup, 15 alterazioni respinte. Driver fisico sequenziale precedente, non integrazione del nuovo provider. Checkpoint deploy precedente `ee2d208fe5ade40180b522d74360c31ebab276e2`: tutti i 50 workflow SUCCESS.
- Qualifica same-host/local POSIX, ext4 effettivo; UNKNOWN iniettato e crash processo, non guasto reale DB/rete o power loss. Niente multi-host, rollback dello store esterno, wiring operativo, issuer/grant o nuova ammissione. MinIO/source-lock invariati; MiniPET **18,3/46 = 39,78%, 0/8 gate, 0/21 AT, 0/120 oggetti reali**.
- Prossima coppia: osservabilità dello stato non risolto e riconciliazione esito owner; qualifica ripresa governata dopo commit/quiescenza verificati e nuova generazione. Non cancellare latch in base a PID/timeout.
- Riferimenti: `docs/OUF_STORAGE_DURABLE_LOCAL_AUTHORITY_20261105.md`, `evidence/storage-durable-local-authority-qualified-20261105.json`, `scripts/readback-durable-authority-native-20261105.py`, handoff corrente e archivio `docs/handoffs/OUF_PR54_STORAGE_HISTORY_BEFORE_DURABLE_AUTHORITY_20261105.md`.


Onboarding: branch `feat/storage-upload-intent-20261105`, [PR54](https://github.com/GioNob/ouf-source-onboarding/pull/54), HEAD bf8bb65. Deploy: branch `feat/m2-discovery-complete-profile-20261029`, [PR54](https://github.com/GioNob/ouf-deploy/pull/54), leggere l'HEAD contenente questo handoff. Entrambe draft/open; nessun merge/deploy/target/grant.

[Dossier](../OUF_STORAGE_DURABLE_LOCAL_AUTHORITY_20261105.md), [ricevuta](../../evidence/storage-durable-local-authority-qualified-20261105.json), [storia precedente completa](OUF_PR54_STORAGE_HISTORY_BEFORE_DURABLE_AUTHORITY_20261105.md).

La prima qualifica ba18f0c (87 test PASS, 8/8 CI) è conservata ma superata dal latch durevole finale. Il provider è costruito esplicitamente nei test e non è un bean/endpoint. Non scambiare lo store corrente per audit approvativo o issuer. Non rimuovere né ricreare guard/store per aggirare uno stato incerto; mantenere il diniego fino a una futura procedura governata dimostrata.

L'ambiente locale Windows non esegue i test Java21/PostgreSQL17/OCI nativi; la qualifica è CI Linux/ext4. Il verificatore Python confronta l'archivio nativo con i blob Git del commit esatto, senza ripetere test nativi.

Restano aperti: custodia e qualifica mount operativo, pubblicazione autenticata e audit, recovery/startup, budget dopo rollback owner completo, multi-host, UDP/Ingestion, mixed rollout, riapertura e RPO/RTO. Non cambiare source-lock, MinIO o i crediti MiniPET sulla base di questi test sintetici.
