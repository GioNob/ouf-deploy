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
