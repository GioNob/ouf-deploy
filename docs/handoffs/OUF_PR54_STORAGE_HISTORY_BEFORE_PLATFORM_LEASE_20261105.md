# PR54 e handoff prima del binding piattaforma e rollback logico — 5 novembre 2026

Stato precedente preservato; i nuovi risultati sono nel dossier successivo.

## Onboarding PR54

Restoring an old allowed policy and delivered recovery decision must not restore operational authority. V41 pins an independent current-authority generation in immutable decision history and idempotent command hashes; preparation, delivery and owner use require a fresh matching fence, with another check after owner audit. Missing adapters deny by default.

Durable uploads, bounded reconciliation and the actual Authorization registry bridge remain in place. The common-cut fixture now contains two real recovery decisions, versioned delivery and owner/policy audit. It revokes authority after the cut, restores the old DELIVERED state and proves that neither fresh preparation nor redelivery can bypass current revocation.

Validation on source `087fcf21e7402cd5057972093dc0565f03e35427`:

- [Native owner 42018524212](https://github.com/GioNob/ouf-source-onboarding/actions/runs/42018524212): **63 owner scenarios + 8 API/storage tests PASS**, zero failures/errors/skips.
- [Physical cut and independent readback 42018524202](https://github.com/GioNob/ouf-source-onboarding/actions/runs/42018524202): **both jobs SUCCESS**, now restoring populated decisions, projection, delivery/action audit and actual policy history. Direct fresh preparation and redelivery are denied after post-cut revocation, including when the independent current fence is absent.
- Readback: **39 ZIP members, 38 checksums, 272 source bindings, all 1,695 backup files**, and **15 semantic corruptions rejected** with recomputed outer checksums. Two synthetic objects/36 bytes, six native PUT denials, twelve storage and two PostgreSQL clean stops.
- **Source CI 8/8 SUCCESS**, including [PR 42018532139](https://github.com/GioNob/ouf-source-onboarding/actions/runs/42018532139), [push 42018524519](https://github.com/GioNob/ouf-source-onboarding/actions/runs/42018524519), blocking image scan and container boot. General suite: 428 reported minus 63 skipped native cases = 365 executed PASS; all 63 native cases ran separately.

[Dossier](https://github.com/GioNob/ouf-deploy/blob/aa17823c77b91c6d905731ce37b4809482afebca/docs/OUF_STORAGE_AUTHORIZATION_RESTORE_20261105.md), [exact receipt and artifact metadata](https://github.com/GioNob/ouf-deploy/blob/aa17823c77b91c6d905731ce37b4809482afebca/evidence/storage-authorization-restore-qualified-20261105.json), [handoff](https://github.com/GioNob/ouf-deploy/blob/aa17823c77b91c6d905731ce37b4809482afebca/docs/handoffs/OUF_STORAGE_ONBOARDING_RECOVERY_HANDOFF_20261105.md), [previous PR descriptions and handoff preserved](https://github.com/GioNob/ouf-deploy/blob/aa17823c77b91c6d905731ce37b4809482afebca/docs/handoffs/OUF_PR54_STORAGE_HISTORY_BEFORE_AUTHORIZATION_RESTORE_20261105.md).

The first source 788046bf passed native tests and physical restore, but readback rejected the post-revocation snapshot because changing state changes full-JSON row order. The original archive's digest and complete rows were checked locally; the final fix changes only readback to compare complete decision rows by primary key and adds an altered-generation negative. The first failure and artifacts remain preserved. Final artifacts 13410711639/13411121370/13409979051 are retained until 2027-02-03; no complete local readback of the final archive is claimed.

**Boundary:** internal same-PostgreSQL integration, no bean/endpoint, automatic registration/grant or production current-fence adapter. The production verifier must hold revocation exclusion through commit without remote I/O under owner locks. The physical fixture uses a bounded external file and sequential revocation; it does not establish distributed concurrent revocation or logical rollback safety. Gateway/THS/session binding, all-writer custody, durable denial audit, UDP/Ingestion, mixed rollout, governed reopening and representative RPO/RTO remain open. No merge, deployment, target operation or source-lock promotion. MinIO and MiniPET 18.3/46=39.78%, 0/8 gates, 0/21 AT, 0/120 real objects remain unchanged.

## Deploy PR54

Qualify physical recovery of populated Onboarding Authorization history and prevent restored policy from reissuing revoked authority. Implementation is in [Onboarding PR54](https://github.com/GioNob/ouf-source-onboarding/pull/54); this checkpoint records complete receipts, artifact custody, the corrected independent readback and preserved failed-attempt evidence.

Evidence checkpoint `aa17823c77b91c6d905731ce37b4809482afebca`. Previous deploy `254228b5f96130cc072a80e17079a2bbd2747513` completed **50/50 workflows successfully**. Checks triggered by this new documentation checkpoint are separate.

Validation on source `087fcf21e7402cd5057972093dc0565f03e35427`:

- [Native owner 42018524212](https://github.com/GioNob/ouf-source-onboarding/actions/runs/42018524212): **63 owner scenarios + 8 API/storage tests PASS**, zero failures/errors/skips.
- [Physical cut and independent readback 42018524202](https://github.com/GioNob/ouf-source-onboarding/actions/runs/42018524202): **both jobs SUCCESS**, now restoring populated decisions, projection, delivery/action audit and actual policy history. Direct fresh preparation and redelivery are denied after post-cut revocation, including when the independent current fence is absent.
- Readback: **39 ZIP members, 38 checksums, 272 source bindings, all 1,695 backup files**, and **15 semantic corruptions rejected** with recomputed outer checksums. Two synthetic objects/36 bytes, six native PUT denials, twelve storage and two PostgreSQL clean stops.
- **Source CI 8/8 SUCCESS**, including [PR 42018532139](https://github.com/GioNob/ouf-source-onboarding/actions/runs/42018532139), [push 42018524519](https://github.com/GioNob/ouf-source-onboarding/actions/runs/42018524519), blocking image scan and container boot. General suite: 428 reported minus 63 skipped native cases = 365 executed PASS; all 63 native cases ran separately.

[Dossier](https://github.com/GioNob/ouf-deploy/blob/aa17823c77b91c6d905731ce37b4809482afebca/docs/OUF_STORAGE_AUTHORIZATION_RESTORE_20261105.md), [exact receipt and artifact metadata](https://github.com/GioNob/ouf-deploy/blob/aa17823c77b91c6d905731ce37b4809482afebca/evidence/storage-authorization-restore-qualified-20261105.json), [handoff](https://github.com/GioNob/ouf-deploy/blob/aa17823c77b91c6d905731ce37b4809482afebca/docs/handoffs/OUF_STORAGE_ONBOARDING_RECOVERY_HANDOFF_20261105.md), [previous PR descriptions and handoff preserved](https://github.com/GioNob/ouf-deploy/blob/aa17823c77b91c6d905731ce37b4809482afebca/docs/handoffs/OUF_PR54_STORAGE_HISTORY_BEFORE_AUTHORIZATION_RESTORE_20261105.md).

The first source 788046bf passed native tests and physical restore, but readback rejected the post-revocation snapshot because changing state changes full-JSON row order. The original archive's digest and complete rows were checked locally; the final fix changes only readback to compare complete decision rows by primary key and adds an altered-generation negative. The first failure and artifacts remain preserved. Final artifacts 13410711639/13411121370/13409979051 are retained until 2027-02-03; no complete local readback of the final archive is claimed.

**Boundary:** internal same-PostgreSQL integration, no bean/endpoint, automatic registration/grant or production current-fence adapter. The production verifier must hold revocation exclusion through commit without remote I/O under owner locks. The physical fixture uses a bounded external file and sequential revocation; it does not establish distributed concurrent revocation or logical rollback safety. Gateway/THS/session binding, all-writer custody, durable denial audit, UDP/Ingestion, mixed rollout, governed reopening and representative RPO/RTO remain open. No merge, deployment, target operation or source-lock promotion. MinIO and MiniPET 18.3/46=39.78%, 0/8 gates, 0/21 AT, 0/120 real objects remain unchanged.

Next pair: define the independent verifier's binding to existing platform/Authorization owners, then qualify logical rollback at unchanged PostgreSQL postmaster with current generations. Persistent preference: two steps per continuation, no subagents.

## Handoff precedente

# Ripresa storage — restore Authorization qualificato, 5 novembre 2026

Continuare per **due passi alla volta, senza subagenti**. Verificare branch e CI prima di modificare; non ripetere prove concluse senza modifiche o un motivo documentato.

- Deploy: PR54 draft, branch `feat/m2-discovery-complete-profile-20261029`; leggere l'HEAD che contiene questo handoff. Precedente254228b5f96130cc072a80e17079a2bbd2747513 con 50/50 CI SUCCESS.
- Onboarding: PR54 draft, branch `feat/storage-upload-intent-20261105`, fonte `087fcf21e7402cd5057972093dc0565f03e35427`.
- [Dossier](../OUF_STORAGE_AUTHORIZATION_RESTORE_20261105.md), [ricevuta](../../evidence/storage-authorization-restore-qualified-20261105.json). 63 scenari nativi + 8 API/storage PASS; common-cut/readback SUCCESS, 39 membri/38 checksum/272 sorgenti/1695 file backup, 15 negativi.
- **CI sorgente 8/8 SUCCESS**, incluse PR42018532139/push42018524519, scansione immagine bloccante e avvio container. Suite generale: 428 riportati meno 63 nativi saltati = 365 eseguiti PASS; i 63 nativi sono tutti eseguiti nel job dedicato.
- La prova fisica usa davvero Authorization: decisioni A/B, seconda consegna che revoca A, proiezione versione2, 5 eventi delivery e 4 owner; bundle e audit registry inclusi. Dopo il cut revoca B, proiezione3/null, policy2 senza grant e autorità esterna2/revocata. Restore torna alla policy1 e a B DELIVERED, ma nuova preparazione, riconsegna e owner sono negati. Anche l'autorità esterna assente blocca; snapshot owner/policy/audit invariati dopo dinieghi e verifica S3.
- `StorageRecoveryAuthorityFence` obbligatoria, indipendente dal set ripristinato; default senza verificatore nega. V41 registra generazione immutabile; vecchie righe V40 a zero inutilizzabili. Verifica corrente su prepare/deliver/uso owner e dopo audit. Il verificatore produttivo deve mantenere l'esclusione della revoca fino al commit, senza rete sotto lock. Nessuna implementazione produttiva installata.
- Il file esterno della fixture è sintetico, limitato a 4096 byte e usato con revoca sequenziale; non prova un protocollo distribuito concorrente. Runtime/sessione/postmaster, custody separata e budget128/24h restano in vigore. Nessun bean/endpoint/registrazione/grant automatico.
- Primo788046bf: native e restore PASS, readback fallito su confronto dell'ordine di righe dopo cambio stato. Diagnosi locale dell'originale con digest verificato; correzione solo readback, confronto completo per ID e nuovo negativo di generazione. Fallimento e archivi preservati nel dossier. Pacchetto finale non scaricato localmente.

Prossima coppia proposta: **1)** definire il binding del verificatore corrente indipendente agli owner piattaforma/Authorization esistenti; **2)** qualificare rollback logico a postmaster invariato e generazioni obsolete, senza grant target. Il restore fisico di V40 popolata è ora qualificato; il rollback logico rimane aperto.

MinIO/source-lock, MiniPET18,3/46=39,78%, 0/8 gate, 0/21 AT, 0/120 oggetti reali invariati. Nessun merge/deploy/target/admission/replay/reset/grant. Autenticazione Gateway/THS, custody completa, audit dinieghi, revoca distribuita, UDP/Ingestion, rollout misto, riapertura e RPO/RTO OPEN.
