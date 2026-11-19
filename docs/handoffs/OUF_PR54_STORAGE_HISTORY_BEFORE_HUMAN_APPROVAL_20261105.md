# Storia PR54 prima del collegamento HUMAN — 2026-11-05

Snapshot integrale precedente: source `529aca458ea7c3699d1437934ea7cd4379d70870`, deploy `7e04721bcc3722857eb152c26c715de31906917a`. Descrizioni e handoff seguenti sono storici; il checkpoint corrente è HUMAN_APPROVAL.

## PR54 source — Bind storage authority to PostgreSQL owner transactions and resolve uncertain COMMIT

An uncertain owner COMMIT now leaves a durable marker bound to the actual Spring-owned PostgreSQL transaction. The new resolver reads its terminal outcome from PostgreSQL, so a dropped COMMIT reply can be distinguished from an unsent or still-pending COMMIT without trusting a fixture outcome oracle. Earlier upload, policy delivery, observation, reconciliation and rollback protections remain; their prior descriptions and handoff are preserved in the history below.

The bound store records xid8, cluster system identifier, database OID and admitted postmaster start time before granting the lease. Capture requires the exact transaction-bound DataSource/connection, primary PostgreSQL17 and synchronous_commit=on. Missing admission metadata cannot downgrade the store to legacy mode. No implicit legacy migration or automatic restart/restore rebind is provided.

The resolver queries outside the owner transaction and file guard, accepts only committed/aborted, and returns an opaque proof bound to the exact request and recorded transaction. In-progress/prepared, discarded/NULL, SQL errors and identity mismatches deny resolution. The provider rechecks marker, transaction and held approval under the guard, writes the existing durable receipt and publishes the next generation revoked before clearing the exact latch. Proof lifetime is at most 30 seconds within an approval of at most five minutes. Resume still requires separate publication, admission and decision; exhausted budgets remain exhausted.

**Authenticated HUMAN approval and operational wiring remain unimplemented.** ApprovalLease is a trusted port supplied synthetically by tests; the transaction outcome is read from real PostgreSQL. No endpoint, bean, runtime grant or operational admission is installed. SQL/network timeouts are two seconds; the injected DataSource must separately bound acquisition/login/pool waits. Least-privilege operational qualification remains open.

Validation at source `529aca458ea7c3699d1437934ea7cd4379d70870`:

- [Native owner 42043116716](https://github.com/GioNob/ouf-source-onboarding/actions/runs/42043116716): **97 native scenarios + 8 API/storage tests = 105 PASS**, zero failures/errors/skips. Eight new cases cover exact transaction binding, actual TCP lost-reply/unsent/delayed COMMIT, COMMIT/ROLLBACK PREPARED, invalid database/approval, real PostgreSQL restart and stale prepared proof. The three TCP cases produce real JDBC/Spring failures without injected UNKNOWN; older oracle tests remain distinct.
- Native archive verified locally against the exact Git commit: **174 members, 173 checksums, 278 source blobs**, 26 provider receipts, 17 child JVM logs and five full PostgreSQL outcome receipts. This is archive verification, not repeated native execution.
- [Physical regression/readback 42043116701](https://github.com/GioNob/ouf-source-onboarding/actions/runs/42043116701): both jobs SUCCESS; 39 members, 38 checksums, 281 source bindings, 1,695 backup files and 15 semantic corruptions rejected. The existing sequential physical driver does not integrate the new resolver; readback is not an independent native restore. The physical ZIP was not reverified locally in this block.
- **Source CI 8/8 SUCCESS**; general suite 462 reported minus 97 native skips = 365 executed PASS; blocking image scan and container boot successful. All ten changed source files reread after publication. Prior deploy checkpoint `a9a8fb1`: **50/50 SUCCESS**. Checks for this documentation commit are separate.

Scope remains same-host/local POSIX/ext4 and PostgreSQL17. Actual restart is qualified as denial of the old admission, not automatic recovery. The loopback TCP fixture uses simple-query without TLS/GSS. Operational approval, least privileges, custody/store rollback, governed restore/rebind, actual XID-history exhaustion, TLS faults, multi-host, full owner rollback budgets, Gateway/MCP observation, UDP/Ingestion, mixed rollout and RPO/RTO remain open.

No merge, deployment, target operation, grant, automatic re-admission or MinIO/source-lock change. MiniPET **18.3/46 = 39.78%, 0/8 gates, 0/21 AT, 0/120 real objects**.

[Dossier](https://github.com/GioNob/ouf-deploy/blob/7e04721bcc3722857eb152c26c715de31906917a/docs/OUF_STORAGE_POSTGRES_OWNER_OUTCOME_20261105.md), [qualification receipt](https://github.com/GioNob/ouf-deploy/blob/7e04721bcc3722857eb152c26c715de31906917a/evidence/storage-postgres-owner-outcome-qualified-20261105.json), [native archive verifier](https://github.com/GioNob/ouf-deploy/blob/7e04721bcc3722857eb152c26c715de31906917a/scripts/readback-postgres-authority-native-20261105.py), [current handoff](https://github.com/GioNob/ouf-deploy/blob/7e04721bcc3722857eb152c26c715de31906917a/docs/handoffs/OUF_STORAGE_ONBOARDING_RECOVERY_HANDOFF_20261105.md), [previous PR descriptions and handoff](https://github.com/GioNob/ouf-deploy/blob/7e04721bcc3722857eb152c26c715de31906917a/docs/handoffs/OUF_PR54_STORAGE_HISTORY_BEFORE_POSTGRES_OUTCOME_20261105.md).

Next pair: bind authenticated, revocable HUMAN approval to the exact command fingerprint; qualify that binding with least PostgreSQL privileges and finite connection acquisition limits. Keep restart/restore rebind denied until separately governed and qualified.

## PR54 deploy — Qualify bound PostgreSQL owner outcomes with real COMMIT faults

Record the source candidate, complete receipts, pinned archive verifier and current handoff; preserve all prior checkpoint history. This PR changes qualification records and does not deploy the provider.

An uncertain owner COMMIT now leaves a durable marker bound to the actual Spring-owned PostgreSQL transaction. The new resolver reads its terminal outcome from PostgreSQL, so a dropped COMMIT reply can be distinguished from an unsent or still-pending COMMIT without trusting a fixture outcome oracle. Earlier upload, policy delivery, observation, reconciliation and rollback protections remain; their prior descriptions and handoff are preserved in the history below.

The bound store records xid8, cluster system identifier, database OID and admitted postmaster start time before granting the lease. Capture requires the exact transaction-bound DataSource/connection, primary PostgreSQL17 and synchronous_commit=on. Missing admission metadata cannot downgrade the store to legacy mode. No implicit legacy migration or automatic restart/restore rebind is provided.

The resolver queries outside the owner transaction and file guard, accepts only committed/aborted, and returns an opaque proof bound to the exact request and recorded transaction. In-progress/prepared, discarded/NULL, SQL errors and identity mismatches deny resolution. The provider rechecks marker, transaction and held approval under the guard, writes the existing durable receipt and publishes the next generation revoked before clearing the exact latch. Proof lifetime is at most 30 seconds within an approval of at most five minutes. Resume still requires separate publication, admission and decision; exhausted budgets remain exhausted.

**Authenticated HUMAN approval and operational wiring remain unimplemented.** ApprovalLease is a trusted port supplied synthetically by tests; the transaction outcome is read from real PostgreSQL. No endpoint, bean, runtime grant or operational admission is installed. SQL/network timeouts are two seconds; the injected DataSource must separately bound acquisition/login/pool waits. Least-privilege operational qualification remains open.

Validation at source `529aca458ea7c3699d1437934ea7cd4379d70870`:

- [Native owner 42043116716](https://github.com/GioNob/ouf-source-onboarding/actions/runs/42043116716): **97 native scenarios + 8 API/storage tests = 105 PASS**, zero failures/errors/skips. Eight new cases cover exact transaction binding, actual TCP lost-reply/unsent/delayed COMMIT, COMMIT/ROLLBACK PREPARED, invalid database/approval, real PostgreSQL restart and stale prepared proof. The three TCP cases produce real JDBC/Spring failures without injected UNKNOWN; older oracle tests remain distinct.
- Native archive verified locally against the exact Git commit: **174 members, 173 checksums, 278 source blobs**, 26 provider receipts, 17 child JVM logs and five full PostgreSQL outcome receipts. This is archive verification, not repeated native execution.
- [Physical regression/readback 42043116701](https://github.com/GioNob/ouf-source-onboarding/actions/runs/42043116701): both jobs SUCCESS; 39 members, 38 checksums, 281 source bindings, 1,695 backup files and 15 semantic corruptions rejected. The existing sequential physical driver does not integrate the new resolver; readback is not an independent native restore. The physical ZIP was not reverified locally in this block.
- **Source CI 8/8 SUCCESS**; general suite 462 reported minus 97 native skips = 365 executed PASS; blocking image scan and container boot successful. All ten changed source files reread after publication. Prior deploy checkpoint `a9a8fb1`: **50/50 SUCCESS**. Checks for this documentation commit are separate.

Scope remains same-host/local POSIX/ext4 and PostgreSQL17. Actual restart is qualified as denial of the old admission, not automatic recovery. The loopback TCP fixture uses simple-query without TLS/GSS. Operational approval, least privileges, custody/store rollback, governed restore/rebind, actual XID-history exhaustion, TLS faults, multi-host, full owner rollback budgets, Gateway/MCP observation, UDP/Ingestion, mixed rollout and RPO/RTO remain open.

No merge, deployment, target operation, grant, automatic re-admission or MinIO/source-lock change. MiniPET **18.3/46 = 39.78%, 0/8 gates, 0/21 AT, 0/120 real objects**.

[Dossier](https://github.com/GioNob/ouf-deploy/blob/7e04721bcc3722857eb152c26c715de31906917a/docs/OUF_STORAGE_POSTGRES_OWNER_OUTCOME_20261105.md), [qualification receipt](https://github.com/GioNob/ouf-deploy/blob/7e04721bcc3722857eb152c26c715de31906917a/evidence/storage-postgres-owner-outcome-qualified-20261105.json), [native archive verifier](https://github.com/GioNob/ouf-deploy/blob/7e04721bcc3722857eb152c26c715de31906917a/scripts/readback-postgres-authority-native-20261105.py), [current handoff](https://github.com/GioNob/ouf-deploy/blob/7e04721bcc3722857eb152c26c715de31906917a/docs/handoffs/OUF_STORAGE_ONBOARDING_RECOVERY_HANDOFF_20261105.md), [previous PR descriptions and handoff](https://github.com/GioNob/ouf-deploy/blob/7e04721bcc3722857eb152c26c715de31906917a/docs/handoffs/OUF_PR54_STORAGE_HISTORY_BEFORE_POSTGRES_OUTCOME_20261105.md).

Next pair: bind authenticated, revocable HUMAN approval to the exact command fingerprint; qualify that binding with least PostgreSQL privileges and finite connection acquisition limits. Keep restart/restore rebind denied until separately governed and qualified.

## Handoff precedente integrale

# Ripresa storage — esito PostgreSQL reale, 5 novembre 2026

Continuare **due passi alla volta, senza subagenti**. Leggere HEAD e CI; non duplicare prove già riuscite senza cambiamenti o motivi documentati.

## Checkpoint 2026-11-05 — binding owner PostgreSQL e risoluzione dell'esito reale

- Due passi completati: lease persistente legata alla transazione Spring owner effettiva (xid8, system identifier, database OID, avvio postmaster); resolver PostgreSQL qualificato con guasti TCP/JDBC reali durante COMMIT. Sorgente `529aca458ea7c3699d1437934ea7cd4379d70870`, PR54 draft.
- Il marker bound richiede metadata `owner.database` ammessi e prova opaca del resolver sul comando e sulla transazione esatti. Solo committed/aborted sono terminali; in progress, prepared non conclusa, NULL, errore o identità diversa bloccano. Preflight SQL fuori dal guard; ricontrollo approvazione/prova sotto guard, ricevuta durevole e generazione successiva revocata. Nessuna riapertura automatica.
- Otto nuovi casi: binding connessione, risposta COMMIT persa, COMMIT non inviato, COMMIT ritardato, prepared commit/rollback, database/approvazione errati, restart PostgreSQL reale e prova superata. Le tre prove TCP non iniettano UNKNOWN; il resolver legge l'esito dal database reale. I test legacy con oracolo rimangono distinti.
- **L'approvazione HUMAN autenticata e il wiring operativo restano aperti**: approvazioni sintetiche nei test, nessun endpoint/bean/grant/ammissione installato. Prepared dura al massimo 30 secondi e non oltre l'approvazione (massimo cinque minuti). Query/socket limitati a due secondi; la DataSource operativa deve imporre un timeout finito di acquisizione/login/pool.
- **105 test PASS (97 nativi + 8 API/storage), CI sorgente 8/8 SUCCESS**. Generale: 462 riportati − 97 skip nativi = 365 PASS; scan bloccante e boot riusciti. Readback ZIP nativo: 174 membri, 173 checksum, 278 blob Git esatti; 26 ricevute provider, 17 log JVM, cinque ricevute di esito PG. Dieci file sorgente riletti dopo la pubblicazione.
- Regressione fisica/readback SUCCESS: 39 membri, 38 checksum, 281 sorgenti, 1.695 file backup, 15 alterazioni respinte. Driver sequenziale precedente, non integrazione del nuovo resolver né secondo restore nativo. Lo ZIP fisico non è stato riverificato localmente in questo blocco. Predecessore deploy `a9a8fb196dabe4c94cafee2ccae8814f212d085c`: **50/50 SUCCESS**; i nuovi controlli documentali sono distinti.
- Restart PG cambia l'identità ammessa e blocca vecchia risoluzione/ammissione. Non cancellare metadata o latch, non catturare l'owner XID su una nuova connessione, non riammettere automaticamente dopo restart/restore. Custodia/rollback dello store, failover/restore, storia XID esaurita, privilegi minimi e TLS fault restano da qualificare.
- Prossima coppia: collegamento dell'approvazione HUMAN autenticata/revocabile al fingerprint esatto; qualifica con profilo PostgreSQL a privilegi minimi e timeout finiti. Il rebind dopo restart resta negato fino a prove governate dedicate.
- MinIO/source-lock invariati; MiniPET **18,3/46 = 39,78%, 0/8 gate, 0/21 AT, 0/120 oggetti reali**. Nessun merge, deploy, target o grant. Budget owner già esauriti e ammissione separata per riprendere restano invariati.
- Dossier `docs/OUF_STORAGE_POSTGRES_OWNER_OUTCOME_20261105.md`, ricevuta `evidence/storage-postgres-owner-outcome-qualified-20261105.json`, verificatore `scripts/readback-postgres-authority-native-20261105.py`, archivio integrale precedente `docs/handoffs/OUF_PR54_STORAGE_HISTORY_BEFORE_POSTGRES_OUTCOME_20261105.md`.


Onboarding branch `feat/storage-upload-intent-20261105`, [PR54](https://github.com/GioNob/ouf-source-onboarding/pull/54), HEAD `529aca458ea7c3699d1437934ea7cd4379d70870`. Deploy branch `feat/m2-discovery-complete-profile-20261029`, [PR54](https://github.com/GioNob/ouf-deploy/pull/54): leggere l'HEAD contenente questo documento. Entrambe draft/open.

[Dossier](../OUF_STORAGE_POSTGRES_OWNER_OUTCOME_20261105.md), [ricevuta](../../evidence/storage-postgres-owner-outcome-qualified-20261105.json), [verificatore](../../scripts/readback-postgres-authority-native-20261105.py), [storia integrale precedente](OUF_PR54_STORAGE_HISTORY_BEFORE_POSTGRES_OUTCOME_20261105.md).

Il nuovo resolver elimina l'oracolo dell'esito per i marker bound, ma non costituisce un'approvazione HUMAN autenticata. `ApprovalLease` è ancora un'interfaccia fidata iniettata; le fixture ne forniscono un'implementazione sintetica. Il provisioning richiede un'identità già ammessa: `observe` legge fatti, non conferisce ammissione. Il provider non è installato come bean o endpoint.

La cattura avviene sulla connessione già appartenente alla transazione owner. La risoluzione usa una connessione distinta fuori da quella transazione e dal guard, chiusa prima del tratto che modifica lo store. Non confondere queste due fasi. Dopo preflight il provider ricontrolla marker/transazione e approvazione; il risultato è REVOKED. Pubblicazione di nuova generazione, ammissione e decisione rimangono azioni separate.

La qualifica prepared distingue davvero COMMIT PREPARED e ROLLBACK PREPARED; non qualifica restore o rebind. Il proxy TCP della fixture opera su loopback senza SSL/GSS e non registra autenticazione o dati. La qualifica resta Linux/ext4, PostgreSQL17, stesso host; Python locale ha verificato l'archivio contro Git senza rieseguire Java/PG.

Restano aperti anche custodia e retention governata dello store, storia business/budget dopo rollback owner completo, proiezione owner/Gateway/MCP, multi-host, UDP/Ingestion, rollout misto, riapertura traffico e RPO/RTO. Nessun credito MiniPET aggiunto.

