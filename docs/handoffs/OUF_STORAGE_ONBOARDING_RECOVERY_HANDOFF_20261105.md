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
