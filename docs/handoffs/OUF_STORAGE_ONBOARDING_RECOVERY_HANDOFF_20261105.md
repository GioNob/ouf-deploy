# Ripresa storage — osservabilità e riconciliazione governata, 5 novembre 2026

Continuare **due passi alla volta, senza subagenti**. Leggere HEAD e CI; non duplicare prove riuscite senza cambiamenti o motivi documentati.

## Checkpoint 2026-11-05 — osservabilità e riconciliazione governata dell'autorità

- Due passi nel perimetro interno: osservazione read-only dello store e protocollo di riconciliazione dell'esatta lease. Fonte Onboarding `6eb268070ca9c96743cb399b51558016fdc96aa5`, PR54 draft. Stati CURRENT/CONTENDED/RECONCILE_REQUIRED/REVOKED/EXPIRED/FENCED/UNAVAILABLE; CURRENT non è readiness o ALLOW.
- La risoluzione richiede gate fidato con decisione esatta, esito COMMITTED/ROLLED_BACK ed esclusione owner mantenuta. Persistenza: ricevuta con checksum, generazione successiva revocata, nuovo controllo gate, cancellazione/fsync del marker esatto. Replay identico non rinnova; altro intento/nuova lease non vengono cancellati. Ricevute limitate a 8.192 byte e 128 per store; saturazione blocca senza eliminare storico.
- **Il gate operativo non è ancora implementato**: fixture con oracolo sintetico dell'esito e vero lock PostgreSQL NOWAIT. Commit/rollback e halt JVM sono reali; UNKNOWN è iniettato, non guasto reale di rete. Nessun endpoint/bean/capability/issuer/grant/ammissione installato.
- **97 test PASS (89 nativi + 8 API/storage)**; nove nuovi casi, 18 ricevute provider, 16 log JVM. CI sorgente **8/8 SUCCESS**; generale 454 − 89 skip nativi = 365 PASS, scan bloccante e boot riusciti. Readback locale nativo: 151 membri, 150 checksum, 275 blob Git verificati.
- Regressione fisica/readback SUCCESS: 39 membri, 38 checksum, 278 sorgenti, 1.695 file backup, 15 alterazioni respinte. Driver fisico precedente, non integrazione del nuovo resolver. Checkpoint deploy precedente `105a35cd55b0db3822f12188dd0d5e958ca22156`: 50/50 SUCCESS.
- Prima pubblicazione 297b7ed respinta per file test troncato nel trasferimento; corretta in 1b1dc75 (97 PASS). Il commit finale estende il filtro CI fisico alle fixture condivise. Storia e riferimenti conservati.
- Prossima coppia: correlazione durevole lease/transazione/database ammessi; resolver PostgreSQL qualificato su esito incerto reale senza oracolo di test. Custodia, restore/prepared transactions, wiring live e osservabilità MCP restano aperti. Non cancellare marker per PID o timeout.
- MinIO/source-lock invariati; MiniPET **18,3/46 = 39,78%, 0/8 gate, 0/21 AT, 0/120 oggetti reali**. Nessun merge/deploy/target. La ripresa dimostrata richiede pubblicazione separata generazione 3, nuova ammissione e nuova decisione; budget 128 esaurito preservato.
- Dossier `docs/OUF_STORAGE_GOVERNED_AUTHORITY_RECONCILIATION_20261105.md`, ricevuta `evidence/storage-governed-authority-reconciliation-qualified-20261105.json`, verificatore `scripts/readback-governed-authority-native-20261105.py`, handoff corrente e archivio `docs/handoffs/OUF_PR54_STORAGE_HISTORY_BEFORE_GOVERNED_RECONCILIATION_20261105.md`.


Onboarding branch `feat/storage-upload-intent-20261105`, [PR54](https://github.com/GioNob/ouf-source-onboarding/pull/54), HEAD 6eb2680. Deploy branch `feat/m2-discovery-complete-profile-20261029`, [PR54](https://github.com/GioNob/ouf-deploy/pull/54): leggere l'HEAD contenente questo documento. Entrambe draft/open. I controlli del nuovo commit documentale sono distinti dai 50/50 del predecessore.

[Dossier](../OUF_STORAGE_GOVERNED_AUTHORITY_RECONCILIATION_20261105.md), [ricevuta](../../evidence/storage-governed-authority-reconciliation-qualified-20261105.json), [verificatore](../../scripts/readback-governed-authority-native-20261105.py), [storia precedente integrale](OUF_PR54_STORAGE_HISTORY_BEFORE_GOVERNED_RECONCILIATION_20261105.md).

Il marker attuale contiene UUID e generazione, non l'identità PostgreSQL/XID: il gate di produzione non può inferire l'esito da una riga ACTIVE o dal rilascio OS. La fixture `FileAuthorityReconciliationLab` conosce il proprio esito e prova l'esclusione con FOR UPDATE NOWAIT; non è un resolver distribuibile. Il prossimo blocco deve chiudere questa correlazione prima di installare un percorso operativo.

Il provider è esplicitamente costruito, senza bean/endpoint. Il replay di una ricevuta già conclusa è lettura storica e non ammissione. Un esito parziale resta bloccato finché il gate non restituisce nuova prova fresca coerente con quella conservata. La risoluzione porta a REVOKED; nuova policy/ammissione/delivery sono separate e non azzerano i budget.

Restano aperti: prepared transactions e restore del database/store, custodia del mount, pubblicazione autenticata e audit, proiezione owner/Gateway/MCP, retention governata, multi-host, UDP/Ingestion, mixed rollout, riapertura traffico e RPO/RTO. Nessun credito MiniPET aggiunto per i test sintetici. Il computer locale Windows ha verificato l'archivio Python contro Git; esecuzione nativa Java21/PostgreSQL17/OCI33 su CI Linux/ext4.
