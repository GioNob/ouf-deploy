# Handoff alla chat cloud — OUF storage, 4 novembre 2026

## Punto di ripresa

- Repository: GioNob/ouf-deploy.
- PR corrente: https://github.com/GioNob/ouf-deploy/pull/54 (draft, non integrata).
- Branch: `feat/m2-discovery-complete-profile-20261029`.
- HEAD verificato prima di questo handoff: `f039927a42bc2d51c9604dc9508f133b7c02f8e3`.
- Il README di main consultato in questa chat contiene checkpoint storici di ottobre: non usarlo come ultimo stato operativo.
- Leggere AGENTS.md e il MiniPET sul branch corrente; conservare la storia e controllare eventuali commit successivi prima di modificare il lavoro.

## Mandato dell'owner e ordine del lavoro

L'owner autorizza lettura e scrittura sui repository GioNob, aggiornamento delle evidenze e sviluppo autonomo passo per passo secondo PET/MiniPET. Ha autorizzato il plugin OUF con account **ouf-admin**. La disponibilità di tale collegamento deve essere verificata nella nuova chat: non si presume trasferita automaticamente.

Obiettivo: pipeline ripetibile e resiliente file → onboarding → Semantic Registry locale e, quando necessario, discovery OntoPiA tramite capabilities → ingestion → merge/reconciliation UDP → grafo UDP. Il passo corrente è la sostituzione MinIO con SeaweedFS e la rimozione delle dipendenze non mantenute. Dopo storage si riprende il residuo M2 file, poi search sul grafo, poi verticali/API con scheduler e delta.

La delega di sviluppo non sostituisce approvazioni HUMAN/THS, ammissioni e autorità runtime richieste dai contratti owner. Nessuna richiesta di generica riconferma per letture, sviluppo o verifiche già autorizzate. Nessun replay di scope consumati.

## Stato verificato e percentuale

**18,3/46 = 39,78%, circa 40% ±10 punti** di lavoro tecnico stimato. Non è percentuale di migrazione dati o di accettazione:
- 0/8 gate finali chiusi.
- 0/21 test di accettazione completati.
- 0/120 oggetti reali migrati.
- MinIO ancora attivo; nessun passaggio sul target in questa chat.

L'API GitHub Actions è stata letta in questa chat: run **41845769045**, producer `28c4890956dc74813dd3642042575799fa4d3a8b`, stato completed/success. Il dossier conservato registra **134 test e dieci scenari nativi PASS**. Non sono stati rieseguiti qui; ZIP originale e firma publisher non sono stati riverificati in questa chat.

Ultima prova acquisita: witness nativo da 1048593 byte dopo il tombstone nello stesso volume, offset header 4194392→8, persistente a 8 dopo riavvio; 4194304 byte allocati recuperati. Baseline S3 da 8388865 byte e metadati integri; orphan assente. Il witness nativo non è un nuovo oggetto S3 collegato al filer. Non prova crash durante compattazione né power loss/RPO/RTO.

Teatri/M1 preservato: 8/8 verifiche tecniche, 6/6 funzionali; 26 join, 13 identità, 20 proprietà, 8 Cinema. Farmacie/M2: stesso file, 61 righe, 10 campi OPEN, codice ministeriale STRING. Conservati 17 scope consumati / 52 Engine GET cumulativi. Questi sono stati documentati, non una nuova osservazione live del VPS.

## Lavoro realmente svolto nella chat locale

1. Consultati repository, rami, PR54, AGENTS, MiniPET, lock e manifest generation33, dossier di rilocazione e risultato Actions.
2. Identificato il branch di lavoro corretto, distinto dal main storico.
3. Verificato che il candidato corrente è SeaweedFS 4.52/generazione33, upstream `984eac6a790be89e2a11de175a7413e1e3e32dd3`. Il riferimento storico 4.51/`153ab668…` non è il pin corrente.
4. Esaminato `weed/storage/volume_vacuum.go` all'upstream 4.52 esatto e definito il protocollo della prossima prova.
5. Aggiornata la descrizione PR54 con “Continuation review — 4 November 2026 (design only; no new native run)”, conservando la descrizione precedente.
6. Creato questo handoff su richiesta dell'owner prima del passaggio alla chat cloud.

**Nessuna modifica al codice, nessun nuovo test o laboratorio eseguito, nessun clone locale, deploy, merge, chiamata operativa OUF o modifica VPS.** L'inventario ricorsivo della cartella locale non ha restituito file: non esistono patch o artefatti di questa chat rimasti soltanto sul PC. Gli strumenti locali sono stati usati per consultazione di directory/istruzioni. Il lavoro utile è nelle evidenze preesistenti, nella descrizione PR e in questo file.

## Prossimo singolo passo: crash durante compattazione

Stato: **analisi preparata; implementazione e qualifica nativa OPEN**. Nessun incremento percentuale per l'analisi.

Il sorgente upstream esatto distingue:
- prima del marker `.cpc`: `reconcileCompactState` abbandona i temporanei `.cpd/.cpx`, preservando la generazione precedente;
- con marker: `finishCompactSwap` completa le rinomine ancora pendenti;
- tra `.cpd→.dat` e `.cpx→.idx`: non deve essere servita una coppia con dati rilocati e indice precedente.

Questa è analisi di sorgente, non prova del binario finale modificato. Prima dell'iniezione, vincolare il sorgente effettivo con tutte le patch generation33 e la stessa OCI qualificata.

### Implementazione e criteri di prova

1. Riutilizzare il laboratorio di rilocazione, conservando tutti i dieci scenari di regressione. Prima nuova fase: interrompere il volume durante una compattazione precommit realmente osservata.
2. Identificare e fermare in modo verificabile l'esatto processo della fixture; dimostrare lavoro temporaneo in corso e assenza del marker/rename prima del singolo kill. Conservare evidenza dello stato arrestato prima della ripresa. Una sleep temporizzata o il solo successo del riavvio non provano la fase intercettata.
3. Qualificare separatamente marker già presente e intervallo fra le due rinomine. Fase mancata = non qualificata, mai PASS. Qualsiasi build strumentata deve essere identificata separatamente e non eredita la qualifica dell'OCI invariata.
4. Recuperare dalle stesse radici senza reinviare vacuum o riscrivere dati/indici. Rileggere integralmente baseline S3, hash, dimensione e metadati; witness nativo con identità/hash invariati; orphan logicamente assente; coerenza DAT/IDX; volumi non selezionati invariati.
5. Nel rollback precommit sono leciti vecchio offset e byte tombstoned ancora allocati: non imporre reclamation o rilocazione come se il commit fosse riuscito. Nel recupero postcommit richiedere la coppia nuova coerente.
6. Preservare namespace, identità container e gate/firewall prima di exec; tempi e budget finiti. Conservare fallimenti ed esiti incerti, senza retry mutativo automatico né pulizia manuale prima del readback.
7. Aggiornare GitHub con sorgente esatto, run, risultati, limiti e artifact verificati. Un SIGKILL a processo non dimostra power loss, reboot host, guasto disco o RPO/RTO rappresentativo.

Rimangono inoltre aperti manutenzione completa delle dipendenze e ownership patch, review licenze/redistribuzione, custodia durevole, recovery e obiettivi rappresentativi, binding/ammissione target e migrazione effettiva. Non chiudere G1 soltanto per la scansione pulita: il lock conserva `allDependenciesMaintained:false`.

## Riferimenti da leggere sul branch

- [MiniPET storage](../OUF_MINIO_SEAWEEDFS_MINIPET_v1_0_20261102.md)
- [MiniPET M2](../OUF_M2_MINIPET_v1_0_20261026.md)
- [Ultimo dossier di rilocazione](../OUF_STORAGE_RELOCATION33_20261104.md)
- [Readback conservato](../../evidence/storage-relocation33-readback-20261104.json)
- [Piano strutturato](../../releases/minio-seaweedfs-plan-20261102.json)
- [Lock generation33](../../releases/seaweedfs-452-generation33-candidate-lock-20261104.json)
- [Manifest build generation33](../../releases/seaweedfs-452-generation33-vendor-build-manifest-20261104.json)
- [Snapshot e validatori compattazione](../../scripts/storage-generation33-compaction.py)
- [Supporto rilocazione](../../scripts/storage-generation33-relocation.py)
- [Test rilocazione](../../tests/test_storage_relocation_generation33.py)
- [Sorgente upstream esatto esaminato](https://github.com/seaweedfs/seaweedfs/blob/984eac6a790be89e2a11de175a7413e1e3e32dd3/weed/storage/volume_vacuum.go)
- [Run verificato](https://github.com/GioNob/ouf-deploy/actions/runs/41845769045)

Il documento è un passaggio di consegne, non una nuova accettazione o un'autorizzazione runtime.
