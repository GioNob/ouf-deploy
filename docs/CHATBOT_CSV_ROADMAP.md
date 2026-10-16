# Roadmap CSV/chatbot: 8 macrofasi tecniche e 6 tappe funzionali

Roadmap confermata dall'utente il 16 ottobre 2026. Numerazione stabile fino alla conclusione; non confondere queste macrofasi con i nomi interni del launcher. Aggiornare questo documento a ogni avanzamento o nuova evidenza. Negli aggiornamenti all'utente indicare fase tecnica N/8, stato, ostacolo, prossimo controllo e tappe funzionali completate N/6. Nessuna promessa sul numero di tentativi.

## Stato corrente

**Fase tecnica 5/8 sospesa; dimostrazione funzionale 0/6.**

L'esecuzione della prosecuzione `70af66b26d9a8dfdd7151c55f44eb5795fcc84a8` è arrivata a `PUBLISHING_REVIEWED_GATEWAY_ROUTES`, poi si è fermata con `GATEWAY_WRITE_OUTCOME_UNPROVEN_NO_REPLAY`. L'ordine del codice impone prima `migrate_mcp()` (con revoca verificata), quindi sostituzione/readiness e `verify_module()` di UDP e Onboarding. Le fasi 2–4 sono quindi superate nel flusso. La lettura VPS successiva conferma la fase 2 COMPLETE/CLEAN e la generazione UDP; la diagnosi completa successiva conferma entrambe le generazioni e le storie schema UDP/Onboarding. Non scambiare il successo del flusso precedente per disponibilità permanente dopo la cancellazione del worker.

**La fase 1 non è stata ripetuta:** vengono copiati/verificati i quattro archivi già COMPLETE, senza nuovi dump. I messaggi generici del launcher (`REGISTRY_REPLACEMENT_AND_VERIFICATION`, preparazione completa) descrivono passaggi comuni: in questa prosecuzione i dieci effetti Registry restano conservati e non vengono rieseguiti. Le autenticazioni/revisioni rinnovano la sola sessione finita, non la fase backup.

Il Gateway ha un claim di scrittura e una mappa riletta non uguale alla mappa attesa. L'ACK della PUT non è conservato dal codice corrente: dai soli log non si può distinguere mancata applicazione, normalizzazione lato APISIX o altra differenza. **Non rilanciare il delivery né ripetere la PUT.** Diagnosi già eseguita: [diagnosi GET/SELECT di fase 5](../releases/CHATBOT_GATEWAY_PHASE5_READBACK_20261016.md), vincolata al contesto, con differenze strutturali redatte e verifica delle fasi già superate. Il primo reader, pur avendo superato CI `38841644559`, si è fermato sul VPS per una collisione del campo riservato `readOnly` prima di leggere Gateway. Il test del flusso aveva una fixture SQL incompleta: la correzione mantiene il guard e annida i risultati SQL sotto `facts`. Nuovo sorgente `26defb34e5573f535f03be869050fe3811725fd5`, CI `38842513682`: 12 test passati senza skip, inclusi PostgreSQL e namespace reali; il nuovo test riproduce il difetto sulla vecchia riga. Diagnosi VPS corretta completata: due GET stabili, nove effetti applicati, decima route assente e mappa esattamente precedente al claim.

| # | Fase tecnica | Stato |
|---|---|---|
| 1 | Riconciliare il backup interrotto e completare i backup dei quattro database | COMPLETATA: quattro archivi COMPLETE, hash e journal verificati sul VPS; nessun nuovo dump nella ripresa |
| 2 | Applicare le migrazioni MCP e verificare la revoca dei privilegi temporanei | COMPLETATA e confermata sul VPS: 12 migrazioni attese, COMPLETE/CLEAN, privilegi temporanei revocati |
| 3 | Sostituire UDP e verificarne schema e avvio | COMPLETATA; rilettura VPS conferma generazione running/restart 0 e 35 migrazioni attese |
| 4 | Sostituire Onboarding e verificarne schema e avvio | COMPLETATA; rilettura VPS conferma generazione running/restart 0 e 34 migrazioni attese |
| 5 | Pubblicare e verificare le route Gateway | **Sospesa: GATEWAY_WRITE_OUTCOME_UNPROVEN_NO_REPLAY** |
| 6 | Sostituire Ingestion e verificarne schema e avvio | Da eseguire |
| 7 | Sostituire MCP e verificarne schema e avvio | Da eseguire |
| 8 | Verificare l'insieme e riabilitare i produttori | Da eseguire |

| # | Dimostrazione funzionale | Stato |
|---|---|---|
| 1 | Approvare la configurazione semantica del CSV Teatri | Da dimostrare |
| 2 | Completare l'onboarding con approvazione umana | Da dimostrare |
| 3 | Ottenere il commit effettivo in UDP delle 13 righe, con provenienza verificata | Da dimostrare |
| 4 | Ritrovare i dati con una nuova ricerca dal chatbot | Da dimostrare |
| 5 | Importare nuovamente lo stesso CSV e dimostrare il riuso degli oggetti senza duplicazioni | Da dimostrare |
| 6 | Verificare entrambe le acquisizioni e la conservazione degli otto oggetti Cinema esistenti | Da dimostrare |

## Collegamento schema/immagine target confermato, 06:26 Europe/Rome

La lettura mirata è completa: image ID corrispondente al manifest APISIX della riproduzione; schema canonico e proiezione metadata coincidono, URN annidato presente e zero riferimenti. Tutti e tre i massimi corrispondono al contratto safe integer. Due GET stabili: nove effetti applicati, decima route assente, journal immutato. Otto grant conservati, zero chiamate DB/letture backup/mutazioni. [Evidenza](../evidence/chatbot-gateway-schema-target-20261016.json). Non serve ripetere questa diagnosi per ricercare la stessa causa: prossimo lavoro è correzione della serializzazione, prova nativa dei limiti e prosecuzione governata. L'ACK storico resta non disponibile.

## Analisi successiva: compatibilità schema APISIX

La riproduzione isolata con Admin API APISIX reale restituisce HTTP 400 sulla stessa decima route per un `$id` URN annidato non supportato. La proiezione candidata elimina solo il metadato senza riferimenti, lasciando intatto il contratto canonico. La prova su tutte le 37 route ha inoltre rilevato tre massimi numerici alterati da 9007199254740991 a 9007199254741000.0: **il candidato non è ancora applicabile**, nessuna tolleranza nel confronto né indebolimento dei limiti. Prossimo controllo target: [schema e immagine, solo GET senza DB o archivi](../releases/CHATBOT_GATEWAY_SCHEMA_DIAGNOSIS_20261016.md). CI reader 16 test senza skip; riproduzione candidata 37 accettate, 34 GET esatte, 3 differenze ancora aperte. Fase 5/8, CSV 0/6.

## Diagnosi completa VPS, 16 ottobre 2026 05:04 Europe/Rome

Log `/home/oufadmin/ouf-gateway-state.QOMMaUj8/read.log`, sorgente reader `26defb34e5573f535f03be869050fe3811725fd5`: END complete, archivi/journal immutati, zero dump/mutazioni/grant/IAM. Fasi 1–4 confermate nei checkpoint e nelle letture native/schema; la readiness corrente non è stata riprovata e non costituisce accettazione permanente.

Gateway: **9 modifiche APPLIED su 37**, claim alla posizione 10 (`nextStep=9`), due inventari identici alla mappa prima del claim. La route rivendicata è assente; nessuna differenza estranea. L'hash ID corrisponde nel sorgente pubblico a `mcp-managed-file-review-prepare`. L'ACK non è conservato: assenza osservata non dimostra causa, assenza storica di effetti o autorizzazione a ripetere PUT. Il claim resta consumato. Prossimo lavoro: riproduzione isolata del pacchetto originale con Admin API APISIX reale; poi diagnosi/correzione e riconciliazione governata. Otto grant conservati; fasi 6–8 e CSV 0/6 invariati. [Evidenza completa](../evidence/chatbot-gateway-target-readback-20261016.json).

## Ultima diagnosi VPS: parziale, fermata su RESERVED_OUTPUT_FIELD

Log `/home/oufadmin/ouf-gateway-state.FU6f1wTi/read.log`, reader sorgente `ebdcf153c450ea5ab55c1783d281f1b963c5c29c`. Quattro archivi COMPLETE invariati; checkpoint MCP COMPLETE/CLEAN, container migrazione exited 0 e 12 migrazioni attese presenti. Membership/CREATE/TRIGGER temporanei assenti, proprietà/OID/ACL preesistenti preservati. Registry conserva dieci effetti APPLIED. Worker CANCELLED: **8 grant cumulativi**, 2 nella sessione, nessun reset.

UDP running, generazione attesa e cinque effetti completati, restart 0. Il reader si arresta mentre emette lo schema UDP: `module_schema_read` restituisce `readOnly`, campo riservato nell'involucro. Nessuna lettura Gateway né verifica Onboarding raggiunta; controlli finali di stabilità non eseguiti. Zero mutazioni/dump/grant della diagnosi; non dichiararla completa. La correzione della sola emissione e del test non modifica criteri runtime, autorità o normalizzazione Gateway. [Evidenza parziale](../evidence/chatbot-gateway-target-partial-readback-20261016.json).

## Ultimo arresto VPS (16 ottobre 2026, output ricevuto alle 04:30 Europe/Rome)

Revisione `bd2cbc1e969bf3eb4c5b1b54240cf1d67d3283685bc1ca563f893d17e3430144`, autorità `0e3a1a76b5528704c3295eff50c92b269a4f69c7d5eeff3304b193e991b54cb8`.
Contesto `/etc/ouf/deploy-snapshots/chatbot-file-cohort-signed-35d5c6c756feb9c4811ac6d24610698a10c82d22b831d2cc85cd5c22c94d40d5`.
Unità `ouf-file-cohort-35d5c6c756feb9c4811ac6d24610698a.service`, PID iniziale 3622829, piano `b7bd0f0906ab9741b06e91040bd3f402c933b79fbed606cdde003e67d4afd538`, scadenza 1792121285, restart=no.
Log `/home/oufadmin/ouf-mcp-phase2-continuation-launch.AINt2Om8/run.log`.
La rilettura successiva conferma otto grant cumulativi: sei precedenti e due nella sessione, due pubblicazioni; worker CANCELLED e admission BLOCKED. Nessun reset, restore, nuovo primo grant o accettazione permanente. Fasi 6–8 non raggiunte; CSV 0/6.

## Qualificazione storica della prosecuzione di fase 2

Runtime `70af66b26d9a8dfdd7151c55f44eb5795fcc84a8`: CI completa `38838880289` superata, 435 test/58 suite, zero errori o skip. CI backup `38838880431`: 79 test/7 suite, parzialmente sovrapposti alla completa. CI nativa `38839051380`: binario MCP originale su Docker 29.8.1/PostgreSQL 17, da 9 a 12 migrazioni e revoca verificata dei privilegi temporanei; nessun accesso al VPS. Un ulteriore test locale del percorso produzione conferma completamento/pulizia e riconciliazione senza secondo start (13 test locali della nuova suite).

**Passo storico, ora consumato: nuova revisione completa sul VPS** con `scripts/launch-chatbot-mcp-phase2-continuation-20261016.sh`. La nuova sessione conserva sei grant cumulativi; il prossimo è il settimo. L'esecuzione successiva ha superato le fasi 2–4 nel flusso ed è sospesa in fase 5. Il launcher consumato non va ripetuto.

## Precedente conferma VPS (16 ottobre 2026, 03:56 Europe/Rome)

Diagnosi `ouf.chatbot-mcp-migration-readback.v1` conclusa con `complete=true`, zero mutazioni/dump/grant. Fase 1 definitivamente confermata per questo checkpoint: UDP 247357 byte, Onboarding 325831, Ingestion 94318, MCP 250874, tutti COMPLETE e immutati. Il nuovo MCP ha SHA256 `b050f7706b650199a09115e24828858de509179f26896c92072cab6ae9946dc4`.

Fase 2: container `e502ee4e5ebd13ca6cbc8857756d895668a06bd9ca4a44a0b27ed1b0232a12c6`, stato created, mai avviato, PID 0, restart 0. Soli confronti falliti: Env e Labels; entrambi coincidono con immagine più richiesta. Nove migrazioni, identiche alla baseline pre-migrazione; risultato atteso non ancora raggiunto. Ruolo audit BOOTSTRAPPED/NOLOGIN, membership SET=1, CREATE schema=true, TRIGGER temporaneo=1; proprietario/OID/ACL preesistenti preservati. Revoca ancora da eseguire e verificare.

Worker CANCELLED con 1 nuovo tentativo e 1 pubblicazione; **6 grant cumulativi**, predecessori 5. Admission BLOCKED. Registry READY v30 con dieci effetti APPLIED; zero effetti nei journal containers/authorization/gateway. Archivi e journal immutati durante la lettura. I controlli di integrità restano obbligatori: non equivalgono a ripetere la fase 1. La nuova prosecuzione deve usare tutti e quattro gli archivi e il container già creato, senza dump/create ripetuti; conserva i sei tentativi.

## Evidenza storica della sospensione al 16 ottobre 2026

Ultimo sorgente runtime: `b93e3570bd3e43b6c8e99d2237743bb819e43304`; release `cc8921b87a55d17f2a548f6be59eb592b9bd7581`. Il preflight del Registry già in esecuzione e del filesystem è passato sul VPS. Le dieci fasi Registry precedenti restano conservate.

Revisione approvata dall'utente: `225d317b485939ebf2a5b2582d0f5168a5ff6fe19be17e0e68109c9003dade1c`.
Autorità della nuova sessione: `ce4fcdc3b0af1aaee503582f00af4beed06786641d15afe4a55efa0cd29584d7`.
Contesto: `/etc/ouf/deploy-snapshots/chatbot-file-cohort-signed-f9616bc49b224fa219e6ea4b8c9ff5425f9728fda0bc2175d6d877ebb5189a9a`.
Unità: `ouf-file-cohort-f9616bc49b224fa219e6ea4b8c9ff542.service`.
Piano: `6714bf5f617fb53535d5cb3ee6ebf74abe4af841f83b42346a1c7b9d00ddb1e6`.
Scadenza dichiarata: `1792118031`; finestra massima 3600 secondi, nessun rinnovo automatico.

Il traceback raggiunge `databases.migrate_mcp`, riga 668, nella verifica native dopo create e prima di start. Il flusso ha già completato `backup_quiesced()` e verificato nuovamente l'archivio MCP prima del punto fallito: questo sostiene il superamento della fase 1. Questa era l'incertezza iniziale, risolta dalla lettura VPS riportata sopra. Non dichiarare già applicate le migrazioni o revocati i privilegi: la preparazione del ruolo audit precede il create e può avere lasciato privilegi temporanei.

Cinque grant erano consumati prima della nuova sessione; la successiva lettura ha confermato sei grant cumulativi. Il messaggio finale è `FINITE_DELIVERY_PROCESS_STOPPED_INSPECT_RETAINED_STATUS`, con autorità emessa. Nessuna prova end-to-end e nessuna accettazione permanente.

## Regole di prosecuzione

- Prima riconciliare con letture bounded, redatte e vincolate al contesto esatto; conservare claim, archivi, journal, conteggi e storia.
- Non ripetere il launcher già consumato, create/start ambigui o le dieci fasi Registry; non sostituire i backup né ripristinare il DB precedente.
- Non azzerare budget o estendere l'autorità. Una diversa ripresa richiede revisione governata concreta; delega allo sviluppo non equivale ad autorità runtime HUMAN.
- Correggere il contratto di identità solo sulla base dell'immagine e della richiesta verificate, mai consentendo genericamente differenze o variabili aggiuntive.
- Qualificare il comportamento Docker reale rilevante oltre ai test con engine simulato. Documentare separatamente prova CI, prova VPS e parti ancora non verificate.
- Proseguire autonomamente su codice/analisi/CI; fermarsi quando occorre l'intervento dell'utente sul VPS. Tenere l'utente aggiornato durante il lavoro.

Riferimenti: `AGENTS.md`, `docs/OUF_RESILIENCE_POLICY.md`, `releases/CHATBOT_RUNNING_ROOTFS_RECOVERY_20261016.md`.
