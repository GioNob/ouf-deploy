# Roadmap CSV/chatbot: 8 macrofasi tecniche e 6 tappe funzionali

Roadmap confermata dall'utente il 16 ottobre 2026. Numerazione stabile fino alla conclusione; non confondere queste macrofasi con i nomi interni del launcher. Aggiornare questo documento a ogni avanzamento o nuova evidenza. Negli aggiornamenti all'utente indicare fase tecnica N/8, stato, ostacolo, prossimo controllo e tappe funzionali completate N/6. Nessuna promessa sul numero di tentativi.

## Stato corrente

**Fase tecnica 5/8 sospesa; dimostrazione funzionale 0/6.**

L'esecuzione della prosecuzione `70af66b26d9a8dfdd7151c55f44eb5795fcc84a8` è arrivata a `PUBLISHING_REVIEWED_GATEWAY_ROUTES`, poi si è fermata con `GATEWAY_WRITE_OUTCOME_UNPROVEN_NO_REPLAY`. L'ordine del codice impone prima `migrate_mcp()` (con revoca verificata), quindi sostituzione/readiness e `verify_module()` di UDP e Onboarding. Le fasi 2–4 sono quindi superate nel flusso; una nuova rilettura deve confermare checkpoint e stato persistito corrente. Non scambiare il successo del flusso precedente per disponibilità permanente dopo la cancellazione del worker.

**La fase 1 non è stata ripetuta:** vengono copiati/verificati i quattro archivi già COMPLETE, senza nuovi dump. I messaggi generici del launcher (`REGISTRY_REPLACEMENT_AND_VERIFICATION`, preparazione completa) descrivono passaggi comuni: in questa prosecuzione i dieci effetti Registry restano conservati e non vengono rieseguiti. Le autenticazioni/revisioni rinnovano la sola sessione finita, non la fase backup.

Il Gateway ha un claim di scrittura e una mappa riletta non uguale alla mappa attesa. L'ACK della PUT non è conservato dal codice corrente: dai soli log non si può distinguere mancata applicazione, normalizzazione lato APISIX o altra differenza. **Non rilanciare il delivery né ripetere la PUT.** Prossimo passo: diagnosi GET/SELECT vincolata al contesto, con differenze strutturali redatte e verifica delle fasi già superate.

| # | Fase tecnica | Stato |
|---|---|---|
| 1 | Riconciliare il backup interrotto e completare i backup dei quattro database | COMPLETATA: quattro archivi COMPLETE, hash e journal verificati sul VPS; nessun nuovo dump nella ripresa |
| 2 | Applicare le migrazioni MCP e verificare la revoca dei privilegi temporanei | Completata nel flusso; rilettura checkpoint CLEAN e DB da acquisire |
| 3 | Sostituire UDP e verificarne schema e avvio | Completata nel flusso; rilettura da acquisire |
| 4 | Sostituire Onboarding e verificarne schema e avvio | Completata nel flusso; rilettura da acquisire |
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

## Ultimo arresto VPS (16 ottobre 2026, output ricevuto alle 04:30 Europe/Rome)

Revisione `bd2cbc1e969bf3eb4c5b1b54240cf1d67d3283685bc1ca563f893d17e3430144`, autorità `0e3a1a76b5528704c3295eff50c92b269a4f69c7d5eeff3304b193e991b54cb8`.
Contesto `/etc/ouf/deploy-snapshots/chatbot-file-cohort-signed-35d5c6c756feb9c4811ac6d24610698a10c82d22b831d2cc85cd5c22c94d40d5`.
Unità `ouf-file-cohort-35d5c6c756feb9c4811ac6d24610698a.service`, PID iniziale 3622829, piano `b7bd0f0906ab9741b06e91040bd3f402c933b79fbed606cdde003e67d4afd538`, scadenza 1792121285, restart=no.
Log `/home/oufadmin/ouf-mcp-phase2-continuation-launch.AINt2Om8/run.log`.
Sei grant precedenti conservati; il nuovo totale va riletto, non dedotto dal solo avvio worker. Nessun reset, restore, nuovo primo grant o accettazione permanente. Fasi 6–8 non raggiunte; CSV 0/6.

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
