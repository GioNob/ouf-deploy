# Roadmap CSV/chatbot: 8 macrofasi tecniche e 6 tappe funzionali

Roadmap confermata dall'utente il 16 ottobre 2026. Numerazione stabile fino alla conclusione; non confondere queste macrofasi con i nomi interni del launcher. Aggiornare questo documento a ogni avanzamento o nuova evidenza. Negli aggiornamenti all'utente indicare fase tecnica N/8, stato, ostacolo, prossimo controllo e tappe funzionali completate N/6. Nessuna promessa sul numero di tentativi.

## Stato corrente

**Fase tecnica 2/8 sospesa; dimostrazione funzionale 0/6.**

Analisi successiva: la CI `38837043139`, sorgente `adaa828255be7437a06b405db759c891343cd6a0`, ha riprodotto il difetto con l'immagine MCP originale su Docker 29.8.1/containerd. Differiscono solo `Config.Env` e `Config.Labels`: Docker incorpora i default dell'immagine, il predicato runtime confronta invece la sola richiesta. ID immagine, rete, utente, comando, entrypoint, mount e campi host controllati coincidono. Questo identifica un difetto del predicato, ma non certifica lo stato corrente sul VPS. Il reader di fase 2 è qualificato con 8 test e query SELECT su PostgreSQL 17 reale; prossimo intervento: leggere lo stato target con `scripts/launch-chatbot-mcp-migration-state-20261016.sh`. Non rilanciare il delivery.

| # | Fase tecnica | Stato |
|---|---|---|
| 1 | Riconciliare il backup interrotto e completare i backup dei quattro database | COMPLETATA: quattro archivi COMPLETE, hash e journal verificati sul VPS; nessun nuovo dump nella ripresa |
| 2 | Applicare le migrazioni MCP e verificare la revoca dei privilegi temporanei | **Sospesa: MCP_MIGRATION_ROLE_NATIVE_IDENTITY_DRIFT** |
| 3 | Sostituire UDP e verificarne schema e avvio | Da eseguire |
| 4 | Sostituire Onboarding e verificarne schema e avvio | Da eseguire |
| 5 | Pubblicare e verificare le route Gateway | Da eseguire |
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

## Ultima conferma VPS (16 ottobre 2026, 03:56 Europe/Rome)

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

Il traceback raggiunge `databases.migrate_mcp`, riga 668, nella verifica native dopo create e prima di start. Il flusso ha già completato `backup_quiesced()` e verificato nuovamente l'archivio MCP prima del punto fallito: questo sostiene il superamento della fase 1. Occorre ancora leggere archivi, journal e stato nativo correnti per confermare gli effetti persistiti. Non dichiarare già applicate le migrazioni o revocati i privilegi: la preparazione del ruolo audit precede il create e può avere lasciato privilegi temporanei.

Cinque grant erano consumati prima della nuova sessione; il totale successivo è sconosciuto finché non viene riletto. Il messaggio finale è `FINITE_DELIVERY_PROCESS_STOPPED_INSPECT_RETAINED_STATUS`, con autorità emessa. Nessuna prova end-to-end e nessuna accettazione permanente.

## Regole di prosecuzione

- Prima riconciliare con letture bounded, redatte e vincolate al contesto esatto; conservare claim, archivi, journal, conteggi e storia.
- Non ripetere il launcher già consumato, create/start ambigui o le dieci fasi Registry; non sostituire i backup né ripristinare il DB precedente.
- Non azzerare budget o estendere l'autorità. Una diversa ripresa richiede revisione governata concreta; delega allo sviluppo non equivale ad autorità runtime HUMAN.
- Correggere il contratto di identità solo sulla base dell'immagine e della richiesta verificate, mai consentendo genericamente differenze o variabili aggiuntive.
- Qualificare il comportamento Docker reale rilevante oltre ai test con engine simulato. Documentare separatamente prova CI, prova VPS e parti ancora non verificate.
- Proseguire autonomamente su codice/analisi/CI; fermarsi quando occorre l'intervento dell'utente sul VPS. Tenere l'utente aggiornato durante il lavoro.

Riferimenti: `AGENTS.md`, `docs/OUF_RESILIENCE_POLICY.md`, `releases/CHATBOT_RUNNING_ROOTFS_RECOVERY_20261016.md`.
