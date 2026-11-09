# OUF 2 — istruzioni operative

## Produttore token Semantic — aggiornamento del 7 novembre 2026

Il servizio continuo `ouf-registry-token-7cb59501000058b5dc5030ad.service` è **ripristinato**: [ricevuta delle 21:07 CET](evidence/semantic-operational-owner-active-operator-20261107.json), active/running/enabled, nuovo token montato e GET policy :61 HTTP200. Esatto override di cattura conservato e rimosso, altri drop-in invariati. Non ripetere il ripristino già riuscito. Il legacy `ouf-policy-token@semantic.service/.timer` resta masked.

Le successive [chiamate MCP](evidence/semantic-recovery-functional-read-20261107.json) di ricerca e lettura della revisione Teatri riescono. `teatro`/`Theatre` danno liste vuote; `Teatri` restituisce l'ontologia ACTIVE e la lettura esatta 105 statement completi. Non dedurre assenza di semantica da una singola ricerca vuota. Il ciclo automatico successivo e l'integrazione del produttore nell'avviatore generale restano da verificare.

Le diagnosi HELD sono storiche: GetUnit può non trovare l'unità inattiva non caricata. La v3 eseguita verifica main fragment/all drop-in e NeedDaemonReload=no, senza dedurre array vuoti dai campi omessi né usare D-Bus diretto. [Runbook](docs/OUF_SEMANTIC_TOKEN_RENEWAL_20261107.md).

Riprendere da asset/profilo e [mapping](docs/OUF_TEATRI_SEAWEEDFS_MAPPING_REVIEW_20261107.md), senza nuovo upload/profilazione. **OPEN per tutte le 20 colonne è acquisito.** L'owner chiede proprietà condivise identificate da URI per il significato delle colonne, non enumerazioni dei valori: [analisi per colonna](docs/OUF_TEATRI_COLUMN_SEMANTIC_REFERENCES_20261107.md). I 18 termini locali con dominio PerformingArtsTheater non sono automaticamente riusabili su tipi diversi. Discovery esterna non esposta nella connessione; candidati già esistenti da riconciliare col runtime, senza URI inventati o sostituzione con web research. L'ultima ricerca Cinema è stata rifiutata per orchestration budget exhausted/retryable:false: non ripeterla alla cieca o resettare il budget. La review HUMAN della futura sorgente resta distinta dall'analisi.

## Oggetti ampi e budget semantico — decisione corrente

Limite richiesto **1024 colonne**, per pratiche SUE da 300–400 campi: [modifiche, rischi e prove](docs/OUF_WIDE_OBJECTS_1024_20261107.md), [stato CI](evidence/wide-object-1024-20261107.json). Gateway applicato, Semantic V12, MCP PR83/schema14, Onboarding1024, Ingestion1024 e UDP1024 sono installati e pronti secondo le rispettive ricevute. UDP completato il9novembre06:58CET: nuovoCID ab8549a9, readiness200, V36/59 tabelle invariate, due reti/IP/MAC/alias e storage/truststore preservati, vecchi writer spenti. [Ricevuta](evidence/udp-wide-ready-operator-20261109.json). Non ripetere gli installer completati o il preflight UDP. La lettura delle 07:24 CET conferma provider v2 e southbound v2 exited, reti condivise presenti, Semantic senza mount credenziale. Legacy created/scollegato, da mantenere fermo. [Controllo di avvio v2 concluso alle 07:51 CET](docs/OUF_DISCOVERY_STARTUP_READ_20261109.md): credenziale/truststore preparati coerenti, certificati validi per data/nome; TLS/issuer non provati. Runtime v4, adapter DELETED/southbound DELETING: conservare i journal, riconciliare task/handle e qualificare nuova generazione. Nessun avviatore VPS corrente pronto; non riusare vecchi claim. Il segnaposto southbound è stato rimosso alle 09:06 CET, con journal e frame conservati. La quiescenza delle 09:31 CET è HELD per NFT_INSTALLATION_STRUCTURE_DRIFT, prima di intento o scritture. Non rilanciare la rimozione o la quiescenza. Prossimo passo: [confronto mirato delle impronte nft](docs/OUF_DISCOVERY_NFT_DRIFT_READ_20261109.md), in sola lettura. Non ignorare handle/metainfo o sostituire l'impronta attesa per ammettere il risultato: la causa sul VPS non è ancora provata. Nuova ammissione/avvio provider ancora da qualificare. I sei strumenti restano INACTIVE nell'immagine MCP installata; PR84 ha qualificato build/immagine ACTIVE (225e625a, CI42578075516 PASS), senza installazione. Restano dipendenze e grant. Non riscrivere il catalogo DB o il permesso di reprocessing scaduto per simulare l'attivazione. Il confronto MAC resta API1.44 omogeneo, senza esclusioni globali. Readiness e test CI non provano ingestione funzionale1024 o E2E. La pratica resta un oggetto; le pagine da 128 riguardano solo lo schema. Preservare le correzioni CSV di memoria, i campi fino all'ultimo e il rifiuto della 1025ª colonna. Non ripartire dal solo cambio 256→1024.

Il candidato MCP PR83 compone discovery e analisi `plan/read/step`: profilo verificato→attività uniche→consumo/progresso persistiti, con attesa e ripresa. Budget dal lavoro effettivamente pianificato, non da coefficienti inventati per colonna; la finestra di PR82 protegge solo il ritmo. [Stato e limiti](docs/OUF_SEMANTIC_ANALYSIS_BUDGET_20261107.md). Il pacchetto MCP PR83 è installato: migrazione 14 verificata e readiness HTTP 204, [ricevuta](evidence/mcp-analysis-ready-operator-20261108.json). I nuovi strumenti restano INACTIVE e l'analisi funzionale non è ancora provata. Completamento delle chiamate pianificate non significa mapping o discovery conclusi. Non riaprire l'implementazione da zero o presentare la sola quota fissa come soluzione finale. OPEN è acquisito per Teatri, non automaticamente per dati SUE. Nessun nuovo upload/reprofilazione dei dati reali per ripetere i test di codice.

## Priorità corrente dell'owner — 7 novembre 2026

Far funzionare SeaweedFS, poi rendere ripetibile l'E2E CSV fino al grafo UDP. Industrializzazione, DR, RPO/RTO e chiusura formale dei gate di produzione sono rinviati: non usarli come prerequisiti della prova funzionale non produttiva.

Giovanni ha fermato il filone parallelo e affidato anche il 403/THS al solo agente principale. La correzione del grant upload è pubblicata nella policy :60; il selettore si apre e il primo handoff è STAGED. Il riuso dello stesso link per un altro file ha dato HTTP_500: preservare la prima ricevuta e riconciliare il secondo esito prima di ripetere. Il 502 della prova isolata Onboarding→SeaweedFS è distinto finché una prova non li collega.

## Regola MAC da consultare prima di modificare i container

Prima di creare/sostituire container o confrontare `Config`/`NetworkSettings`, leggere [la regola permanente MAC](docs/OUF_LEARNED_CONTAINER_MAC_INVARIANTS.md) e il [precedente del 25 ottobre](docs/handoffs/OUF_ACQUISITION_MAC_LESSON_AND_RETAINED_STATE_20261025.md). Distinguere `Config.MacAddress` legacy dagli endpoint per rete. La primitiva `tools/acquisition_read_native/retained_mac.py` copre soltanto il vecchio container dopo STOP/DETACH provati: non usarla per ammettere automaticamente differenze sui sostituti running. Vietate esclusioni globali del campo o riscritture delle impronte. Per un caso diverso riportare presenza/tipo del campo prima e dopo, corrispondenza con gli endpoint e fase del lifecycle; qualificare quel profilo prima di modificare il guard. Non riscoprire il problema come se il precedente non esistesse.

## Da leggere per riprendere

1. [Stato corrente](docs/STATE.md): blocco e prossima azione.
2. [MiniPET funzionale SeaweedFS → E2E](docs/OUF_STORAGE_MINIPET.md): risultati F1–F6 e criteri di riuscita.
3. [Registro funzionale e fonti](releases/storage-functional-status-20261107.json): fatti, limiti e stato delle prove.
4. [MiniPET M2](docs/OUF_M2_MINIPET.md), [PET/Matrix](docs/baseline/v1.7/README.md) e [policy di resilienza](docs/OUF_RESILIENCE_POLICY.md) per i contratti coinvolti. Non riaprire tutti i filoni di accettazione per correggere un binding.

## Come lavorare

- Agente principale, esecuzione sequenziale, senza subagenti o automazioni operative. Procedere con il lavoro autorizzato, aggiornando Giovanni su risultati e blocchi concreti.
- Non inventare cause, risultati, stati live, percentuali o scadenze. Separare codice, prove isolate, ricevute operatore e osservazioni attuali.
- Completare un percorso applicativo; non costruire nuove infrastrutture di test se non risolvono un difetto concreto. Riutilizzare le prove già valide.
- Non cambiare dati o proprietà per fingere successo. Conservare ID, URI, hash, lineage e decisioni HUMAN; niente bypass TLS/IAM o credenziali nei report.
- Non rigiocare claim/comandi consumati, resettare budget o cancellare parziali. Le autorizzazioni già espresse restano acquisite nel loro perimetro; non richiedere consensi generici ripetuti.
- Le vecchie dichiarazioni “tutti fermi” sono osservazioni storiche: stack MinIO e SeaweedFS risultano successivamente riavviati. Prima del cambio verificare i dati correnti e impedire scritture sui due backend contemporaneamente.
- Controllare HEAD e lavoro concorrente prima di scrivere. Per il 403/THS preservare i risultati del filone fermato e seguire lo stato corrente. Nessun merge o effetto runtime è attestato dal solo aggiornamento documentale.
- Aggiornare STATE e il registro funzionale; aggiungere gli eventi nel log, senza impilarli in questo file.

## Storico conservato

Il precedente AGENTS di 1.521 righe è [conservato integralmente nello snapshot Git](https://github.com/GioNob/ouf-deploy/blob/6c17d701221322ad8d5c8284254a6aa1eb0d727f/AGENTS.md). È cronologia delle singole operazioni, non una lista di comandi da rieseguire. Le ricevute originarie e i source-lock restano nei rispettivi percorsi.



