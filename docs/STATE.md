# Stato corrente OUF

Aggiornato l'**8 novembre 2026**, Europe/Rome. Priorità: **SeaweedFS funzionante, poi E2E ripetibile; industrializzazione dopo**. Esecuzione sequenziale del solo agente principale.

## Risultato corrente

**F1 PASS. Onboarding e UDP collegati a SeaweedFS. Il produttore del token Semantic è ripristinato: servizio active/enabled, nuovo token montato e GET policy :61 HTTP 200. Le successive chiamate MCP di ricerca e lettura della revisione Teatri riescono. F2–F6 restano aperti.**

- **Upload e lettura riusciti:** handoff `2de7b988-da47-4231-8443-0e5043214c42` → asset `c51745c5-1fc0-4d36-bdcf-1e9a8a049c94` STAGED → job `f460d4d5-c6f7-4b65-b305-08091e9849cf` SUCCEEDED → profilo `da3f17a2-5cbc-4d7d-9ed8-7f4b39a00342`. CSV UTF-8, separatore `;`, 13 righe e 20 colonne. Preview riletta dopo il ripristino Semantic. Il codice installato controlla dimensione/hash prima di salvare il profilo; il valore hash non è esposto dalla preview. [Evidenza F1](../evidence/onboarding-seaweedfs-profile-success-20261107.json).
- **Policy :61 già pubblicata e verificata:** nessun nuovo permesso modificato per recuperare Semantic. Proposta `66ecf0fb-04e8-476b-9ce5-4fdc1dd496fa` PUBLISHED. Il GET host del ripristino legge proprio la :61; la versione caricata in memoria dalla JVM non è letta direttamente.
- **Semantic applicativo riuscito:** `semantic.search(q=teatro)` e `q=Theatre` restituiscono liste vuote; `q=Teatri` restituisce l'ontologia ACTIVE 1.0.0. `semantic.get` con revisione e publication set esatti restituisce lo snapshot completo di 105 statement. Il precedente 403 non si presenta in queste chiamate. [Evidenza MCP](../evidence/semantic-recovery-functional-read-20261107.json).

## Prossimo passo concreto

**Requisito 1024 colonne, caso SUE da 300–400 campi:** primo incremento di codice su Onboarding, MCP, Gateway, Ingestion e UDP. CSV profilato e ingerito senza trattenere tutta la tabella, pagine immutabili da 128 colonne, array di proprietà/segnali e limiti di trasporto/tempo allineati. Una pratica resta un oggetto. Prove native con 1024 colonne riuscite a 384 MiB; non sono misure o installazioni VPS. [Modifiche, rischi e sequenza](OUF_WIDE_OBJECTS_1024_20261107.md) · [Evidenza e CI](../evidence/wide-object-1024-20261107.json).

**Budget proporzionato al lavoro: candidato MCP PR83.** `source.analysis.plan/read/step` collegano il profilo autorevole alle attività, deduplicano le ricerche riusabili e conservano consumi, risposte e avanzamento delle attività per colonna. Il budget cresce con il lavoro pianificato; la finestra a 60/minuto resta separata e produce attesa persistita. La discovery esistente è composta nello stesso ramo. I sei nuovi strumenti analisi/discovery restano INACTIVE, nessun rollout o mapping live è avvenuto. La ripresa richiede un chiamante autorizzato; non è uno scheduler in background. [Stato, prove e limiti](OUF_SEMANTIC_ANALYSIS_BUDGET_20261107.md).

**Scelta OPEN acquisita per tutte le 20 colonne.** L'owner richiede l'associazione delle colonne a proprietà semantiche condivise (URI stabili) per confronti tra oggetti diversi; non chiede vocabolari per enumerare i valori. [Tabella completa delle 20 colonne](OUF_TEATRI_COLUMN_SEMANTIC_REFERENCES_20261107.md).

La nuova lettura MCP della revisione Teatri conferma 105 statement: due termini schema.org (`name` e il candidato `additionalType`), 18 proprietà locali con dominio PerformingArtsTheater e range string. La presenza di una proprietà locale non chiude la scelta di un riferimento generale. Le ricerche per `nome`, `indirizzo` e `coordinate` sono vuote; non dimostrano assenza dei termini dentro gli snapshot.

**Inventario VPS acquisito alle 09:11 CET dell'8 novembre:** sette immagini coincidono con quelle trattenute; Onboarding/UDP conservano Config, mount, reti e dichiarazioni SeaweedFS, vecchi writer spenti. Registry conserva l'immagine trattenuta, ma la sua corrispondenza al candidato più recente non è provata; provider e worker sono dichiarati `false`. MCP è ancora la vecchia immagine. [Ricevuta](../evidence/analysis-discovery-runtime-operator-20261108.json).

**Dipendenze lette alle 09:31 CET:** MCP ha migrazioni 1–13 esatte; manca la 14 e le tabelle analisi non sono presenti. APISIX ha 84 route: create ancora a 256 campi, review a 32 segnali, tre route discovery assenti. La credenziale provider non ha mount dichiarato. La lettura Semantic DB è fallita: causa e backlog non noti. [Sintesi della ricevuta operatore](../evidence/discovery-contract-operator-summary-20261108.json). L'assenza dei path provider in questo APISIX non prova la loro assenza sul distinto gateway southbound.

**Gateway applicato alle 17:56 CET:** otto PUT riuscite e rilette; cinque aggiornamenti, tre aggiunte, 87 route totali e 79 conservate. Owner e container invariati. [Ricevuta](../evidence/gateway-analysis-applied-operator-20261108.json). Non ripetere il comando Gateway.

**Semantic DB acquisito:** OID21558, storia Flyway riuscita fino a V10, `recovery_state` assente, nessuna richiesta discovery al momento della lettura. I dieci checksum coincidono con il prefisso del sorgente candidato. Rispetto al candidato mancano V11/V12 nel database; la compatibilità dell'applicazione installata deve ancora essere riconciliata.

**Migrazione fermata alle 18:16 CET prima degli effetti:** `INSTALLED_MIGRATIONS_DIFFER_FROM_SOURCE`, zero sessioni DB/Java/migrazioni. [Ricevuta](../evidence/semantic-v11-v12-held-operator-20261108.json). Il source-lock del candidato dichiara che la presenza dei suoi artefatti nel runtime non è provata. L'assistente aveva indebitamente usato l'uguaglianza dell'immagine con quella trattenuta per attribuirle quel sorgente: affermazione ritirata. Le prove su JAR ricostruito non attestavano il JAR installato.

**Prossima azione operatore: [leggere il package Semantic installato](OUF_SEMANTIC_INSTALLED_PACKAGE_READ_20261108.md).** Hash/elenco SQL, differenze dal candidato, librerie e classi discovery selezionate, YAML/manifest e dichiarazioni Flyway. Due GET Docker, nessun Java/SQL/provider o modifica runtime. Sei test del lettore riusciti, zero skip. Prima riconciliare applicazione e schema: non ripetere il migratore né eliminare la directory del tentativo. Gateway applicato e F1 restano acquisiti.

**Impedimento funzionale:** la connessione non espone discovery.request/status/candidates per OntoPiA/schema.gov.it. MCP PR83 compone discovery, 1024 colonne e analisi persistente, ma resta da installare/attivare con contratti compatibili e grant verificati. Route e migrazioni MCP sono ora lette; schema/backlog Semantic sono ora letti (V10, richieste vuote); restano migrazioni V11/V12, binding/trasporto effettivo del provider e grant. Conservare file/SeaweedFS; non inventare URI o sostituire la richiesta con ricerca web/import manuali.

L'ultima ricerca `Cinema` ha risposto `orchestration budget exhausted`, `retryable:false`: esito conservato, nessun retry, reset o cambio account. [Evidenza](../evidence/teatri-column-semantic-reference-review-20261107.json).

Il [payload OPEN](../releases/TEATRI_SEAWEEDFS_MAPPING_REVIEW_20261107.json) è aggiornato come proposta di lavoro; mantiene temporaneamente i riferimenti precedenti e **non è ancora la scelta finale dei termini condivisi**. Nessuna bozza applicativa o Ingestion inviata. Dopo il mapping: bozza idempotente, review THS, Ingestion→UDP→grafo e normale operazione lake su SeaweedFS.

Non ricaricare o riprofilare, non ripubblicare Teatri e non riavviare il produttore token già ripristinato. La sorgente storica `teatri-csv-6609b245` è invariata; la proposta riguarda `teatri-seaweedfs-c51745c5`. Coordinate originali conservate senza conversioni.

## Ripristino Semantic acquisito

[Ricevuta operatore delle 21:07:05 CET](../evidence/semantic-operational-owner-active-operator-20261107.json): rimosso solo l'esatto override di cattura, conservato nel backup privato; altri drop-in invariati. Un avvio del servizio `ouf-registry-token-7cb59501000058b5dc5030ad.service`, ora active/running/enabled, Restart=on-failure. Pubblicazioni 6468→6469, registro ACTIVE, token montato cambiato, GET policy200. Applicazione Semantic invariata; zero cambi di permessi, zero SQL/S3/richieste business emesse dallo script.

Le unità legacy `ouf-policy-token@semantic.service/.timer` restano masked. Le precedenti diagnosi HELD sono storiche. Il [runbook](OUF_SEMANTIC_TOKEN_RENEWAL_20261107.md) conserva il comando eseguito, non una nuova azione da ripetere. Un secondo ciclo di rinnovo automatico non è ancora dimostrato.

## Binding storage acquisiti

| Servizio | Risultato documentato | Limite |
| --- | --- | --- |
| Onboarding | Stessa immagine `7b9d3e91…`, endpoint `https://ouf-seaweedfs-stage:9002`, bucket `ouf-managed-files`. 12 oggetti/40.709 byte coincidenti a writer fermo; readiness/TLS, 118 certificati JDK più CA. Vecchio container conservato spento. Upload/profilazione applicativi riusciti. | Non riavviare il vecchio writer MinIO dopo le nuove scritture. |
| UDP | Stessa immagine `ae78f604…`, stesso endpoint HTTPS, bucket `ouf-udp`. 110 oggetti/181.364 byte coincidenti a writer fermo; zero copie/sovrascritture; diagnostico rimosso; readiness/TLS e certificati verificati. Vecchio container spento. | `applicationHttpLakeOperationTested=false`: la normale operazione lake resta da provare. |

[Ricevuta Onboarding](../evidence/onboarding-seaweedfs-ready-operator-20261107.json) · [Ricevuta UDP](../evidence/udp-seaweedfs-ready-operator-20261107.json). I confronti curl/Java Onboarding e PUT/HEAD/GET dell'adapter UDP originale hanno avuto successo nei rispettivi ambiti: non ripeterli. La causa del vecchio 502 in una diversa configurazione resta non provata.

## Problemi ancora aperti

- **Riavvio generale e MAC:** [regola permanente](OUF_LEARNED_CONTAINER_MAC_INVARIANTS.md). Nella ricevuta dell'8 novembre Onboarding/UDP non differiscono più dalla cattura dei sostituti, compreso il campo legacy. Negli altri cinque servizi l'unico delta Config è ABSENT→STRING, unicast nonzero e coerente con un endpoint; anche NetworkSettings differisce dalla cattura. Questi due snapshot non autorizzano a normalizzare il lifecycle. Nessuna impronta riscritta. Il vecchio avviatore generale può ancora fermarsi e omette il produttore continuo Semantic ripristinato: non rieseguirlo come scorciatoia.
- **F2–F6:** normale operazione lake UDP, nuovo CSV fino al grafo, seconda esecuzione e ripresa da altra sessione. Il blocco della ricerca Semantic è superato per le chiamate osservate; nessun E2E completo dichiarato.
- **Stato Ingestion:** `ouf.ingestion.status(limit=10)` era negato; nessun grant di quella capability nel catalogo letto. Lettura non ripetuta né permessi ampliati per aggirarla.
- **Riuso vecchio selettore Farmacie→Teatri:** HTTP_500, handoff `1d3c1a27-5a57-4e81-bbbc-2f6bc606c6ce` conserva asset `8061fad3-1a8b-4f65-9e4a-bfead7974cb7`. Rifiuto di riassociare il medesimo handoff riprodotto sul codice; manca l'eccezione live e resta da riconciliare la possibile seconda persistenza. Nessuna cancellazione. [Evidenza](../evidence/ths-upload-reuse-storage-next-20261107.json).

Non distribuire il vecchio commit diagnostico Onboarding `380e8dcb`: parte 20 commit prima del sorgente conservato `73498c17` e la build è fallita a Trivy. Conservare l'installazione funzionante. MCP HEALTHY non dimostra l'E2E.

## Riferimenti operativi

[MiniPET funzionale](OUF_STORAGE_MINIPET.md) · [Registro funzionale](../releases/storage-functional-status-20261107.json) · [Log cronologico](OUF_M2_CHECKPOINT_LOG.md). Non dichiarare produzione pronta o E2E concluso.
