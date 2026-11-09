# OUF — MiniPET operativo: SeaweedFS funzionante → E2E ripetibile

**Versione 2.31 — 9 novembre 2026, Europe/Rome.** Owner: Giovanni. Esecuzione: agente principale, sequenziale. Stato: **F1 riuscito sul percorso Onboarding; F2–F6 aperti**.

## 1. Decisione e risultato da ottenere

Giovanni ha precisato la priorità durante questo audit: **far funzionare SeaweedFS, poi rendere ripetibile l'E2E; industrializzare dopo**. Questa decisione sostituisce la precedente sequenza di lavoro orientata alla produzione. DR, RPO/RTO, HA, qualifica estesa, manutenzione del fork e chiusura formale dei gate di produzione sono rinviati. Non sono prerequisiti per la prova funzionale non produttiva.

Due risultati, in quest'ordine:

1. **STORAGE FUNZIONANTE:** OUF scrive e legge realmente su SeaweedFS, usando i propri servizi e riferimenti; il percorso verificato non dipende più da MinIO.
2. **E2E RIPETIBILE:** un CSV passa da chatbot/upload a Onboarding, semantica, Ingestion, riconciliazione e grafo UDP; la procedura riesce di nuovo senza correzioni manuali dei dati o dello storage tra le due esecuzioni.

Giovanni ha fermato il filone parallelo: anche il 403/THS è ora in carico al solo agente principale. Il grant upload admin richiede attributi assenti dal contesto del selettore; il diniego è riprodotto nel valutatore originale. La correzione è pubblicata nella policy :60: il selettore si apre e il primo asset risulta STAGED. Il successivo tentativo Teatri nello stesso link ha dato HTTP_500; il rifiuto del riuso è riprodotto sul codice, ma l'esito della seconda scrittura va riconciliato. [Stato aggiornato](STATE.md). [Evidenza](../evidence/ths-upload-role-diagnosis-20261107.json). Il 502 della prova isolata Onboarding→SeaweedFS è un problema distinto finché una prova non li collega.

Questo MiniPET serve a finire il percorso funzionante. Non dichiara il sistema pronto per la produzione né chiude automaticamente l'intero contratto M2.

## 2. Dove siamo davvero

**Requisito 1024 colonne, caso SUE da 300–400 campi:** primo incremento di codice su Onboarding, MCP, Gateway, Ingestion e UDP. CSV profilato e ingerito senza trattenere tutta la tabella, pagine immutabili da 128 colonne, array di proprietà/segnali e limiti di trasporto/tempo allineati. Una pratica resta un oggetto. Prove native con 1024 colonne riuscite a 384 MiB; non sono misure o installazioni VPS. [Modifiche, rischi e sequenza](OUF_WIDE_OBJECTS_1024_20261107.md) · [Evidenza e CI](../evidence/wide-object-1024-20261107.json).

**Budget proporzionato al lavoro: candidato MCP PR83.** `source.analysis.plan/read/step` collegano il profilo autorevole alle attività, deduplicano le ricerche riusabili e conservano consumi, risposte e avanzamento delle attività per colonna. Il budget cresce con il lavoro pianificato; la finestra a 60/minuto resta separata e produce attesa persistita. La discovery esistente è composta nello stesso ramo. MCP PR83 è installato con migrazione 14 e readiness HTTP 204; i sei nuovi strumenti analisi/discovery restano INACTIVE e nessun mapping live è avvenuto. La ripresa richiede un chiamante autorizzato; non è uno scheduler in background. [Stato, prove e limiti](OUF_SEMANTIC_ANALYSIS_BUDGET_20261107.md).

**Aggiornamento corrente:** F1 PASS; Onboarding e UDP sono collegati a SeaweedFS; gli aggiornamenti applicativi1024 sono distinti dal precedente cambio dei binding. Il produttore token Semantic è stato ripristinato alle 21:07 CET: servizio active/enabled, token montato nuovo, GET policy :61 HTTP200. Le successive chiamate MCP riescono: ricerca `Teatri`, lettura della revisione esatta e preview del profilo. [Ricevuta operatore](../evidence/semantic-operational-owner-active-operator-20261107.json) · [Prova applicativa](../evidence/semantic-recovery-functional-read-20261107.json).

Il profilo contiene 13 righe e 20 colonne. **OPEN acquisito per tutte le colonne.** L'owner richiede proprietà condivise per il significato delle colonne, con URI utili al confronto tra tipi diversi. La [tabella semantica](OUF_TEATRI_COLUMN_SEMANTIC_REFERENCES_20261107.md) distingue due termini schema.org presenti da 18 proprietà locali con dominio PerformingArtsTheater; l'allineamento esterno resta aperto. La connessione MCP non espone la discovery OntoPiA già candidata. L'ultima ricerca Cinema è stata rifiutata per budget con retryable:false, senza ripetizione. Dopo la qualifica e il rilascio del candidato composto PR83 con i servizi corrispondenti: verificare e attivare il percorso governato di discovery, chiudere il mapping e passare a bozza/review THS/Ingestion→UDP→grafo. Non introdurre vocabolari di valori come requisito non richiesto. Nessun nuovo upload, profilo, sorgente o Ingestion inviato. F2–F6, normale operazione lake UDP e rinnovo automatico successivo restano da provare.

Fonti dell'audit iniziale, storiche rispetto all'aggiornamento operativo qui sopra: deploy **6c17d701**, aggiornamenti THS incorporati fino a **74409f14**; Onboarding **d5155899**, UDP **0d40da05**, Ingestion **4165b9e1** e contratto di lettura Gateway **81fdf7a5**. Le ricevute VPS/Windows sono risultati dell'operatore conservati in Git, non nuove osservazioni live dell'auditor. [Registro delle fonti e limiti](../releases/storage-functional-status-20261107.json).

| Fatto nelle fonti dell'audit iniziale (storico) | Cosa significa | Cosa non dimostra |
| --- | --- | --- |
| Copia cifrata su Windows: 6.544.578.724 byte; decifratura e manifest verificati, 53 payload + 3 evidenze [E1] | La conservazione storica esiste: non ripartire da installazione age, scelta PC o prima cattura | Non è una nuova copia dello stato dopo la riapertura |
| PostgreSQL storico riaperto in isolamento: 7 DB, una riga campione per DB; MinIO storico: 120 oggetti/versioni letti [E2, E3] | Le prove sono riusabili per il loro ambito | Non è una verifica integrale di tutte le righe o un E2E |
| Rehearsal OCI33: 120 oggetti, 203.743 byte, 2 bucket; chiavi, corpi, metadati e tag coincidenti [E4] | SeaweedFS ha già conservato e restituito il dataset storico | La ricevuta dichiara 0 oggetti migrati operativamente |
| Due identità S3: due letture del proprio bucket e due dinieghi sull'altro, TLS verificato [E5] | Il collegamento S3 di base ha funzionato | La prova dichiara 0 container applicativi avviati: non è il PUT di Onboarding |
| Onboarding candidato avviato sulle copie, V39–V41 presenti; POST reale isolato terminato 502 [E6] | L'applicazione parte; la scrittura applicativa non è ancora riuscita | Readiness e GET preliminare non valgono come successo upload |
| Readback del primo upload: intento DISPATCHED, nessun ACK/asset, chiave riservata assente [E7] | Il tentativo è conservato e il suo esito osservato è incompleto | Non va trasformato in successo o reinviato alla cieca |
| JFR: indizi di connection refused/loopback IPv6 e timeout, un handshake TLS nella finestra [E8] | Ci sono elementi per una diagnosi mirata del trasporto | Non identifica con certezza la richiesta fallita o la causa del 502 |
| STATE e runbook di avvio riportano stack originale su MinIO e OCI33 su rete privata [E9] | Esistono due backend; manca il cambio applicativo verificato | L'avvio di SeaweedFS non cambia i binding e non sincronizza nuove scritture MinIO |
| 403 THS anche in InPrivate, account ouf-admin confermato [E10] | Blocco dell'ingresso utente, ora seguito dall'agente principale | Non prova un difetto di SeaweedFS |

**Stato corrente:** sono riusciti confronto PUT/GET dei client Onboarding, allineamento dei file, passaggio Onboarding, upload e lettura/profilazione dello stesso asset, e PUT/HEAD/GET del client UDP originale su SeaweedFS. Il collegamento UDP è ora riuscito; restano la sua normale operazione applicativa e il percorso fino al grafo, poi la ripetizione senza riparazioni manuali.

La percentuale **39,78%** del vecchio registro è una stima euristica del 4 novembre basata su crediti di lavoro. Non misura né funzionalità né tempo residuo. Non sarà usata per pianificare o rendicontare questo percorso. I vecchi 0/8 gate e 0/21 AT restano stato della precedente accettazione formale, non una lista da chiudere prima di far funzionare il sistema.

## 3. Cosa ha creato confusione

- **Stati superati presentati come correnti.** Il vecchio MiniPET apre con “backup ancora da catturare”; ricevute successive documentano copia, restore e rehearsal. AGENTS conteneva 1.521 righe di checkpoint, il MiniPET 1.368. Il prossimo passo non deve richiedere di ricostruire tutta la cronologia.
- **Molto lavoro tecnico, pochi esiti applicativi conclusivi.** Sono stati costruiti e provati molti strumenti di cattura, contenimento e recovery; il POST dell'applicazione è ancora fallito. Questo è un giudizio sul percorso osservato, non l'affermazione che tutte quelle prove fossero inutili.
- **Candidato, fixture e servizio installato mescolati.** Il client isolato e l'immagine completa non sono intercambiabili. Onboarding d515 introduce anche V39–V41; non è un semplice cambio endpoint. Prima di modificare va identificata la generazione effettiva usata dal flusso.
- **Branch troppo ampio per un'unica consegna leggibile.** La PR deploy #54 aveva 740 commit e 3.016 file modificati all'inizio dell'audit, ed è cambiata durante la lettura. Il riordino viene proposto su ramo separato; nessun merge o rewrite del ramo operativo.

Da ora: [STATE.md](STATE.md) per il prossimo passo; questo documento per risultato e sequenza; [registro funzionale](../releases/storage-functional-status-20261107.json) per esiti e prove. La cronologia resta in Git e nel log M2, non in testa al piano.

## 4. Roadmap funzionale

**Passo corrente:** Semantic V12 è pronto: [ricevuta delle 19:59 CET](../evidence/semantic-discovery-key-repaired-operator-20261108.json), chiave uguale al firmatario Gateway, singolo parametro corretto, stessa immagine e mount, storia V12 invariata. V10 e V12 fallito restano spenti; non ripetere la correzione. Provider e worker sono ancora disabilitati. Gateway resta a 87 route, otto modifiche e 79 conservate. Il preflight MCP delle20:09 CET è acquisito: schema1–13 esatto, permessi14 e file montati, permesso storico scaduto conservato. L'[installazione MCP+14](OUF_MCP_ANALYSIS_UPGRADE_20261108.md) è completata sul VPS alle 20:26 CET: migrazione ordinaria 14 verificata, storia e file del permesso scaduto invariati, readiness 204, vecchio container spento. [Ricevuta](../evidence/mcp-analysis-ready-operator-20261108.json). Non ripetere l'installer. **Onboarding 1024 è pronto sul VPS alle 21:16 CET:** [ricevuta](../evidence/onboarding-wide-ready-operator-20261108.json), readiness 200, storia V38 e righe Teatri invariate; due reti/IP/MAC/alias, mount/truststore e argomenti Java conservati. Nessun migratore esplicito. Vecchi container spenti, installer da non ripetere. **Ingestion 1024 pronto sul VPS alle 22:48 CET:** [ricevuta](../evidence/ingestion-wide-ready-operator-20261108.json), readiness 200, storia/sei tabelle e pianificazioni conservate, endpoint/mount/ENV/argomenti invariati, vecchio spento. Continuazione completata, non ripetere. Nessuna prova funzionale1024; metadata polling invariati durante il controllo, nessun ciclo periodico VPS dimostrato. **UDP1024 pronto il9novembre06:58CET:** [ricevuta](../evidence/udp-wide-ready-operator-20261109.json), readiness200, storia V36/59 tabelle invariate, due reti/IP/MAC/alias e truststore conservati; vecchio UDP e writer MinIO spenti. Installer completato, non ripetere. Nessuna operazione business/S3 inviata dallo script; l'avvio applicativo può accedere a DB/S3. Prossimo passo: verificare i binding attuali provider/southbound e attivazione strumenti, poi mapping Teatri e Ingestion→UDP. Le prove funzionali1024 e F2–F6 restano aperte.

Le righe sono risultati da chiudere, non promesse di durata né nuovi strumenti da costruire. Stato corrente: **F1 PASS**, **F2–F6 OPEN**.

| ID e ordine | Lavoro concreto | Uscita verificabile | Dipendenza / responsabilità |
| --- | --- | --- | --- |
| **F1 — Un PUT/GET applicativo su SeaweedFS** | **PASS:** stessa immagine, nuovo binding SeaweedFS, upload STAGED e profilo SUCCEEDED, risultato letto via MCP. Riferimenti nell'evidenza del 7 novembre. | Upload riuscito; asset/ricevuta coerenti; se si usa d515, intento ACKED; oggetto presente su SeaweedFS, byte e SHA-256 uguali all'input; lettura tramite il normale percorso applicativo riuscita. | Agente storage + operatore soltanto per accesso VPS. Non dipende dalla chiusura dei gate di produzione. |
| **F2 — Collegare lo stack effettivo** | Applicare i binding coerenti di scrittura e lettura a Onboarding, UDP e percorso Gateway/Ingestion. Conservare bucket/key e URI. Aggiornare i dati rispetto alla riapertura di MinIO, se sono cambiati. | Onboarding e UDP scrivono e leggono da SeaweedFS; i riferimenti preesistenti del dataset scelto si risolvono; configurazioni e prova mostrano che il percorso verificato non usa MinIO. | F1. Agente storage. Coordinare nello stesso filone le modifiche THS alle configurazioni condivise. |
| **F3 — Un CSV arriva al grafo** | Dopo il fix THS, seguire un file lungo upload, profilo, mapping/semantica, review prevista, Ingestion, riconciliazione, persistenza UDP e lettura del grafo. | Una catena di riferimenti collega file/hash → asset → source/version → semantic refs → run/ACK → oggetti/relazioni UDP. Gli esiti di tutte le righe del file sono spiegati. | F2 + esito 403/THS. Filone E2E. |
| **F4 — Ripetere il percorso** | Eseguire lo stesso flusso con un secondo CSV comparabile, attraverso la stessa procedura. Verificare inoltre il reimport invariato secondo il contratto già previsto. | Secondo percorso riuscito senza SQL, copie S3 manuali, cambio policy ad hoc o patch tra i due run; reimport senza duplicati/revisioni gratuite. Decisioni HUMAN previste restano normali passi del prodotto. | F3. Filone E2E. |
| **F5 — Riprendere una conversazione** | Riaprire il lavoro da un'altra chat/sessione e leggere stato e riferimenti persistiti; continuare il passo consentito. | Il lavoro è ritrovato senza ricaricare il file per compensare la perdita di contesto; il chatbot non dipende da ID ricordati solo in chat. | F3; verificabile dopo F4. Filone E2E. |
| **F6 — Consegnare la procedura funzionante** | Salvare una procedura breve, le configurazioni effettive e i risultati F1–F5. | Un solo punto di ingresso con prerequisiti, normali azioni utente e risultati attesi; MinIO non è necessario per il flusso dimostrato. | F1–F5. Agente principale; riscontro funzionale Giovanni. |

**Fine del primo risultato:** F1+F2. **Fine dell'E2E ripetibile qui richiesto:** F3+F4+F5+F6. Non contare un nuovo documento, uno script installato o un container UP come chiusura di una riga.

### F1: percorso applicativo verificato

L'immagine installata `7b9d3e91…`, corrispondente al sorgente conservato `73498c17`, usa SeaweedFS. Il 7 novembre il nuovo upload è STAGED, la profilazione è SUCCEEDED e la preview è stata letta tramite MCP. Il worker legge i byte attraverso Gateway; `ManagedFileService.profile` verifica dimensione e hash contro l'asset registrato prima di salvare il risultato. La preview non espone il valore hash: il controllo è quello applicativo, non un nuovo GET S3 indipendente.

F1 è PASS per il percorso Onboarding osservato. Non ricaricare: asset e profilo sono in [STATE](STATE.md). Nessuna bozza/source Ingestion o scrittura UDP aggiunta da questa prova. Coordinate rilevate come STRING, con campione `4.565.094`: la proposta corrente conserva il testo senza interpretarlo come numero geografico. Il riuso del vecchio selettore e il vecchio tentativo Teatri restano da riconciliare.

La causa del vecchio 502 nella diversa configurazione isolata resta storica e non provata; non blocca il risultato applicativo ora acquisito.

### F2: cambiare tutti i percorsi necessari, una volta sola

Onboarding è già verificato. La [prova UDP delle 18:39 CET](../evidence/udp-seaweedfs-client-success-operator-20261107.json) è PASS: factory e adapter installati, AWS SDK 2.54.17, PUT/HEAD/GET HTTPS, 33 byte, corpo/hash/metadati coincidenti. Le proprietà storage selezionate nel JSON dichiarato sono assenti. Spring non avviato; servizio originale invariato.

**Cambio UDP completato** alle 18:59 CET: [ricevuta](../evidence/udp-seaweedfs-ready-operator-20261107.json) con 110 oggetti/181.364 byte coincidenti, zero copie aggiuntive, sorgente invariata a writer fermo, diagnostico rimosso e zero extra target. Stessa immagine, nuova rete/binding HTTPS, readiness/TLS e 118 certificati JDK conservati più CA. Vecchio container spento. Non ripetere il cambio.

F2 non è ancora PASS: manca la normale operazione applicativa lake. Semantic è avviato e ricerca/lettura della revisione Teatri via MCP riescono dopo il ripristino del produttore token; non occorrono altri tentativi del comando già riuscito. Proseguire dal [mapping del profilo esistente](OUF_TEATRI_SEAWEEDFS_MAPPING_REVIEW_20261107.md). Restano separati il confronto MacAddress sui sostituti running, l'omissione del produttore continuo nell'avviatore generale e la lettura di stato Ingestion priva di grant.

| Percorso | Punto noto nel codice | Verifica minima |
| --- | --- | --- |
| Onboarding, scrittura | `ouf.onboarding.staging.*`; client MinIO dietro `ManagedFileStagingStore`, regione us-east-1 | PUT e GET del file reale su SeaweedFS. Il nome della libreria non impone di usare il server MinIO né di riscrivere subito l'adapter. |
| Onboarding, lettura governata | `ouf.onboarding.object-store.*`; `GatewayManagedFileObjectStore`, capability interna `ouf.object-storage.content.read` | Il file appena scritto è letto e profilato tramite il percorso normale, non soltanto da un tool S3. |
| UDP | `ouf.udp.lake.s3.*`; endpoint/region/path-style e `DefaultCredentialsProvider` | Identità effettiva prevista; scrittura e rilettura del payload, confronto byte/hash. HEAD da solo legge il metadato hash e non verifica il corpo. |
| Ingestion → UDP | Configurazione sorgente, lettura governata, consegna e ACK | La run legge il file, consegna i record e ottiene ACK persistito; nessun nuovo endpoint S3 inventato per Ingestion. |

Scegliere esplicitamente la generazione applicativa da usare. Non aggiornare tutti i moduli al branch più recente per il solo cambio storage. d515 è una candidata con prove disponibili; l'installazione corrente non va identificata dalla sola label del container. Un'eventuale necessità di V39–V41 deve derivare dal percorso scelto, non dalla volontà di chiudere un filone di recovery.

MinIO è stato riavviato dopo la copia storica. Il confronto precedente, fatto con sorgenti ferme, resta valido per quel momento; **non certifica l'uguaglianza attuale**. Durante il cambio non devono esserci scritture concorrenti sui due backend. Usare una pausa circoscritta dei writer e una copia/riconciliazione del dataset corrente; con i 120 oggetti storici non è giustificato costruire prima una migrazione online complessa. Se il dataset è cambiato, si lavora sui conteggi reali nuovi.

Il comando `seaweedfs` esistente avvia un servizio aggregato su rete interna, senza porte pubblicate, con volume separato e restart=no. È un punto di partenza funzionante per la prova; non occorre trasformarlo ora in una topologia HA. I collegamenti dei container Onboarding e UDP sono ora verificati nelle rispettive ricevute di cambio; la sola readiness non sostituisce la prova applicativa UDP ancora aperta.

### F3–F5: che cosa rende l'E2E una prova reale

- Usare un file di prova riconoscibile e conservarne hash e numero di righe. Teatri, Farmacie e Cinema sono fixture; non alterare i risultati storici per far sembrare riuscito un nuovo run.
- Usare prima il Semantic Registry locale; ricorrere alla discovery OntoPiA governata soltanto se il mapping lo richiede. Risoluzione semantica e approvazioni devono essere quelle effettive del flusso.
- Per ogni riga distinguere materializzazione, riconciliazione e review necessaria. Una run con righe sospese non viene descritta come tutta completata.
- Verificare oggetti, proprietà, provenienza e relazioni attese nel grafo attraverso le capability disponibili. Il successo della sola ingestion non è il risultato finale.
- Secondo file e reimport sono prove diverse: il primo dimostra ripetibilità del flusso, il secondo assenza di duplicazione per input invariato. Conservare gli identificativi per confrontarli.
- La prima sequenza completa usa il client attuale. La qualifica estesa su due client indipendenti del contratto M2 è rinviata insieme all'accettazione completa, non dichiarata soddisfatta da questi due run.

## 5. Regole pratiche per non ricreare il problema

1. **Un risultato alla volta.** Nel filone storage si lavora su F1 finché è riuscito o ha un blocco identificato. Il 403 è ora nello stesso filone: preservare l'esito pubblicato e risolvere il riuso del selettore senza confonderlo con la prova storage.
2. **Una diagnosi deve scegliere il prossimo intervento.** Prima di un'altra prova scrivere ipotesi, osservazione che la distingue e correzione possibile. Se non distingue nulla, non eseguirla. Dopo due iterazioni senza nuova informazione, riesaminare configurazione e approccio invece di aggiungere strumenti.
3. **Riuso delle prove.** Non rifare cifratura, restore storico, confronto dei 120 oggetti o test già superati se input e codice interessati non sono cambiati. Ripetere solo la verifica resa necessaria da una modifica o dall'avanzamento dei dati.
4. **Stato compatto.** Ogni aggiornamento riporta risultato funzionale, errore attuale, prova e prossimo passo. Niente percentuali, contatori di test come progresso o checkpoint impilati in AGENTS.
5. **Nessuna scorciatoia sui dati.** Niente cancellazione degli originali, proprietà/tenant inventati, SQL per fingere ACK, disabilitazione TLS o privilegi globali per ottenere un verde. Queste sono condizioni per un funzionamento corretto, non un programma di industrializzazione.
6. **Modifiche piccole e riferimenti esatti.** Separare correzione del difetto, binding e documentazione. Ricontrollare HEAD prima di scrivere; il ramo operativo è in uso. Non rigiocare istruzioni storiche o comandi già consumati.
7. **Autorizzazioni già date restano acquisite.** Non chiedere nuovi consensi generici per sviluppo o diagnosi autorizzati. Se serve un effetto non coperto, preparare il cambiamento concreto e chiedere soltanto quella decisione. Il piano non crea grant IAM né approva azioni HUMAN di dominio.

## 6. Lavoro esplicitamente rinviato

DR e RPO/RTO; HA e perdita host; prove estese di crash/compaction; prestazioni e dimensionamento produttivo; rotazione completa; revisione licenze/manutenzione di tutte le dipendenze; custodia della release oltre CI; osservazione di 48 ore; ritiro definitivo/distruzione di MinIO; accettazione formale SW-G0…G7/SW-AT01…21 e M2 completa.

Il lock OCI33 riporta 33 patch, scansione storica PASS_RAW, manutenzione dipendenze e revisione licenze ancora OPEN. Lo si conserva come fatto; **non apre ora un nuovo filone di hardening**. La manutenzione del candidato andrà affrontata dopo il percorso funzionante. Un errore concreto che impedisce F1/F2 resta invece nel lavoro immediato.

I dieci asset legacy senza proprietà provata e le altre classificazioni G0 non vengono “riparati” per migrare. Conservare dati e prove; intervenire sul singolo caso soltanto se impedisce il file/percorso che stiamo facendo funzionare, attraverso il contratto dell'owner.

## 7. Tempi, limiti e consegna

Non c'è una data di fine attendibile: F1 è provato, entrambi i servizi sono collegati a SeaweedFS e Semantic è avviato, e la ricerca Semantic riesce; restano la normale operazione lake UDP e il percorso fino al grafo con ripetizione. Il riuso del selettore richiede correzione e riconciliazione. Si aggiorna la previsione dopo la prima operazione applicativa UDP; la ricerca semantica è riuscita.

Dopo F1 si stima F2 sulla configurazione realmente corretta; dopo il primo E2E si misurano i tempi del secondo. Ogni blocco di lavoro deve produrre una correzione verificata, una prova funzionale o un impedimento preciso con l'azione necessaria. Se serve un'azione sul VPS, consegnare il solo comando attuale e il risultato richiesto, non una serie di preparazioni speculative.

**Limiti di questo audit:** lettura dei documenti correnti, ricevute selezionate, contratti e punti di codice direttamente coinvolti; non review esaustiva dei 3.016 file della PR, non nuova esecuzione VPS, non nuova suite runtime, non nuova scansione del candidato. I metadata CI verificano esiti storici di workflow, non l'attuale salute dell'installazione. Nessun difetto di trasporto è dichiarato risolto.

## Fonti essenziali

I riferimenti sono letti sullo snapshot dell'audit; il registro JSON conserva commit e percorsi esatti.

- **E1:** [custodia Windows](../evidence/storage-retained-custody-windows-verified-operator-20261107.json).
- **E2–E3:** [restore PostgreSQL](../evidence/storage-historical-postgres-restored-operator-20261107.json), [restore MinIO](../evidence/storage-historical-minio-restored-operator-20261107.json).
- **E4:** [parità OCI33](../evidence/storage-retained-oci33-rehearsal-parity-operator-20261107.json).
- **E5:** [letture e isolamento S3](../evidence/storage-oci33-app-bindings-ready-operator-20261107.json).
- **E6–E8:** [upload 502](../evidence/storage-oci33-onboarding-upload-http502-held-operator-20261107.json), [readback](../evidence/storage-oci33-onboarding-upload-readback-operator-20261107.json), [JFR](../evidence/storage-oci33-onboarding-upload-jfr-window-operator-20261107.json).
- **E9:** [avvio stack e SeaweedFS](OUF_RUNTIME_RESTART_20261107.md), [codice avvio](../scripts/ouf-runtime-20261107.py), [confronto sorgenti prima della riapertura](../evidence/storage-retained-source-comparison-match-operator-20261107.json).
- **E10:** [checkpoint THS](OUF_M2_CHECKPOINT_LOG.md), [stato corrente](STATE.md).
- [Coorte candidata e delta Onboarding](OUF_STORAGE_COHORT_DECISION_20261106.md), [lock OCI33](../releases/seaweedfs-452-generation33-candidate-lock-20261104.json), [classificazione G0](OUF_STORAGE_G0_FINDINGS_DISPOSITION_20261106.md).
- [Contratto storage precedente, snapshot immutabile](https://github.com/GioNob/ouf-deploy/blob/6c17d701221322ad8d5c8284254a6aa1eb0d727f/docs/OUF_MINIO_SEAWEEDFS_MINIPET_v1_0_20261102.md), [MiniPET M2](OUF_M2_MINIPET.md), [baseline PET/Matrix](baseline/v1.7/README.md), [policy resilienza](OUF_RESILIENCE_POLICY.md).


