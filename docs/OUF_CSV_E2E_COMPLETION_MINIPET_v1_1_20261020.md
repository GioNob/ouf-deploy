> Chiarimento vincolante dell’owner — 29 ottobre 2026: il flusso è **CSV → lavorazione governata → oggetti UDP**. Search non è una fase del caricamento. Le capabilities UDP devono essere utilizzabili via chatbot sugli oggetti caricati; la loro qualifica è distinta dalla sequenza di ingestion. La discovery semantica del Registry rimane nel mapping governato. I requisiti/test di consultazione rimangono tracciati come qualifica delle capabilities, senza aggiungere uno step search al flusso.

# OUF — Mini-PET per il completamento del percorso CSV end-to-end

**Identificativo:** OUF-MP-CSV-E2E  
**Versione:** 1.1 · 20 ottobre 2026 · Europe/Rome  
**Stato:** piano esecutivo per l'avvio del miniprogetto; nessuna autorità runtime conferita  
**Responsabile di accettazione:** owner del progetto / HUMAN autorizzato  
**Esecuzione tecnica:** agent principale, lavoro sequenziale, senza subagenti né automazioni operative  
**Stato iniziale:** tecniche 8/8; funzionali 4/6  
**Effort residuo stimato:** 18–30 ore assistite per il caso conservato; 40–70 ore complessive per il percorso CSV generale

Questo documento è la base operativa del miniprogetto. Specifica il risultato, i delta da implementare, l'ordine delle attività, gli input necessari e le prove con cui dichiarare concluso il percorso. La [riesamina dei repository](CSV_REPOSITORY_REAUDIT_AND_EFFORT_20261020.md) è la motivazione della stima e del riuso. Il [registro strutturato](../releases/csv-e2e-completion-plan-20261020.json) contiene work package, dipendenze, effort e casi di accettazione. Non è un launcher.

**Novità della versione 1.1:** cronoprogramma in ore cumulative nei §§15.1–15.7, con 30 attività, scenario centrale da 55 ore e punti di disponibilità HUMAN. La [versione 1.0](OUF_CSV_E2E_COMPLETION_MINIPET_v1_0_20261020.md) rimane lo storico del piano iniziale; questa versione è il riferimento corrente.

## 1. Obiettivo e traguardi

Un utente autorizzato deve poter partire dalla chat, acquisire un CSV, definirne il significato, completare l'onboarding governato, seguire l'ingestion, riconciliare le righe con gli oggetti già presenti in UDP e verificare l'esito persistito. Il percorso ordinario deve funzionare senza terminale, SQL, accesso al VPS o ricostruzione manuale di identificatori.

Le decisioni HUMAN restano nel **Trusted Approval Workspace della THS**; la chat prepara, accompagna e recupera gli esiti. Il collegamento a THS e il ritorno alla chat fanno parte dello stesso percorso, senza delegare all'agent approvazione o attivazione.

| Traguardo | Risultato | Condizione di completamento |
| --- | --- | --- |
| M1 — Caso conservato | Pubblicazione nativa del profilo e chiusura F5–F6 | Stessa fonte/CSV, seconda acquisizione deliberata, identità/proprietà/ACK/provenienza verificate per entrambe le acquisizioni;8 Cinema preservati |
| M2 — CSV ripetibile | Percorso completo utilizzabile su dati nuovi | M1 + nuovo CSV, semantica con vocabolario dove richiesto, casi esistenti/nuovi/ambigui, fault/ripresa e due client reali qualificati |
| Fuori dal miniprogetto | Estensioni successive | Altri formati, verticali API, layer dinamici/streaming GIS, nuove ricerche per prossimità/affinità e qualifica di un installer universale multi-host |

M1 non implica M2. M2 è accettazione del percorso CSV nel profilo dichiarato, non certificazione dell'intera piattaforma o sostituzione di tutte le suite PET.

Il piano storico del17 ottobre mantiene validi i requisiti più ampi: merge di due oggetti canonici, grafi avanzati e altre estensioni non diventano PASS per effetto di questo documento. Il match di una nuova riga con un oggetto esistente è obbligatorio qui; il merge di due oggetti canonici già esistenti è un'operazione distinta e resta una verifica separata.

## 2. Autorità documentale e baseline

Ordine di prevalenza: istruzioni attuali dell'owner; baseline originale Matrix/PET/contratti; policy di resilienza vigente; questo miniprogetto per sequenza, tracciabilità e criteri locali. Un conflitto normativo ferma il solo delta interessato e viene esplicitato; non si corregge cambiando silenziosamente il criterio.

Originali consultati per la versione1.0:

| Riferimento | Sezioni utilizzate | Vincolo applicato |
| --- | --- | --- |
| Matrix1.7 | §§1–4 | Ownership congelata, E2E canonici, distinzione qualifica logica/accettazione rappresentativa |
| Blueprint0.3 | §§7–10 | Identificativi OUF-E2E-001…025, prove specifiche, gate e stato corrente unico |
| Onboarding PET1.6 | §§7.3–7.6,8–9,12–13 | Mapping, source-object identity, temporalità, semantic gap e azioni HUMAN |
| Semantic Registry PET1.3 | §§7–9.2 | Vocabolari/concetti, relazioni, lifecycle e pubblicazione autoritativa |
| UDP PET1.3 | §§4–4.1,11.1–12,20–20.1 | ACK distinto dal commit, identità canonica e atomicità revisioni/lineage |
| E2E Integration Specification0.3 | scenario catalog, frozen acceptance traceability, evidence-record-v1 | Semantica concreta dei casi e formato delle prove canoniche |
| Contratti OUF | 1.0.0-rc3-coherence | Contratti fissati e compatibilità dei delta |

Il catalogo originale è nell'allegato baseline: implementation/ouf-e2e-integration-spec-v0.3/spec/e2e-scenario-catalog.yaml. I casi locali CSV-AT-* sotto sono test del miniprogetto: **non creano un nuovo namespace E2E canonico**.

A ogni sprint si consultano gli originali pertinenti al delta, registrando versione e sezioni effettivamente lette. Per i rilasci si riusano le evidenze valide delle suite di modulo e si eseguono regressioni giustificate dai cambiamenti; SKIPPED non equivale a PASS.

## 3. Stato iniziale da conservare

| Elemento | Stato e trattamento |
| --- | --- |
| Tecniche | 8/8 conservato; le attività WP sotto non rinumerano le fasi tecniche |
| Funzionali | F1–F4 provate; F5–F6 aperte |
| Owner7/projection7 | Completi, claim consumati, nessun replay |
| Prima acquisizione/lettura | Ricevute F3/F4:13 Teatri,20 proprietà ciascuno, identità precedente conservata; prima acquisizione ottenuta con recovery governato |
| Source revision generica | Codice, test, canale MCP/Gateway e ricevuta di installazione presenti; profilo concreto non pubblicato |
| DB | Prerequisiti read-only storicamente provati; ammissione corrente e policy effettiva di startup ancora da provare nel nuovo contesto |
| Executor | Core firmato/finito, key custody, comparatori e namespace qualificati a livello componente; Ports/issuer/closure/entrypoint completi mancanti |
| HUMAN | Ultimo278/288,10 residui; scadenza20 ottobre00:57:44Europe/Rome già trascorsa; nessuna autorità corrente inferibile |
| Account OUF | ouf-admin è account routing;26 definizioni tool esposte; ciò non attesta autenticazione corrente né disponibilità di executor target |
| CI corrente | Tre risultati da riconciliare: Ingestion39380500855, MCP39232083000, Deploy39392193693 |

Contesti preservati: ingestion-rollout-packet-kkj_njiz; ingestion-rollout-packet-reconcile-0wd4wyuf; ingestion-frame-mac-reconcile-qfcpqd9f. Ultimo packet-plan SHA256: ad1bdb240483f85785b989f28cd895a72394ea964baabd85ad3062b10180fe5c; verifiedInputs: c556d7ea44bc7f7e1f337358e166e2cde11c90e6459a76cc703c178218bd9907.

Questi sono binding storici dell'installazione corrente, non default di prodotto. Le installazioni/readback, preflight DB, bootstrap, audit/download/staging e riconciliazioni già conclusi non si rilanciano. Una nuova osservazione richiesta da un gate deve avere finalità, perimetro e budget propri e non riaprire l'azione consumata.

## 4. Ownership e riuso obbligatorio

| Owner | Responsabilità nel percorso | Riuso individuato |
| --- | --- | --- |
| Semantic Registry | Artefatti semantici, vocabolari, concetti e pubblicazioni esatte | ProposalCommandService, GovernanceService, catalogo e receipt |
| Onboarding/THS | Fonte, asset, mapping/versioni, review e bundle immutabili | ManagedFile*, ManagedFileExecutionProposal, SourceRevisionService, review nativa |
| Ingestion | Esecuzione fissata, trasformazione approvata, handoff, checkpoint e watermark | ManagedTabularAdapter, CanonicalRecordPipeline, RunExecutionWorker, OutboxDispatcher |
| UDP | Identità, conflitti, proprietà, revisioni, relazioni e lineage canonici | GovernedIdentity*, LinkedPropertyReconciler, PublishedResolutionLoop, recovery |
| Gateway | Routing e mediazione governata, contesto verificato | Materializzatori source revision/managed/semantic e ricevute Lua |
| Authorization | Policy e capability; controllo fine applicato dagli owner | SDK e bundle di policy già presenti |
| MCP | Tool tipizzati, delega consentita, stato e ripresa | Manifest/kernel, revisioni, stato/storia, read/receipt, delta PR48 da riconciliare |
| Deploy | Installazione parametrica e azioni finite governate | NativePorts precedenti, journal/CAS, contract/key/replacement/namespace nuovi |

Per ogni modifica si registra: requisito, owner, codice/test esistente, delta minimo, impatto contratti/migrazioni e nuova prova richiesta. Non creare un secondo workflow engine, un nuovo identity engine o un recovery engine parallelo.

## 5. Requisiti del miniprogetto

“Deve” indica requisito di uscita; “non deve” indica invariante. Le forme wire e i nomi degli endpoint restano quelli dei contratti owner. Gli identificativi seguenti servono per tracciamento.

| ID | Requisito verificabile | Owner principale | Test |
| --- | --- | --- | --- |
| CSV-R01 | Discovery/tool e chiamate devono riflettere le autorizzazioni correnti del principal; una capability visibile non conferisce grant | MCP/Gateway/Authorization | AT01,AT18 |
| CSV-R02 | Upload deve usare picker/trasporto OUF governato, asset owner, hash e limiti; nessun URL arbitrario assunto come allegato affidabile | Onboarding | AT02,AT03 |
| CSV-R03 | Il parser deve gestire il profilo CSV dichiarato; input incompatibili devono produrre diagnosi senza alterare l'originale | Onboarding/Ingestion | AT03 |
| CSV-R04 | Ogni riga deve avere sourceObjectId deterministico secondo policy approvata; riordino e duplicati di chiave devono avere esito esplicito | Onboarding/Ingestion | AT04 |
| CSV-R05 | Classi/proprietà/vocabolari devono essere riferimenti pubblicati e versionati; nessuna equivalenza inventata da etichette | Registry/Onboarding | AT05,AT06 |
| CSV-R06 | Mapping codice→concetto deve conservare codice originale, concetto/versione e regola; valore sconosciuto gestito esplicitamente | Onboarding/Ingestion | AT05 |
| CSV-R07 | Tipi, normalizzazioni e temporalità devono essere dichiarati; nessuna data/validità o cancellazione inferita implicitamente | Onboarding/Ingestion/UDP | AT05,AT12 |
| CSV-R08 | Approvazione/attivazione devono avvenire in THS con identità HUMAN e stato/hash/versione attuali | THS/owner | AT07,AT18 |
| CSV-R09 | Pubblicare una nuova versione e ammettere una nuova acquisizione devono avere effetti dichiarati; una proposta non esegue acquisizione | Onboarding/Ingestion | AT08 |
| CSV-R10 | Run, bundle, schema e pubblicazione semantica devono restare fissati anche durante cambi ACTIVE o ripresa | Ingestion/Registry | AT09 |
| CSV-R11 | Nessun committed watermark deve avanzare senza ACK durevole; esiti ambigui si riconciliano con la stessa identità | Ingestion/UDP | AT10,AT17 |
| CSV-R12 | Il resoconto deve distinguere consegna/ACK da materializzazione e mostrare l'esito terminale per riga ammessa | UDP/MCP | AT10,AT14 |
| CSV-R13 | UDP deve decidere MATCH/NEW/REVIEW; Onboarding/Ingestion non assegnano urbanObjectId | UDP | AT11 |
| CSV-R14 | Proprietà complementari, autorità, conflitti, null/vuoti, multivalore e cancellazioni devono rispettare il profilo approvato | UDP | AT12 |
| CSV-R15 | Provenienza e storia devono consentire risalita fino a fonte/riga/run/bundle/pubblicazione semantica | Ingestion/UDP | AT12,AT14 |
| CSV-R16 | Una relazione dichiarata nel profilo deve usare semantica e risoluzione governate; target assente/ambiguo non genera edge arbitrari | Registry/Onboarding/UDP | AT13 |
| CSV-R17 | Retry tecnico e seconda acquisizione deliberata devono avere identità ed effetti distinti; nessun duplicato canonico o revisione gratuita | Ingestion/UDP | AT15,AT16 |
| CSV-R18 | Interruzione, revoca e restart devono conservare contesto, claim, budget e storia; nessun replay automatico dopo STOP | Tutti | AT17,AT18 |
| CSV-R19 | Una nuova chat/client deve recuperare il lavoro dagli owner, senza dipendere dalla memoria del modello | MCP/Onboarding | AT19 |
| CSV-R20 | Dati/contatori/edge riservati devono essere filtrati dall'owner prima della serializzazione, anche per tenant diverso | Authorization/UDP/MCP | AT18 |
| CSV-R21 | Il percorso deve riuscire su due client MCP indipendenti, almeno uno con soli tool e collegamenti web OUF | MCP/THS | AT20 |
| CSV-R22 | Ogni valore specifico dell'Ente deve provenire dal profilo validato; MAC endpoint distinti dai MAC fisici host | Deploy/tutti | AT21 |
| CSV-R23 | Rollout deve essere finito, con effetti claimed-once, prove di generazione e riconciliazione degli esiti incerti | Deploy | AT22,AT23 |
| CSV-R24 | Fonti/oggetti/claim storici e baseline8 Cinema devono essere conservati; il dossier deve separare CI, target e accettazione | Deploy/UDP | AT16,AT24 |

I nomi AT01…AT24 nella tabella abbreviano CSV-AT-01…CSV-AT-24.

## 6. Profilo CSV di accettazione

### 6.1 Perimetro di input

Il profilo iniziale usa UTF-8, con/senza BOM, separatore esplicito virgola o punto e virgola, quoting CSV, newline nelle celle e intestazione obbligatoria. Il parser/profiler decide validità rispetto a quel profilo; non deve reinterpretare silenziosamente delimitatori o encoding diversi. File limite, righe irregolari, intestazioni duplicate/mancanti e caratteri non validi hanno esito strutturato.

Limiti di byte/righe/colonne/cella, retention e quote sono parametri versionati del profilo. Il compilatore corrente ammette1–32 campi e asset fino a10 MiB: questo è il supporto oggi verificato nel codice, non un obbligo ad aumentarlo. Le prove coprono i limiti del profilo scelto, compreso il caso appena oltre soglia.

Tipi minimi nel profilo generale: stringa preservata, decimale con formato esplicito, data con formato esplicito, concetto di vocabolario. Il delta rispetto al percorso string/IDENTITY va implementato e provato in WP5. Altri tipi sono ammessi solo se dichiarati e già qualificati.

Una colonna di relazione può essere inclusa nella fixture generale per esercitare una relazione verso un oggetto preesistente; riusa i contratti e il motore relazioni UDP. Non richiede nuove ricerche geografiche o un graph database distinto.

### 6.2 Intenti distinti

| Intenzione | Regola |
| --- | --- |
| Retry della stessa richiesta | Stessa command/idempotency identity, stessa risposta o riconciliazione; non nuova fonte/versione/run implicita |
| Seconda acquisizione voluta | Nuova intenzione governata e nuova run; stessa fonte e identità record secondo policy |
| Nuova configurazione | Nuova versione e nuova approvazione; effetti di acquisizione espliciti |
| Recovery dopo STOP | Leggere claim/esito già persistito, chiudere solo con evidenza; non redispatch dell'effetto incerto |
| Nuovo budget HUMAN | Solo decisione esplicita ammessa dai contratti, nuova sessione finita e storia conservata; non reset o estensione automatica |

Sul caso corrente il nuovo profilo può legittimamente cambiare il risultato delle proprietà e generare revisioni. La prova “snapshot invariato” richiede invece stesso contenuto e stessa configurazione fissata: deve verificare nessuna nuova revisione canonica dovuta al solo fatto di una nuova run.

## 7. Contratti logici ed evidenze di stato

Nessun nuovo datastore di workflow è richiesto. Il riepilogo conversazionale aggrega gli stati degli owner e conserva i riferimenti necessari al recupero.

| Fase logica | Identità/evidenza da conservare | Condizione per avanzare |
| --- | --- | --- |
| File acquisito | assetId, source owner, hash contenuto, receipt/handoff picker | Ownership e limiti verificati; riferimento recuperabile |
| Profilo pronto | profileId/versione, schema osservato, anomalie, identity policy proposta | Parser e scelte esplicite |
| Mapping in revisione | sourceId/versione, mapping, semantic refs, hash, commandKey, trustedApprovalRef | Validazione e review preparate; nessuna autorità implicita |
| Configurazione attiva | bundle/versione/checksum, attore/decisione HUMAN, publication refs | Stato corrente owner e consumer compatibility |
| Run ammessa | runId, intentionRef, source/version, snapshot contratti, correlationId | Gate d'ammissione e budget validi |
| Consegna persistita | riga/sourceObjectId, handoffId, receipt ACK, watermark | Evidenza durevole downstream |
| Materializzazione | materializationJob, outcome, urbanObjectId/revision, property/edge lineage | Stato terminale owner; ambiguità esplicita |
| Resoconto | Conteggi completi o parzialità dichiarata, errori e prossime azioni consentite | Lettura autorizzata, niente successo dedotto dal solo ACK |

Queste etichette sono viste logiche, non nuovi enum imposti agli owner. La mappatura agli stati effettivi viene verificata in WP6.

L'invariante di rendiconto è: ogni riga ammessa ha un esito tracciato; righe rifiutate o in attesa sono contabilizzate separatamente. Non si ottiene “successo” ignorando righe problematiche o cambiando il denominatore.

## 8. Work package e sequenza esecutiva

### WP0 — Fissare il punto di ripartenza

**Effort:** incluso in WP1, nessun totale aggiuntivo.  
**Input:** questo piano, audit, AGENTS, baseline originale, handoff corrente e contesti conservati.  
**Output:** registro iniziale con head/immagini/contratti noti, prove riusabili e stati aperti.

Azioni: verificare gli head prima delle modifiche; distinguere sorgente/candidato/installato; riportare claim già consumati; marcare le sole osservazioni correnti necessarie ai gate futuri. Validare i riferimenti dell'account ouf-admin senza trasformare discovery in prova di autorizzazione.

**Gate G0:** baseline e selezione inequivoche; nessun input mancante sostituito con una scelta “simile”. Se non è accessibile un originale necessario, il requisito relativo resta bloccato e viene indicato esattamente quale documento manca.

### WP1 — Qualificare la coorte e correggere i tre risultati CI

**Dipendenza:** WP0. **Effort:**2–4 ore.  
**Owner:** Ingestion, MCP, Deploy.

1. Ingestion: riprodurre in ambiente isolato i tre esiti RunControlRuntimeTest e verificare l'interferenza di schedule/fixture. Correggere isolamento o difetto effettivo; conservare test che provano comportamento globale del scheduler.
2. MCP: diagnosticare il p95 circa73ms rispetto al gate25ms; distinguere carico del runner, profilo di test e regressione. Non aumentare la soglia solo per ottenere PASS.
3. Deploy: ricostruire il binding storico di human_session.py nel test pacchetto/capsule. Preservare i pacchetti già consegnati/consumati; correggere la riconciliazione documentata o produrre un nuovo pacchetto distinto se richiesto dal contratto.
4. Fissare la coorte finale compatibile e i controlli da rieseguire dopo ogni delta, con riferimenti alle prove riutilizzabili.

**Output:** fix mirati, CI pertinenti verdi, registro pin/migrazioni e motivazione di eventuali esclusioni.  
**Gate G1:** nessun fallimento rilevante aperto o ignorato; evidenza legata ai byte effettivamente candidati. Una CI verde su un altro head non chiude il gate.

### WP2 — Completare e qualificare l'executor nativo

**Dipendenza:** WP1 per qualificazione; preparazione su baseline WP0 consentita. **Effort:**8–14 ore.  
**Owner:** Deploy.

Sottoattività:
- WP2.1 adattare NativePorts esistenti agli effetti del nuovo piano, reti multiple e binding completi; persistere allocazione/CID prima di poter riconciliare una risposta persa;
- WP2.2 integrare controlli correnti HUMAN, Owner7/payload/ETag/projection, DB read-only e readiness con budget limitati;
- WP2.3 mantenere un canale di controllo qualificato indipendente dal Gateway fermato; usare soltanto namespace FD e generazione del nuovo Gateway per il suo admin transport;
- WP2.4 gestire esattamente i due PUT proposti e il readback completo82 route, preservando le altre80 per l'installazione corrente;
- WP2.5 comporre nuovo scope/issuer, chiusura eseguibile immutabile e entrypoint; vietare uso di autorizzazioni Owner7/projection7 consumate;
- WP2.6 prove native su runtime isolato: due reti, esito perso prima/dopo effetto, restart, drift, revoca, scadenza, processo vecchio/namespace vecchio, claim già presente e budget esaurito.

**Output:** executor qualificato, contratto della review, source/image pin, prove avversariali e procedura di sola riconciliazione.  
**Gate G2:** executor completo qualificato; componenti singoli o Gateway fixture che dorme non bastano. Tutti i valori dell'Ente provengono dagli input validati. Non eseguire ancora sul VPS per ottenere questo gate.

### WP3 — Ammissione, rollout e pubblicazione del profilo

**Dipendenza:** G1 e G2; disponibilità esplicita dei gate runtime. **Effort:**4–6 ore attive, attese HUMAN escluse.  
**Owner:** Deploy, Onboarding/THS, Ingestion, Gateway.

Prima di ogni nuova mutazione devono risultare: autorità corrente valida per il nuovo scope; budget residuo sufficiente; owner/generazioni attesi; ammissione DB corrente; policy effettiva di startup/migrazione validata; trasporti e closure qualificati. La preflight storica non vale come ammissione corrente e non deve essere rilanciata come azione consumata.

Il gate DB verifica il profilo approvato, ruolo/privilegi, schema e storia migrazioni, catalogo candidato, pressione/capacità e workload rilevante. Il candidato corrente è validate-only: un'impostazione d'ambiente non prova da sola la policy effettiva. Non avviare migrazioni implicite per superare il gate.

Preparare la review concreta e governata del nuovo rollout. Se manca autorità, fermare le operazioni dipendenti: il presente piano non autorizza login/rinnovi/reset automatici. Con autorità valida, eseguire soltanto gli effetti nuovi non consumati, conservando vecchi container/claim per le verifiche previste.

Dopo readiness e route verificate, preparare la revisione del profilo tramite capacità generiche esistenti, mostrare diff e possibile effetto di acquisizione, ottenere approvazione/attivazione HUMAN in THS e verificare pubblicazione esatta. Pubblicazione e acquisizione devono corrispondere all'intenzione approvata, senza avvio duplicato.

**Output:** ricevuta rollout, ammissione effettiva, profilo nativo pubblicato, esatti riferimenti di versione/decisione.  
**Gate G3:** realtà runtime coerente con il piano; nessuna ambiguità irrisolta o route collaterale cambiata. In caso STOP, conservare e riconciliare.

### WP4 — Chiudere F5 e F6 sul caso conservato

**Dipendenza:** G3. **Effort:**4–6 ore.  
**Owner:** Ingestion/UDP/MCP, accettazione HUMAN.

Prima della seconda acquisizione fissare il confronto delle identità e proprietà dalle prove conservate e dalle sole letture correnti necessarie. Autorizzare la nuova acquisizione della stessa fonte/CSV tramite il percorso nativo, distinguendola da retry e recovery.

Verificare tutte le13 righe, non un campione: run e bundle, ACK durevoli, outcome UDP,13 identità Teatri conservate,20 proprietà secondo il nuovo profilo, provenance di entrambe le acquisizioni, decisioni storiche non ripetute,8 Cinema invariati. Le revisioni nuove sono ammesse solo se giustificate dal cambiamento di contenuto/contratto applicato.

**Output:** dossier F5 e F6 separati, resoconto chat e confronto before/after autorizzato.  
**Gate G4/M1:** F5 e F6 provate. F5 non si chiude con un retry della prima run; F6 non si chiude con il solo stato Ingestion SUCCEEDED.

### WP5 — Completare il delta semantico del CSV generale

**Dipendenza:** G0 e contratti fissati; integrazione finale dopo G1. **Effort:**8–14 ore.  
**Owner:** Onboarding, Ingestion, Registry; UDP per valori/relazioni.

1. Definire i delta nei contratti esistenti per mapping codice→concetto e tipi dichiarati; compatibilità delle configurazioni IDENTITY già pubblicate.
2. Riutilizzare i vocabolari/concetti pubblicati del Registry e i mapping source-specific di Onboarding.
3. Estendere proposta/validazione/compilazione ed esecuzione in modo coerente; impedire che la proposta accetti una trasformazione che il consumer rifiuta.
4. Conservare valore originale, regola/versione, concetto e publication set; valore sconosciuto produce gap/errore secondo policy approvata, senza fallback semantico inventato.
5. Comporre un mapping di relazione semplice attraverso i contratti già esistenti e qualificare il caso target presente/assente/ambiguo; nessun nuovo motore relazioni.
6. Verificare backward compatibility, formato/limiti e compatibilità di ogni riga prima dell'attivazione.

**Output:** patch minime nei moduli owner, contratti/esempi coerenti, suite e fixture semantica.  
**Gate G5:** testAT03–AT07,AT09,AT13 pertinenti verdi; pubblicazioni storiche ancora risolvibili; nessuna attivazione del nuovo percorso basata sulla sola compilazione.

### WP6 — Completare il percorso conversazionale e la ripresa

**Dipendenza:** G0/G1; prove definitive con G5. **Effort:**8–14 ore.  
**Owner:** MCP/Gateway/Onboarding/UDP/THS.

Riconciliare il delta già sviluppato di resolution.issue.read e la relativa route con i contratti owner correnti. Esporre soltanto le letture/proiezioni mancanti: caso ambiguo, riferimenti di review, esiti per riga, proprietà/lineage e stato del lavoro.

Rendere recuperabile il riferimento a file/fonte/review/run dopo nuova chat. La receipt temporanea del picker non deve essere l'unico modo per ritrovare l'asset persistito. Prima di aggiungere persistenza o API, verificare le letture owner già disponibili e riusarle.

Il resoconto deve distinguere “in revisione”, “ammesso/in esecuzione”, “consegnato”, “materializzato”, “parziale/errore” usando gli stati owner, con conteggi, motivi e prossime azioni autorizzate. Non dedurre assenza di dati da403 o indisponibilità.

Qualificare due client indipendenti: entrambi percorrono i tool e i link OUF; almeno uno non richiede UI incorporata. Le conferme restano HUMAN. L'autenticazione manuale necessaria si svolge solo nel percorso esplicitamente autorizzato, senza rinnovi automatici dell'agent.

**Output:** superficie MCP completa nel perimetro, schema del riepilogo, recupero e prove client.  
**Gate G6:** AT01,AT14,AT18–AT20 verdi sul profilo di test; tool protetti assenti e nessuna dipendenza da un prompt segreto o script locale dell'utente.

### WP7 — Collaudo finale e rilascio del miniprogetto

**Dipendenza:** G4,G5,G6 e coorte finale fissata. **Effort:**6–12 ore.  
**Owner:** intermodulo, accettazione finale HUMAN.

Comporre e qualificare la coorte finale risultante da WP5/WP6 e distribuirne il solo delta con un piano e un'autorità runtime pertinenti. Riutilizzare l'executor qualificato; non ripetere gli effetti o i claim di WP3. Le nuove immagini devono essere quelle effettivamente collaudate. Questa integrazione finale e il relativo rollout governato sono inclusi nell'effort WP7.

Aggiornare l'harness verticale esistente, non crearne uno equivalente. Eseguire soltanto scenari mancanti o regressioni causate dai delta. Distinguere fixture di IAM/Gateway dalle prove rappresentative con binding reali.

Eseguire il nuovo CSV e la seconda acquisizione invariata, casi ambigui/conflittuali, fault/revoca/ripresa, due client e secondo profilo d'installazione isolato. Le prove intrusive di crash/riavvio/revoca si eseguono su ambiente dedicato; nessun fault injection sul caso conservato senza un'azione specifica autorizzata.

Consolidare evidenze, pin, guida utente e runbook operatore. I problemi aperti devono avere requisito/test/owner e conseguenza sulla chiusura; non si accetta un generico “da monitorare”.

**Gate G7/M2:** tutti i test obbligatori locali PASS nel livello richiesto; criteri canonici mappati provati o chiaramente non attestati fuori perimetro; accettazione esplicita HUMAN registrata. Un gate obbligatorio bloccato mantiene M2 aperto.

## 9. Gate e dipendenze

| Gate | Evidenza richiesta | Consente |
| --- | --- | --- |
| G0 | Selezione/baseline/contesti e ledger iniziale | Sviluppo del delta |
| G1 | Coorte e CI pertinenti qualificate | Qualificazione finale di executor e release candidata |
| G2 | Executor completo, chiusura e test nativi | Preparazione della review runtime |
| G3 | Autorità corrente + DB/readiness/rollout/profilo effettivi | Seconda acquisizione governata |
| G4 | F5/F6 provate | M1 completo |
| G5 | Semantica CSV generale e contratti qualificati | Test generale di acquisizione |
| G6 | Superficie chat/ripresa/client qualificata | Accettazione utente completa |
| G7 | Coorte finale e dossier completo | M2 completo |

Percorso del caso corrente: WP0→WP1→WP2→WP3→WP4.  
Percorso generale: WP0/WP1→WP5 e WP6; WP4+WP5+WP6→WP7.  
Durante un'attesa HUMAN si può lavorare su WP5/WP6 senza consumare authority o ricominciare operazioni ferme. La sessione resta sequenziale, senza subagenti.

## 10. Dataset e ambienti di collaudo

| ID | Preparazione | Risultato deterministico |
| --- | --- | --- |
| CSV-DS0 | Caso conservato: stessi byte CSV/fonte/versioni storiche,13 Teatri e baseline8 Cinema | Nuova acquisizione esplicita;13 identità conservate;20 proprietà conformi;8 Cinema e claim storici preservati |
| CSV-DS1 | CSV sintetico nuovo,3 righe con chiavi stabili; scope isolato con3 oggetti U1,U2,U3; rigaA matchU1, rigaB nuova, rigaC matchU2 secondo policy esplicita |4 oggetti canonici totali nello scope, un solo nuovo ID, nessuna modificaU3; lineage dei tre record |
| CSV-DS1R | Stessi byte, stessa configurazione e stessi semantic refs diDS1, nuova acquisizione autorizzata | Sempre4 oggetti; ID e revisioni canoniche invariati se il contenuto canonico è invariato; nuova evidenza run/handoff |
| CSV-DS2 | Varianti separate: chiavi duplicate, schema errato, codice vocabolario sconosciuto, due candidati plausibili, conflitto a pari autorità | Esito negativo o review previsto; nessun match/concetto/cancellazione inventato |
| CSV-DS3 | Vocabolario pubblicato con codici01/02; stringa con zero iniziale, decimale/data con formato dichiarato; relazione verso target autorizzato | Codice originale preservato, concetto/versione corretti, tipi deterministici, un edge governato; varianti target assente/ambiguo esplicite |
| CSV-ENV-A/B | Profili isolati con nomi rete, indirizzi, MAC endpoint, path e binding differenti | Stesso codice e stessi contratti; nessun valore dell'EnteA necessario perB |

Dataset sintetici e nuove fixture non possono usare come input da riconfermare le decisioni storiche già consumate. Hash, expected outcomes e policy sono fissati prima dell'esecuzione; cambiarli dopo un risultato richiede nuova versione della fixture.

Per i casi di fault servono runtime isolati reali e persistenza reale. Per la prova client finale servono IAM/Gateway/THS reali del profilo selezionato. La disponibilità di due client e di authority valida è una dipendenza esplicita, non una precondizione da simulare per dichiarare M2.

## 11. Catalogo di accettazione locale

Per ogni test: input fissato, azione autorizzata, output atteso, evidenza e livello. “I”=integrazione isolata; “T”=target/binding reali; “C”=client reale. Gli scenari canonici elencati indicano tracciabilità: il PASS locale non chiude lo scenario canonico se non ne esegue tutte le precondizioni/asserzioni.

| Test | Procedura ed esito atteso | Livello | Tracciabilità canonica |
| --- | --- | --- | --- |
| CSV-AT-01 | Discovery e chiamata con principal autorizzato/negato; capability,owner,scope,versione e route coerenti; negato senza dispatch improprio | I+T+C | OUF-E2E-022 |
| CSV-AT-02 | Upload OUF, profiling e risposta persa; asset/hash/owner unici, stesso comando riconciliato senza nuovo asset/fonte involontario | I+T+C | Locale; supporta017 |
| CSV-AT-03 | BOM/delimitatore/quoting/newline; file/cella/righe al limite e oltre; header/forma errati; diagnosi e originale preservati | I | Locale; variante schema001 solo se scenario completo |
| CSV-AT-04 | Riordinare righe con chiavi approvate e provare chiave duplicata; sourceObjectId stabili o errore esplicito | I+T | OUF-E2E-020 |
| CSV-AT-05 | DS3: codici→concetti e tipi dichiarati; originali/versioni preservati; unknown e valore invalido non materializzati come validi | I+T+C | Locale; supporta017,019 |
| CSV-AT-06 | Gap semantico: proposta DRAFT, validazione/review/pubblicazione HUMAN, ripresa sulla stessa fonte; nessuna attivazione con riferimento non ammesso | I+T+C | Locale; supporta017 |
| CSV-AT-07 | Confermare versione corrente e tentare hash/ETag obsoleto; corrente accettato, obsoleto rifiutato; MCP non approva/attiva | I+T | THS-A pertinente; supporta017,022 |
| CSV-AT-08 | Preparazione non pubblica/acquisisce; nuova pubblicazione mostra effetto; una intenzione governata ammette la sola acquisizione prevista, anche dopo poll/restart | I+T | OUF-E2E-017 |
| CSV-AT-09 | Cambiare ACTIVE semantico durante run isolata e riprendere; run resta sulla pubblicazione fissata, nessun fallback latest | I | OUF-E2E-019 |
| CSV-AT-10 | Fault prima della persistenza/ACK e risposta ACK persa; watermark non anticipato, idempotenza; commit UDP verificato separatamente | I+T readback | OUF-E2E-002 |
| CSV-AT-11 | DS1 e variante ambigua; due match,un nuovo ID; ambiguità inreview; decisione HUMAN consumata una volta | I+T+C | OUF-E2E-006,020 |
| CSV-AT-12 | Complementi/null/vuoto/equivalenza/priorità/conflitto/multivalore/delete esplicito; proprietà corrette, contributi e storia conservati, no perdita collaterale | I+T | Locale; supporta006 |
| CSV-AT-13 | Relazione dichiarata: target presente/assente/ambiguo, retry; solo edge ammesso, deduplicato e con provenance | I+T | Locale, suite UDP relazioni |
| CSV-AT-14 | Riepilogo di tutte le righe; collegamenti riga→run→handoff→ACK→job→oggetto/revisione; parzialità/attese/errore distinti | T+C | OUF-E2E-017,025 |
| CSV-AT-15 | DS1R invariato con nuova run e retry separato della stessa richiesta;4 oggetti e nessuna revisione canonica gratuita; lineage nuova run presente | I+T+C | OUF-E2E-003 |
| CSV-AT-16 | DS0: seconda acquisizione effettiva distinta dalla prima;13 identità/20 proprietà, ACK/provenienza di entrambe,8 Cinema invariati, zero replay decisioni | T+C | F5/F6;003 solo nel caso contratti/contenuto invariati |
| CSV-AT-17 | Pause/restart/risposta persa, budget esaurito e claim incerto; contatori/storia preservati, solo riconciliazione, nessun effetto doppio | I | OUF-E2E-002;009/010 solo con tutte le loro condizioni |
| CSV-AT-18 | Revoca/scadenza, tenant errato e dato protetto; stop prima di nuovi effetti e owner deny prima della serializzazione; log/capability protetti non raggiungibili daMCP | I+T | OUF-E2E-018,022;016 boundary, non intera suiteTHS |
| CSV-AT-19 | Interrompere chat dopo upload/review/run; riaprire con stesso utente autorizzato e riferimenti durevoli; riprendere senza nuovo job implicito | T+C | Locale, MCP acceptance |
| CSV-AT-20 | ClientA eB indipendenti eseguono il percorso nuovo CSV; almenoB senza UI incorporata; rientro daTHS e lettura esiti senza terminale | T+C |017,022 e suiteMCP/THS applicabili |
| CSV-AT-21 | ProfiliENV-A/B: endpoint/indirizzi/MAC/path differenti, due reti; stesso codice, nessun default storico; input non validi rifiutati | I |021 per identità se precondizioni complete; ambiente locale |
| CSV-AT-22 | Executor: key/image/lifecycle/route con fault prima/dopo effetto; CID/PID/StartedAt/namespace nuovi verificati, predecessore conservato, no replay | I | Locale, gate operativo |
| CSV-AT-23 | Gate correnti DB/HUMAN/Owner e readiness; assenza/drift/revoca blocca; due route attese e altre80preservate, policy startup effettiva provata | I+T |024 solo se intero scenario LKG eseguito |
| CSV-AT-24 | Verifica finale coorte/contratti/evidenze/baseline e guida; tutti i requisiti coperti, nessun obbligatorio SKIPPED/BLOCKED, accettazione HUMAN | T+C | Blueprint0.3§9 |

Le prove già valide del medesimo codice/contratto si riusano tramite riferimenti. Una modifica a codice, dipendenza, immagine o profilo richiede analisi d'impatto: non si riusa una prova incompatibile e non si rilancia tutto senza motivo.

### 11.1 Prove canoniche minime e limiti

Il dossier deve contenere prove complete degli scenari canonici applicabili al percorso: **OUF-E2E-002,003,006,017,018,019,020,022,025**. Gli scenari che richiedono fault o switch semantici usano ambiente isolato dichiarato; il percorso positivo e la negazione owner devono avere anche binding rappresentativi.

Per001,009,010,016,021,023,024 si riusano le qualifiche pertinenti disponibili e si eseguono le regressioni impattate; non attribuire PASS completo sulla base di un sotto-test locale. Per esempio, due reti non provano due provider IAM; assenza tool log in MCP non prova l'intero exportTHS; duePUT verificati non provano da soli LKG sotto guastoetcd.

La release CSV non elimina gli obblighi del catalogo canonico e delle suite di modulo per una futura accettazione dell'intera piattaforma.

## 12. Formato delle evidenze e definizione di completato

Ogni work package chiuso deve produrre almeno:
- requisito/test coperto, commit e modulo owner;
- ambiente, profilo/versione/hash, immagini effettive e contract freeze;
- input/fixture e risultati attesi;
- assertion per assertion con PASS/FAIL/BLOCKED, senza “successo generico”;
- link ad artifact/log redatti, timestamp e correlation IDs;
- limiti della prova: fixture vs sistema reale, byte sorgente vs immagine installata;
- per runtime: autorità/decisione di riferimento senza credenziali, claim/stati conservati e postcondizioni verificate.

Per gli E2E canonici si usa evidence-record-v1.json della baseline con scenarioId,executionId,environment,status,assertions,artifacts,contractFreezeVersion. I casi locali conservano testId=CSV-AT-xx e canonicalScenarioRefs; non si inserisce CSV-AT in scenarioId canonico.

**Done di un work package:** output presenti, gate superato, prove collegate al codice corretto, nessun blocco di competenza nascosto.  
**Done M1:** G4 raggiunto e F5/F6 aggiornate con evidenze.  
**Done M2:** G7 raggiunto, nuovi CSV/client/ripresa provati e accettazione HUMAN registrata.  
“Codice presente”, “CI verde”, “container running”, “ACK ricevuto” e “oggetto materializzato” sono evidenze diverse e vanno indicate separatamente.

## 13. Parametrizzazione per Ente

Il profilo d'installazione versionato deve contenere riferimenti validati per domini/DNS, endpoint/porte/scheme/TLS, host placement, route/upstream, issuer/audience/claim mapping/trust, segreti per riferimento, storage, UID/GID/runtime identity, reti/subnet/IPAM/IP/MAC endpoint e policy di allocazione.

I path API/capability e le semantiche di sicurezza congelate dai PET non diventano parametri arbitrari. Gli endpoint fisici si risolvono da binding approvati; input CSV e utente non possono introdurre host o bypass di rete.

Il testENV-B cambia realmente i valori e verifica che il codice non dipenda dall'EnteA. Le fixture con indirizzi fissi sono isolate e identificate come test. La qualifica di trasporti distribuiti multi-host resta distinta e non si deduce da questo test.

## 14. STOP, riconciliazione e recupero

| Evento | Azione consentita | Condizione di ripresa |
| --- | --- | --- |
| Input/contesto non esatto | STOP_RECONCILE, conservare selection e log | Riconciliazione documentata dell'identità corretta |
| Esito mutazione incerto | Claim rimane consumato/incerto; sole letture bounded | Prova owner dell'effetto o intervento governato sullo stesso intento |
| Scadenza/revoca HUMAN | Fermare nuove azioni dipendenti, conservare contesti | Autorità corrente ottenuta con percorso esplicitamente consentito; mai login/rinnovo/reset automatico |
| Transitorio idempotente | Pausa e retry soltanto secondo profilo finito già autorizzato, backoff/jitter e budget persistito | Dipendenza ripristinata, budget e authority ancora validi |
| Drift/integrità/config errata | Nessun retry automatico | Diagnosi e nuovo piano del delta corretto, claim pregressi conservati |
| Esaurimento budget | Incidente persistente e lavoro fermo | Eventuale nuovo budget HUMAN secondo contratto, senza azzerare lo storico |
| Rollout parziale | Conservare vecchi/nuovi container e journal; niente cleanup distruttivo | Riconciliazione stage-by-stage; rollback solo se esiste piano qualificato e autorità pertinente |

La policy generale5/15/60/300/900 secondi, jitter fino20%, massimo128 tentativi/24 ore non estende profili più stretti: il core rollout corrente ha900 secondi/128 letture e resta limitato da autorità residua. Non tenere lock o transazioni durante attese. Una finestra breve insufficiente ferma prima dell'effetto.

## 15. Effort, capacità e calendario

| Blocco | Ore assistite | Uscita |
| --- | ---: | --- |
| WP0+WP1 |2–4| G0/G1 |
| WP2 |8–14| G2 |
| WP3 |4–6| G3 |
| WP4 |4–6| G4/M1 |
| **Totale M1** |**18–30**| **F5/F6** |
| WP5 |8–14| G5 |
| WP6 |8–14| G6 |
| WP7 |6–12| G7/M2 |
| **Totale complessivo M2** |**40–70**| **CSV generale ripetibile** |

Le stime includono lavoro tecnico con agent avanzato, revisione e correzioni ordinarie. Non sono giornate di coding manuale e non devono essere ulteriormente divise per10/20. Il maggior risparmio rispetto alla stima precedente deriva dall'eliminazione di lavoro già realizzato.

Impegno HUMAN previsto3–6 ore complessive, in passaggi separati: decisioni di dominio/semantica, review/attivazioni e verifica finale. Tempo di attesa per disponibilità o autorizzazioni escluso. Indicazione di calendario, con gate disponibili:3–5 giorni lavorativi perM1,7–12complessivi perM2; nessuna data impegnativa finchéG1/G2 e finestreHUMAN non sono definiti.

Checkpoint di ristima:
- dopoWP1: classificazione effettiva dei tre fallimentiCI;
- dopoWP2: durata e affidabilità misurate dell'executor completo;
- dopoWP5/WP6: ampiezza reale dei delta semantici e della portabilità client.

Se un residuo richiede nuovi contratti, modifiche strutturali o multi-host reale, registrare prima impatto/requisito/stima. Non assorbirlo tacitamente nel budget e non ridurre i criteri per rispettare un numero.

### 15.1 Orologio di effort e scenari

Il cronoprogramma parte da **H+0 all'avvio di WP0** nella prossima sessione operativa. Comprende soltanto il lavoro residuo dopo la redazione del piano e dell'audit: non riconta attività già concluse.

H indica **ore cumulative di lavoro tecnico assistito**, con un solo agent principale e sequenza di riferimento senza parallelismo. Comprende analisi, modifiche, verifica e diagnosi attiva. Attese passive di CI/build, provisioning, disponibilità dell'utente, autenticazione o review HUMAN sospendono questo contatore. Si registrano separatamente dall'effort. Le decisioni HUMAN restano necessarie quando previste dai contratti.

| Scenario | M1: caso conservato e F5/F6 | M2: CSV generale completo | Criterio di costruzione |
| --- | ---: | ---: | --- |
| Snello | H+18 | H+40 | Limite inferiore di ogni work package; riuso senza ulteriori difetti rilevanti |
| Centrale | **H+24** | **H+55** | Punto medio degli intervalli; sequenza dettagliata sotto |
| Prudente | H+30 | H+70 | Limite superiore di ogni work package; integrazione e correzioni ordinarie più estese |

Sono tre scenari di pianificazione coerenti, non percentili statistici né deadline garantite. Un difetto strutturale o un ampliamento di perimetro richiede ristima esplicita. Le frazioni d'ora sono budget assegnati per controllare il lavoro: non attestano una durata già misurata.

### 15.2 Sequenza cumulativa per obiettivi e gate

Le finestre indicano l'inizio e la fine di ciascun blocco sul contatore H. Il raggiungimento dell'ora prevista **non supera automaticamente il gate**: servono le evidenze definite nei §§8–12.

| Blocco | Obiettivo d'uscita | Snello: ore cumulative | Centrale: ore cumulative | Prudente: ore cumulative | Gate / milestone |
| --- | --- | ---: | ---: | ---: | --- |
| WP0+WP1 | Baseline, diagnosi CI e coorte | 0–2 | 0–3 | 0–4 | G1 |
| WP2 | Executor completo qualificato | 2–10 | 3–14 | 4–18 | G2 |
| WP3 | Ammissione, rollout e profilo pubblicato | 10–14 | 14–19 | 18–24 | G3 |
| WP4 | Seconda acquisizione e verifica completa | 14–18 | 19–24 | 24–30 | G4 / **M1** |
| WP5 | Semantica, tipi e relazioni CSV | 18–26 | 24–35 | 30–44 | G5 |
| WP6 | Percorso chat, ripresa e client | 26–34 | 35–46 | 44–58 | G6 |
| WP7 | Rilascio finale e accettazione E2E | 34–40 | 46–55 | 58–70 | G7 / **M2** |

G0 è pianificato a **H+0,5** nello scenario centrale, all'interno delle 3 ore di WP0+WP1: non aggiunge un'ulteriore voce al totale. Nello stesso scenario **F5 è prevista a H+22**, **F6 e M1 a H+24**. F1–F4 e le otto fasi tecniche restano prove conservate: non hanno un nuovo blocco di riesecuzione.

### 15.3 Sequenza dettagliata dello scenario centrale

Ogni riga include la verifica del proprio output; i controlli di integrazione finali rimangono nei blocchi esplicitamente dedicati. Test e requisiti sono quelli associati ai WP e ai 24 casi di accettazione del registro strutturato.

| ID | WP | Finestra H | Effort | Attività | Evidenza / uscita |
| --- | --- | ---: | ---: | --- | --- |
| CSV-H-01 | WP0 | 0–0,5 | 0,5 h | Fissare baseline, contesti e selezione | Ledger iniziale; G0 |
| CSV-H-02 | WP1 | 0,5–1,25 | 0,75 h | Diagnosticare e correggere CI Ingestion | Causa dimostrata e correzione mirata |
| CSV-H-03 | WP1 | 1,25–1,75 | 0,5 h | Diagnosticare il gate prestazionale MCP | Profilo/risultato spiegati e verifica pertinente |
| CSV-H-04 | WP1 | 1,75–2,5 | 0,75 h | Riconciliare i pin storici Deploy | Binding pacchetto/capsule corretto senza alterare claim consumati |
| CSV-H-05 | WP1 | 2,5–3 | 0,5 h | Fissare coorte e chiudere le regressioni pertinenti | G1; checkpoint di ristima |
| CSV-H-06 | WP2 | 3–6 | 3 h | Integrare effetti NativePorts e persistenza delle identità | Effetti claimed-once e riconciliazione |
| CSV-H-07 | WP2 | 6–8 | 2 h | Integrare guard HUMAN/Owner/DB e generazioni | Controlli correnti, failure e scadenza verificati in fixture |
| CSV-H-08 | WP2 | 8–10 | 2 h | Integrare nuovo namespace e trasporto Gateway | Route e generazione nuova verificabili |
| CSV-H-09 | WP2 | 10–11,5 | 1,5 h | Comporre issuer, scope, closure ed entrypoint | Pacchetto eseguibile qualificabile |
| CSV-H-10 | WP2 | 11,5–14 | 2,5 h | Qualificare executor nativo e casi avversariali | G2; checkpoint di ristima |
| CSV-H-11 | WP3 | 14–15,5 | 1,5 h | Preparare review concreta e verificare ammissione corrente | Prerequisiti per i nuovi effetti; solo con authority pertinente |
| CSV-H-12 | WP3 | 15,5–17,5 | 2 h | Eseguire rollout governato e verificare readiness/route | Ricevuta e postcondizioni native |
| CSV-H-13 | WP3 | 17,5–19 | 1,5 h | Pubblicare il profilo attraverso THS e verificare i consumer | G3; profilo nativo attivo esatto |
| CSV-H-14 | WP4 | 19–21 | 2 h | Ammettere e seguire la seconda acquisizione deliberata | Nuova run della stessa fonte/CSV e stato owner |
| CSV-H-15 | WP4 | 21–22 | 1 h | Verificare esiti delle13 righe e identità/proprietà | F5 provata, se tutte le asserzioni sono soddisfatte |
| CSV-H-16 | WP4 | 22–24 | 2 h | Confrontare entrambe le acquisizioni e preservare8 Cinema | F6 + G4/M1; ACK, commit e provenienza completi |
| CSV-H-17 | WP5 | 24–26 | 2 h | Fissare contratti/fixture di vocabolari, tipi e temporalità | Delta compatibile con gli owner e gli storici |
| CSV-H-18 | WP5 | 26–29 | 3 h | Estendere proposta, compilazione e validazione | Configurazione dichiarata accettata dal consumer |
| CSV-H-19 | WP5 | 29–32 | 3 h | Integrare mapping valori e tipi nella pipeline | Originali, concetti/versioni e tipi deterministici |
| CSV-H-20 | WP5 | 32–35 | 3 h | Comporre relazioni e completare prove/compatibilità | G5; fixture positiva e casi di rifiuto |
| CSV-H-21 | WP6 | 35–38 | 3 h | Raccordare review package e binding MCP/Gateway | Review accessibile nel percorso governato |
| CSV-H-22 | WP6 | 38–41 | 3 h | Completare riepilogo per riga, esiti e lineage | Stati owner e parzialità distinguibili |
| CSV-H-23 | WP6 | 41–44 | 3 h | Qualificare recupero dopo nuova chat o interruzione | Riferimenti durevoli, nessuna fonte/run implicita |
| CSV-H-24 | WP6 | 44–46 | 2 h | Qualificare superfici su due client e confini THS | G6; checkpoint di ristima, E2E completo ancora WP7 |
| CSV-H-25 | WP7 | 46–47,5 | 1,5 h | Comporre coorte finale, CI e piano di rilascio del delta | Pin finali e regressioni giustificate |
| CSV-H-26 | WP7 | 47,5–49 | 1,5 h | Distribuire governatamente il solo delta finale | Immagini collaudate, nessun replay WP3 |
| CSV-H-27 | WP7 | 49–51 | 2 h | Eseguire nuovo CSV e reimport invariato sui client | DS1/DS1R, identità e revisioni coerenti |
| CSV-H-28 | WP7 | 51–53 | 2 h | Completare fault/revoca e secondo profilo Ente | Casi negativi e ENV-A/B nel livello previsto |
| CSV-H-29 | WP7 | 53–54,5 | 1,5 h | Consolidare dossier, guida utente e runbook | Prove per ogni requisito e limiti espliciti |
| CSV-H-30 | WP7 | 54,5–55 | 0,5 h | Registrare esito dell'accettazione e chiudere il miniprogetto | G7/M2 solo dopo accettazione HUMAN |

La sequenza nominale privilegia la chiusura del caso corrente prima delle estensioni CSV. La qualifica delle superfici client in WP6 non sostituisce l'esecuzione end-to-end sulla coorte finale in WP7. Il rilascio del delta WP5/WP6 è compreso in WP7, quindi non resta un'installazione finale fuori stima.

Le durate di WP3/WP7 comprendono preparazione, verifica e diagnosi: **non sono finestre di validità dell'autorità runtime**. Una singola azione firmata resta entro il proprio TTL/budget, incluso il profilo più stretto da 900 secondi quando applicabile. Il cronoprogramma non presume una sola authority valida per 55 ore, non divide artificiosamente un'azione per aggirare la scadenza e non autorizza rinnovi o reset.

### 15.4 Partecipazione HUMAN e punti di disponibilità

Le seguenti sono quote dell'impegno HUMAN aggiuntivo già stimato in 3–6 ore, non nuovi gate di approvazione del piano. L'autorizzazione allo sviluppo già concessa resta valida; si chiedono soltanto decisioni di dominio o autorità runtime richieste dal percorso vigente.

| Blocco | Finestra tecnica centrale di riferimento | Partecipazione HUMAN | Budget attivo aggiuntivo |
| --- | --- | --- | ---: |
| WP0/WP1 | H+0–3 | Chiarimenti su scelte aperte emerse dalla diagnosi, se necessari |0,25–0,5 h|
| WP2 | Prima di G2, circa H+11,5–14 | Esame della review concreta e dei nuovi effetti proposti, senza anticipare authority |0,25–0,5 h|
| WP3 | H+14–19 | Percorso autorizzativo pertinente e review/attivazione del profilo in THS |1–2 h|
| WP4 | H+22–24 | Verifica degli esiti F5/F6 e baseline conservata |0,25–0,5 h|
| WP5 | H+24–26 e prima di G5 | Scelte semantiche, vocabolari e regole dichiarate |0,5–1 h|
| WP6 | H+44–46 | Passaggi utente e rientro THS sui client qualificati |0,25–0,5 h|
| WP7 | Nuovo rilascio e H+53–55 | Decisioni previste per il delta finale e accettazione conclusiva |0,5–1 h|
| **Totale** | Distribuito lungo il progetto | **Decisioni e accettazione** |**3–6 h**|

Il budget non usato non si consuma per obbligo. La verifica tecnica svolta con l'agent è già conteggiata nelle 40–70 ore; qui si contabilizza soltanto la partecipazione distinta del responsabile HUMAN. La somma contabile delle due voci è 43–76 ore, con riferimento centrale 55+4,5=59,5 ore; **non è la durata di calendario**, perché disponibilità e attese seguono un altro asse.

### 15.5 Attese esterne e riordino consentito

| Punto | Possibile attesa | Lavoro indipendente ammesso | Vincolo |
| --- | --- | --- | --- |
| WP1/WP2/WP5/WP6/WP7 | CI/build o ambiente di test | Preparazione del prossimo delta con prerequisiti già soddisfatti | Il gate resta aperto fino all'esito qualificante |
| Dopo G2, prima/durante WP3 | Authority o disponibilità HUMAN | WP5 e attività WP6 indipendenti dal nuovo runtime | Nessuna operazione protetta per anticipare il gate |
| WP5 | Scelta/pubblicazione semantica | Prove negative, contratti e lavoro di superficie già definito | Nessuna semantica inventata per avanzare |
| WP6/WP7 | Secondo client o binding reale | Dossier, runbook e casi isolati ancora necessari | M2 non chiude con una fixture sostitutiva |
| Qualsiasi punto | STOP, drift o effetto incerto | Diagnosi e riconciliazione autorizzate sul contesto conservato | Nessun replay, nuovo login o reset automatico |

Se WP5/WP6 vengono anticipati durante un'attesa, si annota il nuovo ordine e si ricalcolano le ore cumulative di raggiungimento di M1/G5/G6. **Le 24 ore per M1 valgono per la sequenza di riferimento**: un M1 ritardato da lavoro anticipato non significa che quel lavoro debba essere ricontato. La somma dei WP non cambia, salvo nuovo effort motivato.

Le attese vanno misurate per inizio/fine e causa; sovrapposizioni fra CI, disponibilità HUMAN e altro lavoro si contano una sola volta nel calendario. Nessun promemoria, job pianificato o automazione operativa viene creato dal cronoprogramma.

### 15.6 Consuntivazione, forecast e conversione in giornate

Dopo ogni attività CSV-H-* registrare: stato, ore tecniche effettive, ore HUMAN distinte, gate/prove ottenuti, attese e causa, stima del residuo. Questi sono contatori di progetto: **non sostituiscono né modificano i budget runtime HUMAN/THS**.

Regola di aggiornamento: **effort totale previsto = effort tecnico già speso + nuova stima del lavoro rimanente**. Non riazzerare il consuntivo dopo STOP, cambio chat o nuova versione del piano. Ogni riga spesa ha un solo WP di imputazione; WP0 resta incluso in WP1. Il readback di un effetto completato non diventa un nuovo rollout.

La prima revisione del forecast avviene a G1, la seconda a G2, poi a G5/G6. Appena una voce supera il proprio limite alto o introduce un requisito nuovo, si registra scostamento/causa/impatto sui gate prima di proseguire con lavoro dipendente. Il superamento di una stima non concede nuove autorizzazioni e non riduce i test obbligatori.

Solo per tradurre lo scenario centrale in capacità giornaliera, senza attese:

| Capacità tecnica effettiva | M1: 24 ore | M2: 55 ore complessive |
| --- | ---: | ---: |
|4 h/giorno|6 giornate|14 giornate arrotondate|
|6 h/giorno|4 giornate|10 giornate arrotondate|
|8 h/giorno|3 giornate|7 giornate arrotondate|

Le precedenti indicazioni 3–5 giorni per M1 e 7–12 per M2 presuppongono circa 6–8 ore tecniche effettive al giorno e gate disponibili. Il calendario reale va fissato quando è nota la capacità di lavoro e sono disponibili le finestre HUMAN; non viene dedotto dall'orario di questa conversazione.

### 15.7 Versione e conservazione dei criteri

La versione 1.1 aggiunge il cronoprogramma e i campi di consuntivazione al registro. Conserva perimetro, 24 requisiti, 24 test, gate, stato 8/8–4/6 e intervalli 18–30/40–70 della versione 1.0. Nessun nuovo lavoro esecutivo è iniziato con questa revisione. Per questo aggiornamento sono stati riletti Blueprint 0.3 §§9–10 e Matrix 1.7 §1: la sequenza temporale non può precedere dipendenze obbligatorie o trasferire autorità fra owner.

## 16. Registro iniziale dei rischi e decisioni

| ID | Questione | Decisione/azione prevista | Effetto sulla chiusura |
| --- | --- | --- | --- |
| D01 | Autorità runtime scaduta | Sviluppo/documentazione ammessi; WP3 bloccato fino a gate esplicito valido | Nessuna data target garantita |
| D02 | Executor incompleto | Composizione e qualificaWP2 con riuso | BloccoG2/G3 |
| D03 | CI Ingestion/Deploy/MCP | DiagnosiWP1, non assumere tutti i rossi “solo test” | BloccoG1 se rilevante |
| D04 | Mapping attualeIDENTITY/string | DeltaWP5 con retrocompatibilità | M1 può chiudere;M2 no |
| D05 | Receipt picker temporanea | Qualificare recupero da owner; delta solo se manca | BloccoAT19 |
| D06 | Due client/binding reali | Fissare nomi/versioni/capacità prima del collaudo, almeno uno base | BloccoAT20 se indisponibili |
| D07 | Pubblicazione può acquisire | Effetto esplicito in review e provaammissione singola | BloccoAT08 |
| D08 | Secondo profilo Ente | Tutti i valori in profilo, testENV-A/B | BloccoAT21; non prova multi-host |
| D09 | Crescita scope storico | Merge canonico avanzato, ricerca evoluta e streaming restano registrati separatamente | Nessuna chiusura implicita |
| D10 | Vecchie prove su altre coorti | Analisi d'impatto e pin, regressioni mirate | Nessun PASS trasferito automaticamente |

## 17. Modalità di avanzamento e consegna

Durante l'esecuzione aggiornare questo registro con WP/gate corrente, tecniche8/8 e funzionaliN/6, risultato osservato, blocco effettivo e prossimo passo. Le percentuali non sostituiscono criteri di uscita.

Ogni checkpoint conserva un handoff con: head dei repository, immagine/contratti qualificati, test conclusi, journal/claim retained, ultimi esiti, budget/autorità come osservazioni datate, prossima azione esatta consentita. Mai copiare segreti o presentare una snapshot come authority.

Deliverable finali:
1. coorte candidata/rilasciata con pin e delta collegati ai requisiti;
2. evidenzeM1 eM2 con catalogo locale/canonico;
3. profiloCSV e profili installazione validati;
4. guida utente chat→THS→esito e ripresa;
5. runbook operatore per STOP/riconciliazione, distinto dal percorso utente;
6. stato delle estensioni fuori perimetro, senza lasciarle ambiguamente “completate”.

## 18. Prima azione della prossima sessione

Partire da **WP0/WP1**, non da un nuovo launcherVPS:
1. leggere questo documento, il registro strutturato e l'audit collegato;
2. verificare eventuali nuovihead e adottare gli originaliPET pertinenti;
3. diagnosticare/correggere i tre fallimentiCI con prove mirate;
4. chiudereG1 e passare alla composizioneWP2;
5. presentare una reviewruntime concreta solo quandoG2 è concluso e il percorsoHUMAN pertinente è disponibile.

Questo documento non avvia nuove acquisizioni, non rinnova authority e non cambia lo stato4/6. La prossima sessione aggiornerà il piano in base ai risultati, conservandone identificativi e cronologia delle revisioni.
