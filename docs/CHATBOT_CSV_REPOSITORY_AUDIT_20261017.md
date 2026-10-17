# OUF — audit di riuso del percorso CSV da chat
17 ottobre 2026 · evidenze repository e CI · nessuna operazione runtime

## Esito e regola di pianificazione

Il percorso non parte da zero. Sono già presenti upload/profiling, proposta e revisione semantica, onboarding con THS condivisa, attivazione tramite readiness reale, publication poller, handoff durevole, identità, materializzazione, ricerca MCP, relazioni e recovery. Una CI con processo MCP reale qualifica già gran parte della catena. Il residuo è integrazione delle linee esistenti, configurazione/pubblicazione, correzioni puntuali e accettazione target. Non trasformare un requisito di accettazione in una nuova implementazione.

Questo audit rettifica la versione1.0 del [piano CSV](CHATBOT_CSV_END_TO_END_PLAN_20261017.md), mantenendo R0–R10 e i criteri finali. Prima di ogni modifica: individuare owner, codice/test esistente, branch/PR pertinente e stato installato; implementare solo il delta non coperto.

## Perimetro e limiti della verifica

Inventari GitHub di branch e PR, alberi ricorsivi non troncati e letture mirate di codice, test, documenti ed evidenze nei sette repository seguenti. Gli inventari sono completi nelle pagine restituite (<100 elementi ciascuna); non equivalgono a una revisione di ogni file o di tutte le 441 branch. Sono stati approfonditi i percorsi rilevanti alla richiesta e le linee candidate/di integrazione, oltre a main.

| Repository | Branch / PR inventariate | Commit del codice approfondito |
| --- | --- | --- |
| ouf-deploy | 44 / 39 | [a5a7271a4ddb](https://github.com/GioNob/ouf-deploy/tree/a5a7271a4ddb349a3c086ccd2d13afd3a6569157) |
| ouf-mcp-server | 81 / 69 | [f00e7e3bfcae](https://github.com/GioNob/ouf-mcp-server/tree/f00e7e3bfcaee9272b9b6d204a7fa3ea79a563a4) |
| ouf-source-onboarding | 67 / 45 | [b8b2eb23e36e](https://github.com/GioNob/ouf-source-onboarding/tree/b8b2eb23e36ea3166012edf84fb8c1fc3441dfca) |
| ouf-semantic-registry | 49 / 40 | [eccef11a9736](https://github.com/GioNob/ouf-semantic-registry/tree/eccef11a97367f20e278db40b9ed6f45dd980c37) |
| ouf-ingestion-runtime | 53 / 42 | [f869d8b86b89](https://github.com/GioNob/ouf-ingestion-runtime/tree/f869d8b86b892a0c03c147dac9bb40cd5f873ff2) |
| ouf-udp-object-resolution | 55 / 43 | [e66e6df0833a](https://github.com/GioNob/ouf-udp-object-resolution/tree/e66e6df0833a872f15170eb46a43f85e50dd859b) |
| ouf-api-gateway | 92 / 77 | [425a0377c278](https://github.com/GioNob/ouf-api-gateway/tree/425a0377c278ff52e00ce962ffd24809ee66f2e5) |

I commit sopra sono riferimenti di audit, **non una nuova attestazione della coorte installata**. UDP e Onboarding includono le correzioni XSD candidate, ancora da installare. Deploy integra le evidenze pregresse e ha le PR38/39 separate. Una PR aperta non significa che il suo codice sia assente dal VPS: i rilasci precedenti hanno usato anche linee candidate. Viceversa un merge su main non dimostra installazione. I documenti FILE_LOOP/FILE_FIRST già registrano regressioni di continuità fra main e linee rilasciate: preservare migrazioni, funzionalità e pin esatti.

## Evidenza integrata già disponibile

La [CI R4a real MCP managed CSV vertical, run38534866913](https://github.com/GioNob/ouf-ingestion-runtime/actions/runs/38534866913) è conclusa SUCCESS. Il job five-process-vertical115755187540 stampa un summary PASS con **36 verifiche**. Sono stati letti stato, passi e summary del log, non soltanto il titolo del workflow.

Il run è associato all'head PR41 `98e33a16839e9253b37bf74f37e77cc20dc938e7`; il summary dichiara il checkout Ingestion `272e715ed80fc22f20e53bd816a37e06dbcfa0d2`. I pin degli altri moduli sono conservati nell'[evidenza sintetica dell'audit](../evidence/chatbot-csv-reuse-audit-20261017.json). La [PR41](https://github.com/GioNob/ouf-ingestion-runtime/pull/41) è già unita.

La prova esegue proposta ontologica, validazione, revisione HUMAN via HTTP, pubblicazione e lettura semantica; crea e prepara due fonti tramite MCP, riconcilia la ripetizione dello stesso comando, attiva con compatibilità di tutte le righe e copertura d'identità. Materializza un oggetto iniziale e poi due righe in ingresso: una collegata all'oggetto esistente, una nuova. Verifica identità conservata, nuova revisione, nuova proprietà, tre handoff con ACK durevoli e hash coerenti, ricerca MCP dei due oggetti, codice lessicale con zero iniziale, omissione di fatti riservati e lineage di entrambe le fonti.

**Limiti espliciti:** quattro JVM owner reali, MCP reale, PostgreSQL e MinIO; Gateway, IAM, autenticazione browser e trasporto iniziale del CSV sono fixture dichiarate. Non prova i13record sul VPS, il picker in ogni chatbot, la riconciliazione V35 con il nuovo profilo, un merge di due oggetti preesistenti, la seconda acquisizione dello stesso CSV né l'accettazione da due client. La parola “merge” nel nome del passo CI non estende queste asserzioni.

Riusare [workflow](https://github.com/GioNob/ouf-ingestion-runtime/blob/f869d8b86b892a0c03c147dac9bb40cd5f873ff2/.github/workflows/r4a-chatbot-vertical.yml), [test integrato](https://github.com/GioNob/ouf-ingestion-runtime/blob/f869d8b86b892a0c03c147dac9bb40cd5f873ff2/pairwise/r4a_chatbot_vertical.py) e [contratto della prova](https://github.com/GioNob/ouf-ingestion-runtime/blob/f869d8b86b892a0c03c147dac9bb40cd5f873ff2/docs/R4A_REAL_MCP_VERTICAL.md). Aggiornare i pin e aggiungere solo le asserzioni mancanti quando il codice cambia; non creare una seconda pipeline equivalente.

## Matrice del riuso e del residuo

| Piano | Base già presente | Residuo concreto |
| --- | --- | --- |
| R0 | Runner ouf-deploy, verifiche continuità, rollout/readback, pacchetto XSD qualificato PR38/UDP44/Onboarding45 | Integrare senza regressioni; installare correzione; leggere configurazione completa e stato target in un controllo coerente |
| R1 | Manifest MCP, scope Gateway/owner, ricevute durevoli, read source/proposal e operatività persistente | Qualificare discovery per client/principal reali; raccordare i riferimenti e la ripresa; recuperare le proiezioni già sviluppate sulle branch pertinenti |
| R2 | Picker OUF, staging/hash/ownership, profiling/preview, DRAFT idempotente; Cinema e Teatri già caricati | Testare portabilità, errori di parsing e identità tra versioni contro le suite esistenti; nessun nuovo upload del caso storico |
| R3 | Registry, ricerca/lettura, ontologie native/Turtle limitato, revisione/pubblicazione e receipt | Diagnosticare il403 specifico; completare applicazione dei vocabolari ai valori nel percorso CSV, oggi limitato a IDENTITY |
| R4 | Motore proprietà generico, preview/evidence, V35 installata; preparatore18test e proposta20regole | Verificare vincoli e configurazione completa; installare XSD, pubblicare nativamente e leggere il profilo; non riscrivere riconciliatore |
| R5 | Onboarding clone/validate/approve/activate, stato fonte DISABLED, feed publication, one-shot e schedule | Qualificare la composizione del controllo fonte esistente, incluse race/lease e nuova publicationId; estendere solo se insufficiente |
| R6 | Parser/pipeline, bundle fissato, outbox/ACK/checkpoint; catena già qualificata | Readback e rendiconto target per riga, proiezione conversazionale e sole lacune di test |
| R7 | Identità governata, review package UDP, confronto selettivo THS, commit/provenance e motore proprietà | Integrare esposizione MCP/Gateway già proposta; collaudare profilo attivo e conflitti. Le11decisioni restano consumate |
| R8 | Nodi/edge UDP, materializzatore relazioni, query autorizzate; MCP related_search e object.search | Qualificare mapping e navigazione sul target/client; aggiungere proiezioni solo se le letture necessarie non sono coperte |
| R9 | PAUSE/RESUME/ABORT, quarantena, budget durevoli, fencing, incidenti/stato/storia MCP | Provare seconda acquisizione deliberata, restart/ripresa da nuova chat e conservazione baseline; nessun nuovo recovery engine |
| R10 | Harness integrato e prove owner/contratto | Accettazione su endpoint installato con due client indipendenti, identità/Gateway reali e dossier dei risultati |

## Dettagli che impediscono duplicazioni

### Upload e revisione nativa

Il [contratto intake CSV](https://github.com/GioNob/ouf-source-onboarding/blob/b8b2eb23e36ea3166012edf84fb8c1fc3441dfca/docs/R4A_MANAGED_CSV_INTAKE.md) e il [picker Gateway](https://github.com/GioNob/ouf-api-gateway/blob/425a0377c278ff52e00ce962ffd24809ee66f2e5/docs/R4A_FIRST_PARTY_FILE_PICKER.md) documentano il percorso già realizzato. Non reintrodurre il recupero di URL arbitrari di allegati host. La [continuità VPS](https://github.com/GioNob/ouf-deploy/blob/a5a7271a4ddb349a3c086ccd2d13afd3a6569157/releases/FILE_LOOP_VPS_CONTINUITY_20261010.md) registra gli8Cinema materializzati e il profiling Teatri riuscito; le evidenze successive avanzano Teatri oltre quel punto.

La [revisione managed](https://github.com/GioNob/ouf-source-onboarding/blob/b8b2eb23e36ea3166012edf84fb8c1fc3441dfca/docs/MANAGED_ONBOARDING_REVIEW.md) riusa la sessione `ouf-ths`, PKCE/CSRF e le superfici semantica/onboarding/resolution. Prepare/read hanno ricevute durevoli; approvazione e attivazione restano azioni HUMAN distinte. Readiness usa parser reale e attesta compatibilità, poi il gate UDP e il publication poller. Sono già presenti lease, budget finiti e riconciliazione degli esiti ambigui. Non aggiungere un secondo sistema di login, workflow o approvazione.

### Semantica e vocabolari: restringere il gap

[Continuità Registry file-first](https://github.com/GioNob/ouf-semantic-registry/blob/eccef11a97367f20e278db40b9ed6f45dd980c37/docs/FILE_FIRST_CANDIDATE_COHERENCE_20261014.md): ricerca interna, exact read, DRAFT e pubblicazione esistono; i worker di discovery esterna sono intenzionalmente disabilitati nel profilo file-first. Non confondere questa scelta con assenza del Registry.

Il [compilatore della proposta CSV](https://github.com/GioNob/ouf-source-onboarding/blob/b8b2eb23e36ea3166012edf84fb8c1fc3441dfca/src/main/java/it/comune/trieste/ouf/onboarding/application/ManagedFileExecutionProposal.java) ammette1–32campi, transform IDENTITY e vocabularyMappings vuoto/assente. La [pipeline canonica](https://github.com/GioNob/ouf-ingestion-runtime/blob/f869d8b86b892a0c03c147dac9bb40cd5f873ff2/src/main/java/it/comune/trieste/ouf/ingestion/CanonicalRecordPipeline.java) rifiuta trasformazioni diverse da IDENTITY. Quindi il mapping colonna→proprietà è realizzato, mentre l'applicazione codice→concetto nel percorso managed non è coperta da questa implementazione. Riusare artefatti/vocabolari e contratti del Registry; estendere coerentemente proposta, validazione, esecuzione e lineage, senza dedurre equivalenze da etichette.

Questo è un requisito dell'end-to-end ampliato, non un motivo per azzerare F1 né inventare un vocabolario Teatri. Una fixture separata può esercitarlo.

### Pubblicazione senza acquisizione involontaria

Non manca lo scheduler. Esistono:
- [PATCH source con ETag e autorità HUMAN](https://github.com/GioNob/ouf-source-onboarding/blob/b8b2eb23e36ea3166012edf84fb8c1fc3441dfca/src/main/java/it/comune/trieste/ouf/onboarding/api/OnboardingApi.java), [persistenza dello stato](https://github.com/GioNob/ouf-source-onboarding/blob/b8b2eb23e36ea3166012edf84fb8c1fc3441dfca/src/main/java/it/comune/trieste/ouf/onboarding/application/OnboardingService.java);
- [feed pubblicazioni con sourceStatus corrente](https://github.com/GioNob/ouf-source-onboarding/blob/b8b2eb23e36ea3166012edf84fb8c1fc3441dfca/src/main/java/it/comune/trieste/ouf/onboarding/api/RuntimePublicationApi.java);
- [decode DISABLED→enabled=false](https://github.com/GioNob/ouf-ingestion-runtime/blob/f869d8b86b892a0c03c147dac9bb40cd5f873ff2/src/main/java/it/comune/trieste/ouf/ingestion/PublishedActivation.java) e [reconcile schedule](https://github.com/GioNob/ouf-ingestion-runtime/blob/f869d8b86b892a0c03c147dac9bb40cd5f873ff2/src/main/java/it/comune/trieste/ouf/ingestion/ActivationRepository.java);
- [test lease, snapshot e budget](https://github.com/GioNob/ouf-ingestion-runtime/blob/f869d8b86b892a0c03c147dac9bb40cd5f873ff2/src/test/java/it/comune/trieste/ouf/ingestion/ActivationLeaseRuntimeTest.java).

R5 deve prima verificare se questa composizione soddisfa il requisito: disabilitazione governata della sola fonte, evidenza della cessata ammissione e assenza/gestione di claim attivi, nuova pubblicazione mantenendo la fonte disabilitata, persistenza dopo poll/restart e rilascio esplicito per una sola acquisizione deliberata. Non è una procedura già autorizzata o provata sul target. In particolare il reconcile rispetta lease attive e la riabilitazione con nuova publicationId può rendere dovuto il file.

La pausa di una **run** già avviata non equivale al blocco preventivo di una **fonte**. Il codice conserva alcune schedule PAUSED, ma questa sola condizione SQL non prova un'interfaccia completa di hold. Aggiungere un nuovo meccanismo solo dopo un test negativo del controllo esistente e una descrizione precisa del requisito che manca.

### Revisioni d'identità: recuperare il lavoro su branch

La [PR MCP48](https://github.com/GioNob/ouf-mcp-server/pull/48), head `d7d5330d2b2588b3f896ea23e2c47e19b7b905a1`, implementa `resolution.issue.read`, schema e test, con [contratto del review package](https://github.com/GioNob/ouf-mcp-server/blob/d7d5330d2b2588b3f896ea23e2c47e19b7b905a1/docs/RESOLUTION_REVIEW_PACKAGE.md). La [PR Gateway55](https://github.com/GioNob/ouf-api-gateway/pull/55), head `b368284b3f6a7675863f85eeafc42d67bf9187dc`, contiene la capability corrispondente. Sono aperte e la capability non compare nel manifest della linea MCP `f00e7e3` esaminata.

Il confronto GitHub fra quella linea e MCP48 risulta diverged,11commit avanti/267indietro: **non sostituire la linea attuale con la vecchia branch**. Riconciliare il delta con i contratti owner oggi installati, le nuove comparazioni e i budget; preservare source review, semantica e operatività. La presenza di PR aperte è lavoro recuperabile, non prova di installazione né giustificazione per riscrivere tutto.

UDP42/Onboarding43 e la riconciliazione proprietà già confluita in quelle linee vanno preservati. Le11decisioni completate e la quarantena scelta non devono essere usate come input da rieseguire per provare la nuova esposizione.

### Grafo e recovery

Il [motore relazionale UDP](https://github.com/GioNob/ouf-udp-object-resolution/blob/e66e6df0833a872f15170eb46a43f85e50dd859b/docs/R2E_GEOPACKAGE_RELATIONSHIPS.md) consuma mapping/versioni pubblicate e gestisce target tardivo, ambiguità, idempotenza e storia. I nomi GeoPackage/camera-cabinet identificano il collaudo; non giustificano un motore applicativo separato per CSV o Teatri.

Il [manifest MCP](https://github.com/GioNob/ouf-mcp-server/blob/f00e7e3bfcaee9272b9b6d204a7fa3ea79a563a4/internal/manifest/capabilities.json) contiene già `urban.object.related_search` e `urban.object.search`; [Gateway related_search](https://github.com/GioNob/ouf-api-gateway/blob/425a0377c278ff52e00ce962ffd24809ee66f2e5/ouf-config/capabilities/urban.object.related_search.yaml) dichiara la capability. Il residuo riguarda copertura precisa, autorizzazione/discovery reali e accettazione del percorso, non l'invenzione di un primo tool grafo.

[RunLifecycleService](https://github.com/GioNob/ouf-ingestion-runtime/blob/f869d8b86b892a0c03c147dac9bb40cd5f873ff2/src/main/java/it/comune/trieste/ouf/ingestion/RunLifecycleService.java) implementa PAUSE/RESUME/ABORT con controllo versione. La [policy di recovery HUMAN implementata](https://github.com/GioNob/ouf-ingestion-runtime/blob/f869d8b86b892a0c03c147dac9bb40cd5f873ff2/docs/HUMAN_RECOVERY_BUDGET_V1.md) conserva budget e storia. Il manifest comprende ingestion.status/history e operations.incidents/explain/summary. Qualificare la ripresa dal client e l'isolamento; non creare nuovi registri paralleli.

## Collegamento delle prove al piano di accettazione

| Prove del piano | Riutilizzo prima di aggiungere test |
| --- | --- |
| PLAN-CSV-01/02/03/04/07 | Manifest/kernel, picker/profiler, managed review e test identità esistenti; completare client reali e varianti non coperte |
| PLAN-CSV-05/06 | Registry proposal/read/review e fixture semantica R4a; nuova copertura necessaria per vocabolari applicati ai valori |
| PLAN-CSV-08 | PublishedActivation, ActivationLease, AutomaticActivation; aggiungere scenario completo disabled→nuova pubblicazione→restart→riabilitazione con lease concorrente |
| PLAN-CSV-09/10/16 | R4a36check, identity runtime e serving; readback target distinto e aggiornamento pin |
| PLAN-CSV-11 | Verificare suite merge owner: R4a linked-existing non prova fusione di due oggetti esistenti |
| PLAN-CSV-12/13/14 | LinkedPropertyReconcilerTest/RuntimeTest e compatibilità XSD già qualificata; collaudo del profilo pubblicato |
| PLAN-CSV-15/19 | RelationshipMaterializer/PublishedRelationshipBinding/GraphQuery e suite serving; navigazione da client reale |
| PLAN-CSV-17/18/20/21/22 | Recovery/fencing, replay intent/handoff, continuità VPS e operatività MCP; seconda run dello stesso CSV e cambio client ancora da provare |

La matrice indica copertura da riusare, non dichiara PASS tutti questi criteri. Non rilanciare tutte le CI solo per documentare questo audit: sono stati letti run esistenti; nuove esecuzioni seguono modifiche effettive o lacune precise.

## Ordine del completamento corretto

1. Conservare baseline PET/spec, prove e dati esistenti; chiudere l'integrazione delle linee qualificate e la correzione XSD.
2. Riconciliare esposizione MCP/Gateway già sviluppata e diagnosi del403; preparare insieme le letture target necessarie.
3. Completare proposta20regole e qualificare il controllo nativo della fonte prima della pubblicazione. Nessuna acquisizione storica implicita.
4. Pubblicare solo nel percorso nativo governato, quindi provare il comportamento delle proprietà e consolidare rendiconto/query sul target.
5. Completare i delta generici dell'obiettivo ampliato: vocabolari nel CSV, proiezioni eventualmente mancanti, navigazione/revisione. Riusare gli owner.
6. Estendere l'harness esistente alle lacune e qualificare la coorte finale, poi seconda acquisizione deliberata, baseline Cinema e due client.

Resta **tecniche8/8; funzionali2/6**. L'audit non installa, non pubblica profili, non riprende job e non cambia decisioni d'identità. Il readback corrente conserva20reconciliation null; le prove CI non lo sostituiscono.
