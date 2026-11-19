# OUF — riesame dei repository e stima del completamento CSV
20 ottobre 2026 · verifica documentale e sorgente · tecniche 8/8, funzionali 4/6

## Esito

La precedente stima di 16–30 giornate uomo sovrastimava il nuovo sviluppo: includeva capacità già implementate, testate e, in alcuni casi, già installate. L'audit del 17 ottobre presente nella PR39 aveva già prescritto questo riuso; non era confluito nella linea operativa attuale. L'assenza di un file o di una capability su main non prova l'assenza del lavoro sulle linee candidate.

**Nuova stima prospettica, già considerando un agent avanzato e lavoro sequenziale senza subagenti:**
- **18–30 ore di lavoro tecnico assistito** per completare l'executor, qualificare la coorte, effettuare il rollout governato, pubblicare il profilo e chiudere F5–F6 del caso corrente.
- **40–70 ore complessive**, comprendenti le precedenti, per il percorso CSV generale e ripetibile descritto sotto.
- Impegno attivo aggiuntivo del responsabile HUMAN/dominio: indicativamente **3–6 ore complessive**, distribuite tra decisioni semantiche, revisioni e accettazione. Non sono giornate di presidio continuativo.
- Ordine di grandezza del calendario: **3–5 giorni lavorativi** per il caso corrente; **7–12 giorni lavorativi complessivi** per il percorso generale, se accessi, revisioni HUMAN e ambienti sono disponibili. Sono finestre di pianificazione, non date garantite. Le attese di autorizzazione non hanno durata stimabile da questo audit.

Le ore indicano analisi, modifiche, revisione dei risultati e diagnosi condotte con l'agent; non ore di una persona che scrive manualmente tutto il codice. Non è stato misurato un fattore di produttività 10× o 20× sul progetto. Tale ipotesi può valere come scenario per alcuni delta di implementazione, ma non va applicata di nuovo a queste stime già assistite, né alle attese di CI, ai test temporali o alle decisioni HUMAN.

## Metodo e limiti

Consultati AGENTS nei sette repository, main e PR aperte, alberi ricorsivi non troncati ai commit selezionati, file sorgente/test/workflow/manifest, ricevute conservate e log CI esistenti. Approfonditi 44 file aggiuntivi oltre alle istruzioni, ai documenti e alle ricevute iniziali; letti gli stati di 69 run legati ai sette commit e sei log di job significativi. Non è una revisione integrale di ogni branch o riga di codice. Il precedente audit è usato come indice, non come sostituto della verifica dei sorgenti attuali.

Nessuna CI è stata rilanciata per questo audit. Nessun accesso protetto a OUF, SQL/Engine/Gateway sul target, login, refresh, rinnovo o reset. Non sono state rieseguite le installazioni o i readback conclusi. L'osservazione di GitHub è attuale; le attestazioni VPS sono storiche e conservano data e limiti propri.

Baseline originale allegata consultata: **Matrix1.7 §1; Blueprint0.3 §9; UDP PET1.3 §§4–4.1,11.1–12,20–20.1**. ACK durevole significa presa in carico persistita; non prova materializzazione conclusa. UDP conserva l'autorità su identità canonica, contributi e revisioni. Ingestion conserva esecuzione, handoff e watermark; MCP accompagna il percorso senza sostituire gli owner o THS.

| Repository | Commit approfondito | Significato |
| --- | --- | --- |
| ouf-semantic-registry | [eccef11a9736](https://github.com/GioNob/ouf-semantic-registry/tree/eccef11a97367f20e278db40b9ed6f45dd980c37) | Linea selezionata dalle evidenze di coorte/candidate |
| ouf-source-onboarding | [b0f5e3dacbe5](https://github.com/GioNob/ouf-source-onboarding/tree/b0f5e3dacbe59ebf87e22dd6af2575e41249f51d) | Linea selezionata dalle evidenze di coorte/candidate |
| ouf-ingestion-runtime | [0fe0de60c6d9](https://github.com/GioNob/ouf-ingestion-runtime/tree/0fe0de60c6d980fe97610acf195d4bfd46d3777f) | Candidato validate-only del rollout |
| ouf-udp-object-resolution | [0d40da05408a](https://github.com/GioNob/ouf-udp-object-resolution/tree/0d40da05408a14db31d4d41af2372d6a71480291) | Linea selezionata dalle evidenze di coorte/candidate |
| ouf-mcp-server | [1f2c28d7abad](https://github.com/GioNob/ouf-mcp-server/tree/1f2c28d7abadae78680b040ba7b58be62ef85ee9) | Linea selezionata dalle evidenze di coorte/candidate |
| ouf-api-gateway | [6bcb28906eee](https://github.com/GioNob/ouf-api-gateway/tree/6bcb28906eee08e0ebe3507b8b58dd987012c8e6) | Linea selezionata dalle evidenze di coorte/candidate |
| ouf-deploy | [ed2f2523555d](https://github.com/GioNob/ouf-deploy/tree/ed2f2523555d7023d7fc0a274fc6262327a33941) | Linea operativa di sviluppo |

I commit sono riferimenti di audit, non una nuova attestazione delle immagini attualmente in esecuzione. Le PR aperte e le linee di integrazione vanno riconciliate, preservando migrazioni e funzionalità; non sostituite con main indiscriminatamente.

## Ciò che è già disponibile

| Capacità | Evidenza di implementazione e test | Conseguenza sulla stima |
| --- | --- | --- |
| Upload, profiling e onboarding CSV dalla chat | ManagedFileMcpApiTest verifica ownership, identità delegata, stato limitato e DRAFT idempotente. ManagedTabularAdapterTest copre BOM, delimitatore, quoting, checkpoint, identità per chiave dopo riordino e chiavi duplicate. MCP ha upload/profile/preview/onboarding e ricevute. | Nessun nuovo sottosistema di acquisizione CSV. Restano prove sul client e varianti dichiarate. |
| Proposta, validazione e revisione semantica | [ProposalCommandService](https://github.com/GioNob/ouf-semantic-registry/blob/eccef11a97367f20e278db40b9ed6f45dd980c37/src/main/java/it/comune/trieste/ouf/semantic/application/ProposalCommandService.java) mantiene DRAFT, hash/versione, validazione verde, challenge HUMAN e ricevuta durevole. Registry, MCP e Gateway hanno test del canale. | Riusare Registry e THS. Separare il gap specifico dei vocabolari applicati ai valori. |
| Revisione generica delle proprietà sulla stessa fonte | [SourceRevisionService](https://github.com/GioNob/ouf-source-onboarding/blob/b0f5e3dacbe59ebf87e22dd6af2575e41249f51d/src/main/java/it/comune/trieste/ouf/onboarding/application/SourceRevisionService.java) clona solo la versione della stessa fonte, preserva il resto della configurazione, modifica regole selezionate e conserva commandKey. I test coprono concorrenza, risposta persa, drift, rollback e parent cambiato dopo approvazione. | Eliminare le 2–4 giornate precedentemente trattate come sviluppo del meccanismo. Rimangono configurazione, pubblicazione e collaudo del profilo concreto. |
| Mediazione MCP/Gateway della revisione | source_revision_test.go usa SDK MCP reale e verifica scoping, chiave stabile e trasporto TLS; il backend owner è una fixture dichiarata. test_source_revision.py esegue Lua, verifica ricevute, blocca attori/scope/path impropri e conserva le route preesistenti. | La superficie esiste; non va ricostruita. |
| Esecuzione e consegna durevole | RunExecutionWorker, CanonicalRecordPipeline, OutboxDispatcher e test PostgreSQL coprono bundle fissato, quarantena, drain, outbox, ACK, lease, checkpoint e watermark. | Nessuna nuova pipeline di ingestion. Restano integrazione e accettazione della coorte. |
| Identità esistente/nuova/ambigua | GovernedIdentityEngine e GovernedIdentityResolutionService sono collegati al PublishedResolutionLoop; non sono solo librerie isolate. ObjectResolutionService conserva il source binding e riconcilia handoff ripetuti. Test su scope, semantica, ambiguità e regole sufficienti esplicite. | Nessun nuovo motore di deduplicazione o riconciliazione d'identità. |
| Riconciliazione delle proprietà e commit | [LinkedPropertyReconciler](https://github.com/GioNob/ouf-udp-object-resolution/blob/0d40da05408a14db31d4d41af2372d6a71480291/src/main/java/it/comune/trieste/ouf/udp/LinkedPropertyReconciler.java) gestisce autorità, conflitti, contributi, multivalore e cancellazioni esplicite. LinkedPropertyRuntimeTest prova campi complementari, null/vuoti, originali/provenienza, conflitti circoscritti, storia e scelta HUMAN obsoleta. | Riusare motore e suite; pubblicare e provare le regole concrete. |
| Recupero e ripresa | HumanRecoveryBudgetRuntimeTest e MaterializationRecoveryRuntimeTest coprono budget/storia, concorrenza, worker obsoleti, input durevole, autorizzazione, pressione e impossibilità di ripetere decisioni canoniche concluse. | Eliminare lo sviluppo di un nuovo recovery engine. Qualificare il percorso completo e i punti d'integrazione. |
| Executor di deployment | Esistono NativePorts del precedente source-revision rollout, journal firmato, chiave, comparatori di replacement e namespace Gateway. | Il nuovo executor richiede adattamento e composizione qualificata, non sviluppo da zero. |

La [CI Onboarding39265859608](https://github.com/GioNob/ouf-source-onboarding/actions/runs/39265859608), sul commit selezionato, contiene **270 test modulo +10 SDK senza failure/error/skip**. La [CI proprietà UDP39077784466](https://github.com/GioNob/ouf-udp-object-resolution/actions/runs/39077784466) contiene **95 test mirati +10 SDK senza failure/error/skip**. Questi numeri vengono dai log, non dal solo nome dei workflow.

La [CI verticale38534866913](https://github.com/GioNob/ouf-ingestion-runtime/actions/runs/38534866913) è stata riletta e conserva **36 verifiche PASS**: quattro JVM owner reali, MCP reale, PostgreSQL e MinIO; proposta/revisione semantica, due fonti, match con oggetto esistente, nuovo oggetto, proprietà, tre ACK e lineage. Gateway/IAM/browser e trasporto iniziale sono fixture: non è una prova della coorte finale sul VPS o di due client reali.

Le ricevute già conservate provano inoltre:
- [F3:13 righe committate e13 oggetti distinti](https://github.com/GioNob/ouf-deploy/blob/ed2f2523555d7023d7fc0a274fc6262327a33941/docs/csv-functional-stage3-target-proof-20261018.json), con identità precedente conservata; il percorso ha richiesto un recupero governato e non prova ancora la continuità normale end-to-end.
- [F4:13 Teatri letti da MCP,20 proprietà ciascuno, risultato completo](https://github.com/GioNob/ouf-deploy/blob/ed2f2523555d7023d7fc0a274fc6262327a33941/evidence/csv-functional-stage4-chat-proof-20261018.json).
- [Installazione source revision completata](https://github.com/GioNob/ouf-deploy/blob/ed2f2523555d7023d7fc0a274fc6262327a33941/evidence/source-revision-native-update-completed-20261019.json), migrazione Onboarding34. Questa ricevuta operatore distingue esplicitamente installazione e pubblicazione: nativeProfilePublished=false.

## Residui reali

### 1. Qualifica della coorte: tre fallimenti da trattare

| Run verificato | Risultato concreto del log | Valutazione |
| --- | --- | --- |
| [Ingestion39380500855](https://github.com/GioNob/ouf-ingestion-runtime/actions/runs/39380500855) | 185 test,2 failure,1 error,2 skip. RunControlRuntimeTest raccoglie una schedule tenant-budget al posto di tenant-a, un'altra schedule inattesa e un bundle/source mismatch. | Codice del test privo di isolamento/cleanup e claim globale rendono plausibile interferenza fra fixture. È una diagnosi preliminare, non una correzione provata. La CI generale del candidato non è verde. |
| [MCP39232083000](https://github.com/GioNob/ouf-mcp-server/actions/runs/39232083000) | TestBudgetReserveP95Under25msLANProfileFixture: p95 circa73ms contro25ms. Lo stesso head ha un run push riuscito. | Variabilità prestazionale da diagnosticare nel profilo runner; non dimostra un guasto del CSV ma non va nascosta. |
| [Deploy39392193693](https://github.com/GioNob/ouf-deploy/actions/runs/39392193693) | Test di coerenza pacchetto/capsule fallito su tools/chatbot_file_cohort/human_session.py: hash sorgente e pin atteso diversi. | Riconciliare la chiusura storica del pacchetto. Non cambiare i pin consumati o ignorare il test per rendere verde il rilascio. |

Le qualifiche componenti già riuscite restano valide nel loro perimetro; non fanno diventare verde l'intera coorte.

### 2. Executor nativo residuo

[runner.py](https://github.com/GioNob/ouf-deploy/blob/ed2f2523555d7023d7fc0a274fc6262327a33941/tools/ingestion_rollout_execution/runner.py) dichiara e implementa Ports astratte. Mancano ancora la composizione completa di effetti nativi, controlli correnti HUMAN/Owner/DB, trasporto HTTP nel nuovo namespace Gateway, issuer del nuovo scope, chiusura immutabile e entrypoint qualificato.

Riusare il NativePorts precedente richiede adattamento: assume una rete per replacement e un Gateway già stabile; il rollout corrente cambia anche Gateway, ha endpoint espliciti e deve conservare autorità e canali di controllo durante il fermo. Non è sufficiente copiarlo o rinominarlo.

Tutti i MAC/IP/nomi rete/path/UID/domain/endpoint devono provenire dal profilo validato dell'Ente. Le osservazioni storiche restano selettori dell'installazione corrente, mai default riutilizzabili. La qualifica su due reti è già componente disponibile; una vera installazione distribuita su host distinti non è attestata da questa prova e richiederebbe un profilo di collaudo dedicato.

### 3. Semantica CSV: gap di implementazione circoscritto

Il [compilatore managed](https://github.com/GioNob/ouf-source-onboarding/blob/b0f5e3dacbe59ebf87e22dd6af2575e41249f51d/src/main/java/it/comune/trieste/ouf/onboarding/application/ManagedFileExecutionProposal.java) ammette1–32 campi, mapping IDENTITY, proprietà XSD string, vocabularyMappings vuoto/assente e relationshipMappings vuoto/assente. La [pipeline canonica](https://github.com/GioNob/ouf-ingestion-runtime/blob/0fe0de60c6d980fe97610acf195d4bfd46d3777f/src/main/java/it/comune/trieste/ouf/ingestion/CanonicalRecordPipeline.java) rifiuta transform diverso da IDENTITY.

Quindi mappare colonne a proprietà ontologiche è pronto; applicare un vocabolario ai valori, conservando codice originale, concetto/versione e gestione del valore sconosciuto, non è coperto nel percorso selezionato. È un delta reale su proposta, validazione, esecuzione e lineage. I motori di Registry e relazioni UDP esistono e vanno riusati. Non occorre inventare vocabolari per Teatri: collaudare quel ramo con una fixture separata.

Il CSV generale deve dichiarare tipi e limiti supportati, includendo i casi necessari al contratto di accettazione; non promettere qualsiasi CSV o qualsiasi trasformazione.

### 4. Superficie conversazionale, ripresa e portabilità

Il manifest selezionato espone upload/profiling, semantica, onboarding/revisioni, status/history e ricerche di oggetti. La lettura di un pacchetto di revisione identità esiste su MCP PR48 e Gateway PR55, ma non è nel manifest selezionato: recuperare il delta sulle linee correnti senza sostituirle con branch vecchie.

La ricevuta temporanea del picker in ManagedFileChatHandoff è in memoria con TTL30minuti, mentre l'asset è persistito. Questo non dimostra perdita del file; rende necessario qualificare il recupero del riferimento e il ritorno in una nuova conversazione senza dipendere dalla memoria del chatbot.

Prove ancora necessarie: client reale con IAM/Gateway reali, scadenza/revoca senza perdita di contesto, seconda acquisizione deliberata distinta da retry tecnico, due client indipendenti, un nuovo CSV e un secondo profilo di configurazione. La pubblicazione di una nuova versione può avviare acquisizione: SourceRevisionService lo espone già esplicitamente e richiede accettazione dell'effetto. Non aggiungere un secondo scheduler.

Correzione dell'handoff precedente: **ouf-admin è un riferimento di account routing**, non necessariamente il nome di un tool. L'inventario conservato lo registra e questa sessione espone26 definizioni OUF. Cercare solo un plugin/tool chiamato esattamente ouf-admin non prova che manchi il connettore. Inventario non significa autenticazione runtime corrente; qui non è stata verificata con chiamate protette. Resta separata l'assenza di un executor target qualificato in questa sessione.

## Piano di lavoro ed effort assistito

Stime formulate sul delta identificato, senza subagenti. Non includono riscritture dei componenti esistenti, nuovi login automatici o replay di lavori conclusi.

| Ordine | Risultato verificabile | Ore tecniche assistite |
| --- | --- | ---: |
| A | Riconciliare i tre fallimenti CI e fissare i pin della coorte; diagnosi e correzioni mirate, senza riscrivere storia/pacchetti consumati | 2–4 |
| B | Comporre NativePorts, nuovo scope/issuer/entrypoint, trasporti e test nativi mancanti riusando i componenti qualificati | 8–14 |
| C | Con autorità valida: ammissione DB corrente, rollout governato, readiness e profilo nativo pubblicato; sola nuova esecuzione autorizzata | 4–6 |
| D | F5–F6: seconda acquisizione deliberata dello stesso CSV; entrambe le run, ACK e commit UDP verificati, nessun duplicato,13 Teatri/20 proprietà e8 Cinema preservati | 4–6 |
| **A–D** | **Chiusura del caso corrente, funzionali6/6 quando provate** | **18–30** |
| E | Delta semantico CSV: vocabolari applicati ai valori, tipi/mapping dichiarati e relativi contratti/prove, riusando Registry e pipeline | 8–14 |
| F | Raccordare review e riepilogo degli esiti, recupero dopo nuova chat e percorso su due client; riusare PR e ricevute esistenti | 8–14 |
| G | Collaudo su nuovo CSV e profilo diverso, fault/revoca/ripresa mirati, coorte finale, guida breve e dossier di accettazione | 6–12 |
| **A–G** | **Percorso CSV completo e ripetibile nel perimetro dichiarato** | **40–70** |

Il margine dell'intervallo copre diagnosi, integrazione e correzioni ordinarie. Difetti strutturali nuovi, indisponibilità del target, modifica del criterio di accettazione o supporto multi-host completo richiedono una revisione esplicita; non ore aggiunte silenziosamente.

A e B costituiscono il prossimo punto di aggiornamento: dopo questi risultati si può restringere la stima usando il tempo effettivo e i difetti rimasti. E/F possono essere sviluppati mentre si attende una finestra HUMAN, continuando comunque in modo sequenziale nella sessione, senza subagenti o automazioni.

## Criterio di successo mantenuto

Un utente autorizzato, da un chatbot compatibile e senza terminale/SQL nel percorso ordinario:
1. carica un CSV e ottiene asset/profilo validati con limiti e anomalie comprensibili;
2. propone e conferma i mapping semantici, inclusi i vocabolari dove necessari, mediante i passaggi HUMAN/THS previsti;
3. completa onboarding e acquisizione della versione approvata, con intenzione e conseguenze esplicite;
4. ottiene riconciliazione con oggetti UDP esistenti o creazione di nuovi; ambiguità e conflitti restano revisionabili con evidenze;
5. vede esiti persistiti, revisioni e provenienza fino a riga/run/contratto, distinguendo ACK da commit;
6. ripete il file senza duplicazioni, riprende dopo interruzione/cambio chat e conserva gli oggetti preesistenti;
7. ripete lo stesso percorso su un nuovo CSV e su due client qualificati, senza valori specifici dell'Ente incorporati nel codice.

Le ricerche di verifica e la lettura degli esiti fanno parte dell'accettazione. Nuove modalità di ricerca per prossimità/affinità, formati aggiuntivi, verticali API e streaming GIS restano successivi. La fusione di due oggetti canonici preesistenti è un'operazione distinta dal match di una riga: non si può dichiararla provata dal test linked-existing. Le eventuali prove grafo/merge del piano esteso del17 ottobre restano tracciate separatamente e non vengono marcate PASS dalla chiusura F5–F6.

## Stato e contesti conservati

Tecniche8/8, funzionali4/6. Owner7 e projection7 consumati e completi. Ultimo HUMAN278/288 con10 tentativi residui, finestra già scaduta; nessuna autorità corrente dedotta dal contatore. Pacchetto conservato qfcpqd9f, nessuna pubblicazione nativa del profilo o ammissione DB finale provata da questo audit. Gli STOP si riconciliano senza replay.

I risultati di questo documento sono pianificazione e diagnosi: non una modifica runtime, una nuova autorizzazione o un avanzamento delle milestone.
