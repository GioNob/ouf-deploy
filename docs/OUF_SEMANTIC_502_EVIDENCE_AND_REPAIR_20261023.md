# 502 semantico OUF — evidenze e riparazione circoscritta

Aggiornamento del 23 ottobre 2026. Il 502 resta aperto. Il difetto di disponibilità documentato è la route semantica diretta al Registry esaminato, fermo e privo di endpoint di rete. Il recupero deve ripristinare quel servizio e verificare la stessa richiesta del consumer. La progettazione del Supervisor e i risultati dei test dei componenti non costituiscono una riparazione del target.

## Esito operativo e limiti delle evidenze

Le ricevute dell'operatore documentano una configurazione Gateway invariata e un upstream indisponibile. Lo shutdown Docker/containerd/host è corroborato nell'intervallo dell'arresto del Registry. La restart policy osservata è `no`; inoltre l'entrypoint attende un segnale USR1 prima di avviare Java. Sono quindi documentati un servizio rimasto fermo e un percorso di avvio che richiede un'ammissione distinta dal semplice avvio del container.

Non sono dimostrati l'attore che ha iniziato lo shutdown, la correlazione della singola richiesta fallita con la specifica riga di errore Gateway, né il successo funzionale dopo un recupero. La conclusione sostenuta è **difetto di disponibilità del target della route, con recupero dopo riavvio non completato**. Non si dichiara chiusa la causalità end-to-end né risolto il 502.

Una successiva chiamata corrente a `ouf.system.status`, sul collegamento `ouf-admin`, ha restituito `HEALTHY` per la superficie pubblica MCP. Questa osservazione riguarda MCP: non attesta lo stato del Registry, il suo endpoint, l'ammissione IAM/DB o la GET semantica. Non aggiorna implicitamente le osservazioni storiche del target descritte sotto.

Una sola successiva chiamata corrente a `semantic.get`, sullo stesso collegamento `ouf-admin` e con gli esatti pin Teatri conservati, ha restituito `context deadline exceeded`, `retryable=false` e codice connector `INVALID_ARGUMENT`. Non è stato restituito uno status HTTP 502: il raggiungimento del Registry non è stabilito e questa non è la richiesta originale con identità Ingestion SERVICE. Non sono stati eseguiti retry o cambi di account. Entrambe le osservazioni sono registrate in `evidence/semantic-502-reinvestigation-20261023.json`.

Il branch remoto della PR 43 è stato verificato al commit `1b5a22b4f2415325b3c8ba1bed00245434d1ed4a`; è stata verificata la corrispondenza di `AGENTS.md`, non l'integrità dell'intero albero locale. Questa verifica di provenienza non prova lo stato del VPS. Le evidenze Docker non stabiliscono un'ownership Kubernetes corrente dei workload; il nuovo PET del Supervisor non dimostra che tale architettura sia installata sul target.

## Catena delle osservazioni

Tutti gli orari seguenti sono UTC. Le ricevute Registry, route e owner sono output forniti dall'operatore, con provenienza `OWNER_PASTED_*` o equivalente: non sono letture indipendenti effettuate da questa sessione. I file storici successivamente materializzati dal repository restano evidenze del loro momento di raccolta; non diventano osservazioni correnti del VPS.

| Passaggio | Evidenza | Significato e limite |
| --- | --- | --- |
| Richiesta semantica fallita | `evidence/native-profile-postpatch-http-target-20261022.json`; log `/home/oufadmin/ouf-postpatch-diagnostic.9Hzuuniq/operator.log` | Il 22 ottobre GET configurazione e compatibilità 200 alle 13:13:21Z precedono GET semantica 502 alle 13:13:24.196119097Z e readiness/review 503. La receipt è fornita dall'operatore; il duplicato incollato resta una sola esecuzione. |
| Errore di trasporto nello stesso intervallo | Stessa receipt postpatch | Un `NO_ROUTE_TO_HOST` è riportato nel Gateway. La vicinanza temporale non prova da sola che sia la riga della medesima GET semantica. |
| Registry fermo | `evidence/semantic-historical-registry-observation-target-20261022.json` | Container esatto terminato il 18 ottobre alle 08:09:50.772426142Z, exit 143, nessun OOM, nessun processo, restart count 0. Log vuoto non equivale a salute. |
| Route live invariata verso il target assente | `evidence/semantic-live-route-target-20261022.json` | La mappa completa di 82 route corrisponde a quella conservata; la route semantica usa indirizzo e porta del Registry esaminato; zero endpoint occupano la destinazione. Non è una nuova esecuzione della richiesta data plane. |
| Shutdown corroborato | `evidence/semantic-stop-journal-target-20261023.json` | Docker stopping alle 08:09:50.160621Z e termination request alle 08:09:50.160746Z precedono il termine del Registry. Seguono menzioni dell'ID esatto, shutdown Docker, stop containerd e servizio di shutdown host. L'attore iniziale rimane sconosciuto. |
| Gate applicativo osservato | `evidence/semantic-registry-recovery-proposal-target-20261022.json` e `tools/semantic_registry_recovery_proposal/prepare.py` | `gatedFileOnlyLaunchObserved=true`. Il compilatore verifica entrypoint esatto, comando Java, file-only flags e restart policy `no` prima di produrre la ricevuta. Non emette autorità di recupero. |
| Owner di credenziali osservati non ammissibili | `evidence/semantic-registry-owner-discovery-target-20261023.json` | Tutti i 18 candidati osservati sono CANCELLED/BLOCKED, di un boot precedente, senza finestra token positiva. Nessun owner corrente è selezionato; altri owner fuori dalla ricerca limitata non sono esclusi. |

Il container Registry esatto è:

`790c62742c92eabc095d4ab22f2070e0c40a41e4a219685a7d8120e4661e4e5d`

I log principali delle ricevute sono:

- `/home/oufadmin/ouf-semantic-history.Sg7fpZoS/operator.log`
- `/home/oufadmin/ouf-live-route.ZP4fQDib/operator.log`
- `/home/oufadmin/ouf-stop-cause.u6qJqIMi/operator.log`
- `/home/oufadmin/ouf-registry-proposal.gEjCBGSF/operator.log`
- `/home/oufadmin/ouf-registry-owner-discovery.NKae4nGd/operator.log`

Ulteriori file storici sono stati materializzati dal medesimo commit e letti in questo audit:

- `evidence/post-boot-runtime-reconciliation-20261018.json` riporta UDP terminato alle 08:09:50.930047249Z, circa 158 ms dopo il Registry, e il recupero Docker dell'host. Non dimostra un avvio del Registry.
- `evidence/boot-journal-recovery-stopped-target-20261018.json` conserva una lettura storica di boot/uptime: 16:24:14Z meno 28.978 secondi corrisponde a circa 08:21:16Z; containerd risulta attivo dalle 08:21:22Z. Il documento registra inoltre uno specifico precedente blocco del guard, non uno stato live attuale.
- `evidence/host-network-reconciliation-target-complete-20261018.json` conserva la receipt dell'operatore per le correzioni di rete; `applicationReadinessProven=false` e `independentRootJournalReadbackPerformed=false` restano espliciti.
- `evidence/post-host-network-native-read-target-20261018.json` registra la lettura storica del workflow 39158332027, job 117766143548: readiness di MCP, Onboarding e UDP, non del Registry. `rootJournalReadbackProven=false` non viene reinterpretato.

La sequenza è coerente con un Registry non ripristinato insieme agli altri servizi; non identifica l'attore dello shutdown e non prova lo stato corrente del target.

## Perché il percorso esistente si blocca

Il gate osservato esegue una shell in attesa di USR1; soltanto dopo il segnale esegue:

```text
java -XX:MaxRAMPercentage=75 -jar /app/application.jar
```

Un semplice `docker start` non dimostra pertanto l'avvio della JVM. Un segnale storico, una vecchia firma o il PID precedente non possono ammettere una nuova generazione.

La verifica del codice locale mostra che `NativePorts.gates()` richiama `CurrentAdmission.prerequisites()` prima dell'avvio. Questa chiama `guard_lease()`, che richiede owner ACTIVE, boot corrente e finestra token residua valida. Gli owner osservati non soddisfano tali condizioni.

L'audit sorgente conservato in `docs/handoffs/OUF_SEMANTIC_REGISTRY_POSTBOOT_OWNER_BLOCKER_20261023.md` documenta inoltre che i vecchi profili governed/legacy vincolano il worker al boot della prima receipt e richiedono l'esatta generazione Registry già running. Le vecchie continuazioni conservano quel boot. Combinare tali profili con un recupero che pretende un owner già attivo prima dello start crea una dipendenza circolare. Nuove firme da sole non la correggono.

Questa è una limitazione concreta della composizione esistente. La correzione deve distinguere l'avvio del processo in attesa, con Java bloccata, dall'ammissione applicativa corrente. Non deve falsificare boot, expiry o stato dei vecchi journal.

### Il token serve alla funzionalità autorizzata e non al solo avvio della JVM

L'analisi primaria del codice Registry al commit `eccef11a97367f20e278db40b9ed6f45dd980c37` distingue ulteriormente i due livelli. Nel modulo vendorizzato `vendor/authorization-sdk/src/main/java/it/comune/trieste/ouf/authorization/`:

- `AuthorizationAutoConfiguration.java` crea un runtime senza snapshot quando manca un bundle-file; attiva `ActiveBundleRefresher` quando è configurato il registry-url.
- `ActiveBundleRefresher.java` usa il bearer letto dal token-file per acquisire il bundle; verifica il contenuto prima dell'installazione. `refreshSafely` intercetta gli errori senza arrestare la JVM; il file temporaneo di download viene eliminato.
- `LocalAuthorization.java` conserva lo snapshot in un'`AtomicReference` senza ripristino persistente implicito. `currentSnapshot`/`requireFresh` rifiutano bundle assente (`NO_POLICY_BUNDLE`) o oltre max-staleness (`STALE_POLICY_BUNDLE`). `ServletAuthorization.java` usa quello snapshot per la valutazione.
- Nel Registry, `src/main/java/it/comune/trieste/ouf/semantic/api/SemanticAuthorizationBoundary.java` protegge `/api/semantic/v1/**`; `ValidationApi.java` associa `/references:resolve` alla capability `ouf.semantic.read`. Il profilo `application-file-first.yml` disabilita schema-gov/discovery, non l'Authorization.

Il risultato è che l'avvio del processo non garantisce una policy applicativa fresca. Se manca una policy ammissibile, la richiesta protetta viene negata invece di essere resa permissiva. Questo sarebbe un ulteriore blocco funzionale dopo il ripristino del backend; **non è la causa dimostrata del 502 storico**.

La receipt `evidence/chatbot-semantic-policy-binding-target-20261016.json` osserva sul target storico registry-url/token-file espliciti, refresh 30 secondi e max-staleness 300 secondi. Riporta però anche `SPRING_CONFIG_IMPORT`, `loadedSnapshotProven=false` ed `effectivePolicyProven=false`. L'assenza di un riferimento statico esplicito non esclude un override importato: non è provato un bundle alternativo fresco né è stata riletta la configurazione effettiva corrente.

Lo script `scripts/check-file-cohort-startup.py`, nel commit deploy `1b5a22b4f2415325b3c8ba1bed00245434d1ed4a`, è progettato per una fixture disposable con token `DISPOSABLE_NOT_ADMITTED`, senza `OUF_AUTHORIZATION_REGISTRY_URL`, e verifica `/actuator/health`; dichiara `policyTokenAdmissionProven=false`. La sola lettura dello script non prova l'esecuzione di un test e non autorizza placeholder sul target. Non dimostra che la GET protetta funzioni senza policy valida.

Il source lock `releases/chatbot-file-cohort-20261014.json` registra il riferimento sorgente esaminato. Non costituisce una nuova attestazione della corrispondenza dell'immagine attualmente installata. La verifica corrente di credenziale e policy deve quindi restare parte del recupero funzionale, senza consentire bundle stale o disabilitare Authorization.

Riferimenti verificati nel codice locale:

- `tools/semantic_registry_recovery_execution/native.py`: sequenza e prerequisiti prima degli effetti.
- `tools/semantic_registry_recovery_execution/admission.py`: verifica del token-owner prima dei prerequisiti nativi.
- `tools/semantic_registry_recovery_execution/installed_owner.py`: selezione esatta, guard del boot e della finestra token; nessuna scansione o nuova acquisizione implicita.
- `tools/semantic_registry_recovery_execution/factory.py`: binding del contesto corrente e dei materiali storici; nessuna emissione di autorità.
- `tools/semantic_registry_recovery_execution/semantic_request.py`: verifica funzionale finale del caller originale.

## Richiesta funzionale da ripetere dopo la riparazione

Il consumer è l'Ingestion SERVICE esistente. Il codice di riferimento è `GioNob/ouf-ingestion-runtime` al commit `4165b9e149be467d5d7c6bed35e4e1af4e249db1`, con `PublicationGatewayClient.java`, `FrozenConfigurationProbe.java` e `PublishedActivation.java`, come registrato nell'handoff del percorso nativo.

```text
GET /api/semantic/v1/references:resolve
    ?semanticId=<riferimento esatto>
    &revisionId=<revisione esatta>
    &publicationSetId=<publication set esatto>
```

Origine Gateway e token-file devono corrispondere alla configurazione corrente del caller, rispettivamente `OUF_INGESTION_ACTIVATION_GATEWAY_URL` e `OUF_INGESTION_ACTIVATION_TOKEN_FILE`. La verifica usa la stessa identità SERVICE; un token HUMAN amministrativo non è un sostituto equivalente.

I parametri devono provenire dalle `semanticReferenceBindings` della configurazione congelata, con checksum verificato. La risposta attesa è HTTP 200 con `semantic_id`, `semantic_version`, `revision_id`, `publication_set_id` esatti e `status=ACTIVE`, secondo il contratto del caller conservato. Si verificano tutti i riferimenti della configurazione, senza risolverli verso latest o un'altra pubblicazione.

Il roadmap conserva i seguenti pin, utili per il confronto ma non sostitutivi di una verifica corrente:

| Campo | Valore conservato |
| --- | --- |
| Source | `teatri-csv-6609b245` |
| Onboarding version | `c9fec43c-19b3-4ffb-9111-781bc347c5b0` |
| Configuration hash | `sha256:b13c5fe234168bdb8b315087917bccfe428ceaa8e136ed1c0f56f5bf43deed3d` |
| Semantic ID | `https://api.ouf-lab.it/semantic/teatri#TeatriOntology` |
| Semantic version | `1.0.0` |
| Revision ID | `a1db3912-2b72-42eb-af88-a775fcd0e2ab` |
| Publication set ID | `9fe7d1ee-9e13-40bc-ad50-53e36ea0076b` |

La verifica è una GET dedicata: non richiama activation, readiness orchestration o altri flussi che possano avviare acquisizioni e operazioni di dominio. Health 200 del Registry o HEALTHY di MCP non sostituiscono questa prova.

## Riparazione circoscritta e prossimo input

Non occorre attendere l'implementazione di OUF Supervisor, una migrazione Kubernetes o il completamento dell'intera suite end-to-end della piattaforma. Occorre completare e qualificare il percorso minimo di recupero del Registry e la verifica funzionale sopra descritta.

Il prossimo input mancante è il **binding esatto fra Registry, montaggio della credenziale, installazione del relativo token-owner e lineage dei suoi journal**. Nessuno dei candidati osservati può essere scelto per nome, data più recente o valore massimo del contatore. Non viene chiesto nuovamente all'utente di conoscere il gestore token.

Il nuovo reader `scripts/read-registry-bound-owner-lineage-20261023.py` ricostruisce tale binding dai riferimenti privati esatti già conservati e dai quattro file di metadati di ciascuno dei 18 candidati noti. Verifica gli hash del bundle e della review, la relazione fra mount Registry e output dell'owner e i collegamenti fra predecessori fino al primo grant controllato. Non stampa credenziali, non rilancia vecchi reader, non esegue scansioni o modifica journal. Ambiguità, ramificazioni, antenati mancanti o deriva producono STOP; nessun contatore massimo viene usato come criterio di selezione. Restituisce una lineage storica circoscritta, non un owner attuale o un budget approvato. Sono passati 15 test locali senza skip e la revisione statica indipendente; CI dedicata e lettura di ritorno dei sorgenti immutabili sono ancora in corso. Non è stato eseguito sul target. Specifica: `docs/handoffs/OUF_REGISTRY_BOUND_OWNER_LINEAGE_READMESPEC_20261023.md`.

La sequenza di riparazione da completare è:

1. **Vincolare gli input.** Verificare la catena Registry/mount/owner/lineage e raccogliere il contesto corrente indispensabile, compreso il caller Ingestion e la configurazione congelata. Conservare ogni claim e contatore precedente.
2. **Avviare soltanto il gate nuovo.** Ammettere un processo in attesa, mantenendo Java e gli effetti applicativi bloccati. Registrare durevolmente il tentativo e osservare la nuova generazione reale; un esito incerto richiede riconciliazione prima di altri effetti.
3. **Stabilire il token-owner del boot corrente.** Usare un profilo esplicito che conservi la lineage verificata e la contabilità cumulativa, senza dipendere dall'endpoint applicativo Registry già pronto. Un journal CANCELLED o scaduto resta storico; non viene riscritto per apparire attivo.
4. **Verificare l'ammissione nativa completa.** Con il gate nella fase prevista, verificare OCI, immagine, rootfs completo, mount, configurazione, rete, database e credenziale corrente secondo i profili esatti. Il precedente processo JVM non fornisce un'eccezione al seal del nuovo processo. Eventuale drift richiede una correzione specifica e rivedibile, non cleanup implicito.
5. **Rilasciare la stessa generazione.** Attestare il processo ammesso, completare separatamente unpause e rilascio USR1 del gate con il relativo journal. Verificare che la JVM attesa sia avviata e che la policy applicativa necessaria sia caricata e fresca. Nessun riuso di segnale, PID o attestazione precedente; health UP da solo non prova AUTHZ readiness.
6. **Verificare la richiesta originale.** Confermare che la route raggiunga l'endpoint della generazione ammessa e ottenere la risposta esatta alla GET autenticata dell'Ingestion. Soltanto questa prova permette di dichiarare risolto il 502 nel percorso interessato.

Il lavoro immediato è il collector e la composizione di questa sequenza concreta, non una nuova serie di inventari generici. I test necessari devono qualificare i cambiamenti e i punti di crash di tale percorso; i conteggi di test superati non saranno riportati come recupero del servizio.

Le receipt disponibili non autorizzano a riutilizzare vecchie autorità scadute, a resettare budget o ad acquisire token implicitamente. La storia HUMAN 304/304 e i contatori dei service grant sono distinti; il massimo 319 osservato fra i candidati non è una lineage selezionata né un nuovo plafond. L'eventuale acquisizione necessaria deve essere parte del percorso concreto, con la propria autorità corrente, prima di qualunque richiesta all'issuer.

## Input e canale target già individuati

| Materiale | Percorso e integrità conservati |
| --- | --- |
| Contesto patch completata | `/etc/ouf/deploy-snapshots/ingestion-readiness-stage8-execution-e1c13776c158064f9e1012a4993a409b459ae0711a77486dc59f7dd7a722ce92` |
| Proposta Registry | `/etc/ouf/deploy-snapshots/semantic-registry-recovery-proposal-a14asgjz/proposal.json`; SHA256 `8b1cce8a68003a5c54778f0b61bd92ecb16532d72d1d7eb5510719b857d89624` |
| Input storici riconciliati | `/etc/ouf/deploy-snapshots/semantic-registry-history-capture-r5cc0fjv/inputs.json`; SHA256 `8facd750a673d25c14bfc1a58c8c0ae28d63d8a5ce487ab956b8f2b23dc902c9` |
| Composizione conservata | `/etc/ouf/deploy-snapshots/semantic-registry-recovery-composition-2pygojyp/composition.json`; SHA256 `65717005bcbcd03c342832193cabb5f23160583972635337159a0e5334de7e81` |

I percorsi provengono dalle receipt e dai case locali; i file privati sul VPS non sono stati letti da questo audit. Costituiscono riferimenti per la raccolta mirata, non autorità runtime.

Il terminale dell'operatore `oufadmin@v2202609421511523101` è il canale target già stabilito. Gli handoff citano workflow self-hosted, ma non attestano una sessione o un executor di riparazione attualmente utilizzabile. Non risulta stabilito un accesso SSH diretto da questa sessione. Nessun comando di riparazione viene dichiarato eseguito.

## Regole di continuità

Il primo checkpoint corrente di `AGENTS.md` prevale sulle sezioni storiche dei documenti. Il reader dello stop-journal e la discovery degli owner sono già completati: i vecchi «next command» che li propongono non sono più operativi.

Si conservano tutti i dossier, log, claim e stati incerti. Non sono parte della riparazione una riscrittura delle route Gateway, il ripristino di provider non coinvolti, una nuova activation della source o il replay di operazioni già completate. L'attuale evidence non indica una necessità di cambiare il riferimento semantico o la pubblicazione.

Rimangono distinti lo stato della patch tecnica, la riparazione del 502 e l'accettazione funzionale del progetto. Le ultime evidenze conservate riportano patch 12/12, fasi tecniche 8/8, milestone funzionali 4/6 e G3 aperto; questo audit non modifica tali esiti e non dichiara release acceptance.

## Riferimenti normativi e di implementazione

- **Cross Module Alignment Matrix v1.7, §1**: Registry proprietario delle semantiche e dei riferimenti storici; Ingestion proprietario dell'esecuzione versionata; Gateway proprietario del routing; Authorization e THS mantengono le rispettive autorità.
- **Semantic Model Registry PET v1.3, §§150.1–150.2**: riferimenti e PublicationSet esatti, retention e assenza di fallback verso ACTIVE/latest corrente.
- **Registry PET v1.3, §160.6**: consumer attraverso Gateway, identità autenticata ed enforcement applicativo; nessun bypass di rete.
- **Registry PET v1.3, §160.7**: SERVICE_IDENTITY e binding IAM correnti; nessuna identità implicita dalla rete.
- **Registry PET v1.3, §160.15**: readiness locale, ammissione autorizzativa, binding Gateway e risoluzione dei riferimenti sono verifiche distinte; provider esterno indisponibile non rende indisponibile tutto il patrimonio già adottato.
- `docs/handoffs/OUF_SEMANTIC_REGISTRY_POSTBOOT_OWNER_BLOCKER_20261023.md`: blocco della composizione postboot e limiti della discovery.
- `docs/handoffs/OUF_SEMANTIC_REGISTRY_NATIVE_PATH_20261023.md`: caller originale, componenti nativi e limiti della loro qualificazione.
- `docs/handoffs/OUF_SEMANTIC_REGISTRY_INSTALLED_OWNER_20261023.md`: observer e installer finito; nessuna selezione implicita dell'owner o prova dell'intero recupero target.

Questo aggiornamento consolida la diagnosi e il percorso di correzione. Non esegue operazioni sul VPS, non emette autorità e non dichiara nuova salute del Registry.
