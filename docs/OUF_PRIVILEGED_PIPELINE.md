# Cutover A2 del Semantic

Il workflow manuale governa il cutover A2 27→28 e i rilasci Semantic successivi con `release=next`. Ogni transazione identifica il proprio predecessore tramite CID. Il plan effettivo identifica l’installazione. La riuscita dell’andata richiede una ricevuta della firma, l’upgrade, lo start R3, un ingresso `VERIFIED`, Java PID 1, readiness HTTP 200 con `status=UP`, sonda C e worker abilitato nel frame verificato. L’owner riferisce A2 completato nel run 44882047892 e la testa 29 raggiunta nel run 44909669060.

## Migrazione online del database Semantic

Il 21 novembre l’operatore ha osservato la testa R3 29 con Flyway disabilitato, storia a V12 e immagine fino a V16. Per il recupero usare il solo dispatch manuale `Semantic database migration`. Il plan legge il profilo della testa R3 e il JAR del processo Semantic vivo, verifica nomi e SHA-256 con il manifest dello ZIP fissato nel profilo e confronta la storia PostgreSQL in sola lettura. Il riepilogo identifica testa, digest approvabile, file pendenti e CRC32 Flyway. Per il caso osservato sono attese V13–V16.

L’unica approvazione è sul job `apply` dell’environment `ouf-vps-privileged`. Ogni script prende un lock sulla tabella di storia, ricontrolla OID e prefisso, esegue SQL e inserisce la riga Flyway nella stessa transazione. Il timeout del lock è 5 secondi e quello dello statement 60 secondi. Un errore conserva le versioni già committate. Dopo un’interruzione, un nuovo dispatch legge la storia e presenta il residuo per una nuova approvazione. L’apply ricostruisce la ricevuta di uno script già committato dal claim e dalla riga esatta. La verifica conclusiva richiede l’intera storia, HTTP 200 con stato `UP` e la stessa generazione di PID 1 sulla stessa testa.

**Domande aperte per il profilo privato.** Claude deve inserire la sezione facoltativa `semanticDatabase` con i seguenti valori prima dell’installazione dell’esecutore aggiornato.

| Campo | Valore da inserire |
|---|---|
| `postgresCid` | CID completo a 64 cifre esadecimali del PostgreSQL identificato da `queue.container`, lo stesso di `modules.<modulo>.migration.flyway.postgresCid` |
| `socket` | Directory del socket Unix PostgreSQL **dentro il container**, da confermare con `queue.socket` e il binding del modulo |
| `user` | `ouf_semantic` |
| `database` | `ouf_semantic` |
| `schema` | `ouf_sem` |

Conservare nell’inbox lo ZIP originale del profilo che identifica l’immagine viva (`nextSuccessorImage` per la 29). I valori d’ambiente restano nel perimetro privato dell’esecutore.

## Rilascio Semantic dalla testa 28

Per il task-09 selezionare `release=next`, `direction=forward`. La forma precedente del mandato rimane il default `a2`. Il plan controlla la catena 1…28, la ricevuta terminale del forward A2, il CID corrente, il profilo installato nel supervisore e il frame della linea C con worker acceso. La sonda preflight usa gli input dell’emissione 28 dal run che l’ha completata.

Aggiungere al profilo privato `nextSuccessorImage` con gli stessi campi di `successorImage`. Servono i pin del PR Semantic task-09, workflow, commit e tree provati, run e tentativo CI, ID artefatto, SHA-256 dello ZIP originale, image ID, nome immagine, schema manifest, inbox e campo Flyway. `predecessorMigrations` deve riprodurre l’inventario completo dell’immagine A2 ammessa. Il trasporto pubblico di esempio fissa ancora il PR 49. Chi prepara lo ZIP per il task-09 deve usare le coordinate revisionate del nuovo publisher. L’esecutore verifica di nuovo CI, ZIP, manifest, immagine e inventario prima del fermo.

Il dispatch non chiede `confirm_no_return`. Per `release=next` l’esecutore verifica tutti e cinque i runbook del ritorno prima del fermo e della firma: se manca un binding o un digest non coincide, il forward si ferma. Il profilo storico a 13 binding rimane valido per A2, non abilita questo forward. Apply conserva la linea C in `<retainedName>-v28`; il CID storico A2 resta in `retainedName`. La review Flyway del delta (V14 per il task-09) precede sign e USR1.

**Profilo privato.** Per ogni chiave in tabella inserire `artifactCommit`, `sourceCommit` e `sha256`. `artifactCommit` è lo SHA Git completo del commit revisionato che contiene il rispettivo file: Claude lo completa dopo il commit di 10b. Non usare `HEAD`, un branch o lo SHA del sorgente come sostituto. Per tutte le righe `sourceCommit` è il `C=` del runbook: `c58515e8d4567742fc9dad988b4871966ce49563`. Gli SHA-256 si riferiscono ai blob Git LF, non al checkout CRLF. L’installatore verifica i blob dal clone locale e aggiunge `path` al profilo installato.

| Chiave in `runbooks` | File in `ops/vps/` | `sha256` |
|---|---|---|
| `issue-30` | `r3-issue-v30.sh` | `8f6da4c76baf0fcdd9ec7ca356076f087512b68434c47c790f40ea4e74d04564` |
| `upgrade-30` | `r3-upgrade-v30.sh` | `e465df555805ca0b5edeac8bc6885bf41b7c767a176b7c74a2b533969276e53b` |
| `start-30` | `r3-operate.sh` | `5c1da7b2c8d1c37cc2a83e612faf38b70645e09b67830860355c62d5a99326f6` |
| `stop-30` | `r3-operate.sh` | `5c1da7b2c8d1c37cc2a83e612faf38b70645e09b67830860355c62d5a99326f6` |
| `probe-30` | `c-probe.sh` | `5287ef8a820ef8c1216c29e65ed7ff0a8612d729473db1d757bd4fd06570ca70` |

**Ritorno.** Selezionare `release=next`, `direction=return` in un nuovo dispatch. Prima della firma di 29 si torna al CID della linea C sulla testa 28 senza firmare. Dopo la firma di 29 si conserva il Semantic nuovo fermo, si ricollega lo stesso CID della linea C e si firma la 30 per il suo profilo. Se la 29 è firmata ma non installata, l’upgrade 29 viene prima riconciliato con il piano e gli input dell’emittente. La 30 richiede upgrade, start, ingresso verificato, USR1, readiness e sonda sugli input della **30**, con worker acceso. Questo è un ritorno applicativo, non un downgrade del database: compatibilità della linea C con V14 e qualifica nativa restano da verificare. Non cancellare claim né rigiocare comandi ambigui: riprendere con un nuovo dispatch di ritorno e nuove review.

L’esecutore richiede tutte le coppie payload/firma dalla 1 alla testa e una testa coperta dal profilo installato. L’installatore richiede ruoli contigui dalla 27 per start, stop e probe e dalla 28 per issue e upgrade, fino alla versione massima del profilo. Verifica i blob e i pin per ciascun ruolo. L’autorità R3 ammette fino a 256 emissioni. La composizione continua a usare l’overlay e gli input di rinnovo v27. Operate e sonda C leggono la testa autenticata.

**Journal e interruzioni.** Il forward concluso salva i due puntatori in `<run>/closed-forward` e pubblica `completed-forward`. La rimozione dei puntatori attivi termina con `forward-stage`. Un nuovo dispatch completa una chiusura interrotta, anche per un successo A2 prodotto dalla 17u. L’archivio conserva la provenienza per proof e ritorno. La transazione nuova pubblica i propri puntatori all’apply. Se il ritorno si interrompe durante il ricollegamento, il plan identifica i CID e le reti residue e l’apply completa i collegamenti mancanti. Prima della CREATE, una ricevuta di stop e il frame del CID identificano il distacco da completare. Un claim CREATE con esito privo di CID resta HELD. Al gate la ripresa riusa il CID registrato e richiede le review del nuovo run. Dopo la firma, un nuovo forward confronta il payload 29, lo stage approvato, la generazione e i claim. Per upgrade, start e sonda recupera anche un `result.json` dell’owner con stato e digest attesi. In presenza di un claim USR1 serve Java nella stessa generazione. La ripresa verifica readiness, ingresso e sonda senza un altro segnale. Effetti ambigui privi di riscontro restano HELD.

## Rilascio Semantic dalla testa 29

Per il forward 29→30 del task-16 usare `release=next`, `direction=forward`. Nel profilo privato fissare in `nextSuccessorImage` le coordinate CI e lo ZIP dell’immagine corretta. Impostare `predecessorMigrations` all’inventario completo dell’immagine rilasciata sulla 29. Il plan verifica il journal del forward concluso sulla 29, il relativo CID, il profilo del supervisore e l’immagine del container in esecuzione. La sonda preflight usa gli input del run che ha emesso la 29.

Aggiungere queste cinque voci ai 18 binding fino alla 30. Per ogni voce impostare `sourceCommit` a `c58515e8d4567742fc9dad988b4871966ce49563` e `artifactCommit` allo SHA Git completo del commit revisionato che contiene il file. Per i due nuovi wrapper l’`artifactCommit` sarà disponibile dopo il commit del task-17. I digest si riferiscono ai blob LF.

| Chiave in `runbooks` | File in `ops/vps/` | `sha256` |
|---|---|---|
| `issue-31` | `r3-issue-v31.sh` | `424bb1588dd7e543264f17d8599273ee17e05f9191f46e11ab3cf799199e9ccc` |
| `upgrade-31` | `r3-upgrade-v31.sh` | `2ea6239a2b80bd1f32813c171b83305a8e63595620f1db57e52517c60c7c3532` |
| `start-31` | `r3-operate.sh` | `5c1da7b2c8d1c37cc2a83e612faf38b70645e09b67830860355c62d5a99326f6` |
| `stop-31` | `r3-operate.sh` | `5c1da7b2c8d1c37cc2a83e612faf38b70645e09b67830860355c62d5a99326f6` |
| `probe-31` | `c-probe.sh` | `5287ef8a820ef8c1216c29e65ed7ff0a8612d729473db1d757bd4fd06570ca70` |

Il forward verifica i cinque binding della 31 al plan, prima del fermo e prima della firma. Conserva il CID della 29 in `<retainedName>-v29`. Per il ritorno usare `release=next`, `direction=return`. Prima della firma della 30 si ripristina il predecessore sulla 29. Dopo la firma si riconcilia l’eventuale upgrade 30 pendente, si ricollega lo stesso CID e si emette la 31 per il suo profilo. Upgrade, start e sonda qualificano la 31 con il worker acceso. Le migrazioni del database restano applicate.

### Domande aperte

Una coppia stabile `issue`/`upgrade` potrebbe ricevere dal piano approvato la sequenza richiesta, il digest della testa autenticata e il manifest dei sorgenti fissati. Al plan e all’apply l’emittente verificherebbe `sequenza = testa + 1` e il digest del predecessore. La sequenza determinerebbe i percorsi di stato e di output. L’upgrade consumerebbe gli input e la ricevuta della stessa emissione. Resta da decidere come esprimere nel profilo l’intervallo autorizzato per ciascun manifest. Questa proposta riguarda un task successivo.

## Mandato e approvazione

Claude configura `ouf-vps-privileged` con il reviewer umano, il ref di distribuzione protetto e le restrizioni di deployment. Il profilo di root fissa repository, commit, ref, ID dell’environment e ID dei reviewer individuali ammessi. La concorrenza di Actions serializza i dispatch. Un secondo lock, locale all’installazione, serializza le chiamate all’esecutore.

1. Avviare `Semantic A2 cutover` sul ref approvato. Scegliere `forward` o `return` e la decisione sulla coda. Il job `intent` calcola l’impronta del mandato senza accedere all’host privilegiato. Confrontare l’impronta del riepilogo con quella nel nome del job `plan`. Il plan parte automaticamente sul runner VPS dopo il dispatch. Per autorizzare `apply`, `migrate`, `sign` e `proof`, scegliere **Review deployments → Approve and deploy** sull’environment protetto (D-074, 20 novembre 2026). Il commento è facoltativo.
2. Leggere il riepilogo del plan e confrontare commit, verso, impronta e inventario con la decisione operativa. Il registro privato contiene tenant e requestId. Nel riepilogo pubblico ogni coppia è rappresentata da SHA-256 del JSON canonico ASCII `[tenant,requestId]`, accompagnata da stato, tentativi, generazione del claim e scadenze. Il JSON usa separatori compatti, chiavi ordinate e nessuna terminazione di riga. Con `empty` il plan esige coda vuota. Con `inventory` l’apply autorizza tutte le righe esatte del plan. Se una riga va trattenuta, lasciare in attesa la review. Una coda cambiata o un claim in corso impediscono il rilascio. Approvare il job `apply` con l’impronta pubblicata da `plan`.
3. Il job `apply` conserva il vecchio CID, verifica il successore avviato al cancello e prepara l’emissione. Il nome del job `sign` contiene il **planSha256 effettivo dell’emittente**. Questa review autorizza la firma e le operazioni successive vincolate al payload, al profilo e alla generazione registrata. Nel ritorno su testa 27 compare invece il digest della preparazione al rilascio del vecchio CID. In quel caso il percorso salta l’emissione.
4. Il job `sign` pubblica la ricevuta del cutover. Per predisporre la verifica della linea B nello stesso run, scegliere `worker_proof=true` al dispatch forward. Dopo la disponibilità della discovery autorizzata, inviare dal chatbot la richiesta MCP concordata, verificare l’idempotenza e leggere status e candidates. La review separata di `proof` riporta l’impronta della ricevuta di cutover. Il job legge il riscontro persistito da PostgreSQL e salva una propria ricevuta. Un timeout della prova lascia valido il cutover completato. Con il valore predefinito il workflow termina a `sign`.

Il token temporaneo viaggia su stdin. Root interroga direttamente l’API HTTPS GitHub all’origine fissa. Verifica il run in corso, il primo tentativo, l’evento, il file workflow, repository di origine, branch protetto e HEAD. Anche per il plan verifica nome, ID e regola dei reviewer dell’environment, con almeno un utente ammesso dal profilo. Per le sole fasi soggette ad approvazione legge le review da `actions/runs/{id}/approvals`. Conta le review con stato `approved` per ID e nome dell’environment, espresse da utenti umani presenti sia tra i reviewer dell’environment sia in `reviewerIds` del profilo. Ignora il testo del commento. Il job usa permessi in lettura su contents, actions e deployments. Un token senza visibilità sufficiente produce un diniego. Il token vive solo nel processo.

Per una run `queued` o `in_progress`, root consulta anche `actions/runs/{id}/attempts/1/jobs`. Il job deve risultare `in_progress`, avere il nome `<fase> <digest>` del mandato ed essere assegnato al runner GitHub indicato nel profilo. Una run `completed` viene rifiutata prima di accedere al journal.

Sotto il lock dell’entrypoint, il plan riserva una nuova directory di run e inizializza a zero il contatore. Il digest del mandato lega richiesta, ID dell’environment e campo `approval` con valore `none`. Per ogni fase protetta l’esecutore legge le approvazioni già consumate in `/opt/ouf-a2/state/<run>/approvals`. La fase protetta deve essere nuova e il conteggio delle review qualificanti deve superare di uno il numero di fasi registrate. Prima di eseguire la fase, l’esecutore aggiunge il nome al journal con pubblicazione atomica e sincronizza file e directory con `fsync`. L’impronta restituita lega mandato, environment, indice progressivo dell’approvazione e insieme ordinato degli ID dei reviewer qualificanti. La fase resta consumata anche se l’esecuzione si interrompe o il controllo del digest precedente fallisce. Ogni nuovo dispatch ha un contatore indipendente. Se la directory di un run esiste già e manca il journal delle approvazioni, l’esecutore rifiuta di inizializzare il contatore per quel run.

### Effetti dei quattro plan (D-074, punto 2)

Tutti e quattro i workflow partono solo con `workflow_dispatch`. Il plan usa il runner VPS e conserva nel journal privato l’impronta del mandato e il piano da confrontare all’apply.

| Plan | Letture e preparazione |
|---|---|
| Onboarding | Verifica lo ZIP e la provenienza, osserva container, PID 1 e readiness. Calcola la richiesta di creazione del successore. L’importazione dell’immagine e il fermo iniziano in `apply`. |
| MCP | Esegue le stesse verifiche e legge storia Flyway e schema PostgreSQL. Il ritorno da `READY` passa dal job protetto `rollback`. |
| UDP e Ingestion | Il plan fissa il database del modulo e la storia Flyway. Dopo la CREATE, il job apply presenta il delta del JAR per la review di migrate. |
| Gateway | Verifica il bundle, legge le risorse APISIX con GET e calcola creazioni, aggiornamenti e risorse invariate. Le scritture APISIX appartengono ai job protetti `apply` e `return`. |
| Semantic A2 | Osserva coda, generazione e ingresso. Invoca i runbook in modalità `plan`, che prepara fotografie e stato privato. Se il profilo forward prevede un’immagine successore, ne verifica i byte e la carica nello store Docker. Questi effetti additivi lasciano invariate la configurazione viva e i container in esercizio. Anche nel verso di ritorno il fermo e il ricollegamento richiedono `apply`. |

## Installazione e aggiornamento in sito

Il pacchetto di consegna comprende un clone dedicato di root con gli oggetti Git delle revisioni approvate e un JSON privato del profilo in modalità 0600. Servono Linux con pidfd, Python di sistema 3.11+, Docker CLI, psql nel container PostgreSQL, nsenter, Git, sudo/visudo e i prerequisiti dei runbook fissati. La directory del clone e i suoi antenati devono essere protetti dalle scritture del runner. Prima dell’aggiornamento portare il checkout e il campo `commit` del profilo alla revisione approvata. Se il nome del runner nelle impostazioni GitHub Actions differisce dall’account Unix `runner`, impostare `runnerName` nel profilo. L’installatore verifica il proprio blob Git e legge i file da consegnare dai commit fissati.

```sh
sudo /usr/bin/python3 -I -B scripts/install-ouf-a2.py plan "$A2_PROFILE"
sudo /usr/bin/python3 -I -B scripts/install-ouf-a2.py apply "$A2_PROFILE" --plan-sha256 '<planSha256>'
```

Eseguire i comandi dalla radice del clone. Per il primo aggiornamento da un esecutore precedente, attendere la fine dei job privilegiati e tenere sospesi i nuovi dispatch durante l’apply. Leggere per ogni file l’azione e i campi `before` e `after` con SHA-256 e modo Unix. Il valore `null` indica un file assente. Sostituire `<planSha256>` nel secondo comando con il digest del plan appena esaminato. In caso di `INSTALL_PLAN_DRIFT`, rileggere il plan e verificare la differenza. Per l’installazione interattiva, `bootstrap "$A2_PROFILE"` chiede il digest e segue la stessa procedura.

L’apply ricalcola il plan sotto lock e valida la regola sudoers candidata con `visudo` prima della prima sostituzione. Pubblica ogni file da un temporaneo sincronizzato nella sua directory e sostituisce sudoers per ultima. In caso di errore durante la pubblicazione ripristina i file già modificati. Il primo aggiornamento registra i percorsi consegnati in `/opt/ouf-a2/managed-files.json`. I successivi plan dichiarano `delete` per i percorsi registrati e poi ritirati da `lib` o `books`. Lo stato delle run, i contatori, `gateway-head` e i journal dei moduli restano nella loro sede.

La regola installata è `<runner> ALL=(root) NOPASSWD: NOSETENV: /usr/local/sbin/ouf-a2 ""`. Le virgolette vuote limitano sudo all’invocazione senza argomenti. Il workflow esegue solo questo comando privilegiato. Il protocollo su stdin distingue il cutover nei due versi, la sua prova facoltativa e il rilascio tipizzato di Onboarding. Operazioni Engine, verbi R3, SQL e destinazioni di scrittura sono definiti nell’esecutore. I nomi dell’installazione provengono dal profilo o dalla fotografia verificata.

### Campi del profilo privato

| Campi | Origine e vincolo |
|---|---|
| `runner`, `repository`, `repositoryId`, `branch`, `commit`, `environment`, `environmentId`, `reviewerIds` | Account locale della consegna, slug e identificativi GitHub verificati dall’owner, ref autorizzato, SHA Git completo e reviewer individuali. |
| `runnerName` | Nome registrato in GitHub Actions. In sua assenza l’esecutore usa il valore di `runner`. |
| `installRoot`, `leaseJournal`, `socket`, `roleCids`, `roleTables` | Root dell’installazione R3, journal coordinatore, percorso del socket Unix, i due CID e i due nomi tabella del provider. Il plan li confronta con il supervisore e l’osservazione R3. |
| `originalProfile` | Dichiarazione Semantic autenticata della v27. Include role, containerName, image, configurationSha256, network, networkId, bridge, ipv4, destination, port, protocol e direction. |
| `successorImage` | Facoltativo. Contiene i pin CI, l’inbox assoluta dello ZIP, il nome del campo del manifest con l’intero inventario Flyway e l’inventario del predecessore fissato da `originalProfile.image`. Omettere la sezione per il cutover con la sola abilitazione del worker. |
| `retainedName`, `failedName`, `readinessPort` | Due nomi liberi e distinti dal nome di servizio, porta HTTP di readiness del Semantic sulla rete del profilo. |
| `runbooks` | Mappa per `stop-N`, `start-N`, `probe-N` con N uguale a 27, 28 e 29, più `issue-N` e `upgrade-N` per 28 e 29. Ogni valore contiene `artifactCommit` del runbook, `sourceCommit` interno e `sha256` del blob LF. Per avere anche il ritorno con un solo bootstrap, consegnare entrambi i versi. |
| `probe` | I quattro binding privati `C_R3_INPUTS`, `C_R3_INPUTS_SHA256`, `C_INSTALLATION_PROFILE`, `C_INSTALLATION_PROFILE_SHA256` usati da c-probe. |
| `queue` | Nome o CID del container PostgreSQL in `container`, directory del socket Unix interno in `socket`, `role`, `database` e mappa IAM privata `subjectTenants`. Predisporre nel container l’accesso locale senza password per il ruolo di lettura con visibilità completa della coda. |
| `queue.proof`, `queue.proofWaitSeconds` | Facoltativi in coppia. Per la prova chatbot fissare la finestra in secondi e un oggetto con `subject`, `keyHash`, `fingerprint`, `provider` e `uri`. Il soggetto deve avere un tenant registrato. |
| `modules.onboarding` | Profilo completo del rilascio con artefatto, socket, journal e sonda. Il bootstrap crea il journal privato nella directory padre in custodia root. Il trasporto pubblica nell’inbox indicata nel profilo. |

Compilare i segnaposto e gli ID numerici nel documento privato. L’esempio copre entrambi i versi A2, i tredici binding dei runbook e Onboarding. [Profilo per l’handoff](privileged-executor.example.json)

La V12 registra il soggetto del richiedente. La corrispondenza soggetto→tenant deve provenire dall’owner IAM dell’installazione. Un soggetto pendente sconosciuto impedisce di dichiarare completo l’inventario. Il lettore richiede visibilità senza filtro RLS e seleziona solo metadati delle richieste pendenti o in esecuzione. Il riscontro del candidato restituisce solo l’identificativo del job.

## Consegna dei runbook per Claude

Usare il generatore dell’handoff `sprint-01/tools/gen_r3_runbooks.py` e la distinta `r3_union.txt` riconciliata con i blob della revisione sorgente. Il generatore prende come argomenti il percorso della distinta e il commit della consegna. Per la 28 selezionare `LATEST=28`, codice e composizione della 27, stesso input di rinnovo della 27 (SHA-256 `a829c0ba2a5fca451d9065bbf108b4e0bdd4bb8550f46f5f73a09931461a34d5`). Conservare l’operate della 27 per lo stop e fissare issue-28, upgrade-28, operate e sonda ai rispettivi blob. Preparare nello stesso modo la distinta separata della 29 per il ritorno. I runbook condivisi come `r3-operate.sh` sono selezionati dal commit del blob per quella versione.

Il preparatore eseguito dal runbook usa `--v24-inputs` e `--v24-inputs-sha256`. L’indice contiene esattamente `DATA_INPUTS_V24` e `SOURCE_INPUTS_V24` verificati. Il modo `profile` combina installationProfile, identityProviderPeer, semanticPeer e southbound/historicalTemplate, esamina il Semantic e ripete l’osservazione d’epoca. Il modo `inputs` riceve `--profile`, `--profile-sha256`, `--source-sha256` di semantic_identity_v25.py, `--lease-renewal` e `--lease-renewal-sha256`. Il risultato include `files.semanticProfile`, il rinnovo vincolato e la sorgente di identità. Ogni hash riguarda i byte canonici del preparatore.

La CREATE è fissata prima del fermo. Nel profilo senza `successorImage`, l’immagine, il cancello, i bind, la configurazione host, le reti con IP espliciti e gli alias derivano dalla baseline. Cambia la sola variabile `OUF_DISCOVERY_WORKER_ENABLED`. Docker assegna CID, endpoint e MAC. Appena noto il CID, il verificatore deriva dal frame approvato l’hostname automatico e l’alias breve di API 1.44, poi confronta l’intero hash R3. L’emissione richiede la stessa impronta in `compositionInputHashes.semanticProfile`, sequenza successiva e predecessore atteso. L’emittente rilegge il mandato, usa la chiave Ed25519 nella custodia esistente e verifica la testa pubblicata. L’upgrade ricompone gli stessi input. La 29 ripete la procedura sul vecchio CID riavviato, con il profilo originario.

### Immagine Semantic del task-24c e V13

Per la PR Semantic 49, configurare la variabile di environment `MODULE_RELEASE_INBOX` con la directory assoluta di `successorImage.inbox`, già esistente e scrivibile dal runner. Avviare **Transport Semantic release image** sul branch predefinito protetto. Il run sorgente è `44796175289`. In `source_artifact` inserire l’ID numerico dell’artefatto `semantic-registry-governed-image-44796175289`. Dopo la verifica del manifest, dei byte immagine e della relazione fra testa revisionata, merge provato e albero fissato, il trasporto deposita lo ZIP originale come `<zipSha256>.zip`. La ricevuta è l’artefatto `semantic-transport-<run di trasporto>-1`. [Workflow manuale](../.github/workflows/semantic-release-artifact-transport.yml) · [Pin del publisher](../config/module-release/semantic-successor.example.json)

Per il plan A2 compilare `successorImage.ci` con i pin del publisher e i valori verificati di run, tentativo, ID artefatto e digest ZIP della ricevuta. Scegliere l’`imageId` approvato per lo store di destinazione tra i `verifiedImageIds`. Il prefisso dell’artefatto appartiene al profilo di trasporto. Impostare `migrationsField` a `flywayMigrations`. Per `predecessorMigrations` usare l’inventario verificato dell’immagine v27, nello stesso formato `{name, sha256}` del publisher. Una migrazione storica rimossa o modificata blocca il plan.

Al plan il lettore GitHub deve poter leggere i metadati pubblici del repository del modulo. L’esecutore confronta workflow, PR, testa, run e tentativo con i pin privati, verifica appartenenza, nome e digest GitHub dell’artefatto, quindi verifica ZIP, manifest, parentela e albero testato con i lettori del rilascio moduli. Dopo la verifica registra il claim di import e carica nel Docker locale i byte verificati. Rilegge tag, label e image ID dello store. La ricevuta privata del plan lega provenienza, inventario completo e aggiunte alla richiesta di CREATE. Il riepilogo per la review di apply mostra image ID, digest ZIP e digest dell’inventario.

La CREATE usa l’image ID approvato. Nel rilascio con immagine, il plan dichiara la modalità ricavata dal frame del candidato. Con `spring-flyway` il job `migrate` revisiona le aggiunte del manifest e Spring migra all’avvio. Con `SPRING_FLYWAY_ENABLED=false` la modalità è `governed-sql`. Apply calcola le pendenti dal JAR del candidato al cancello e dall’intera storia del database, comprese le migrazioni di rilasci precedenti ancora da applicare. Il job protetto `migrate` usa lo stesso esecutore SQL del recupero online e verifica il predecessore fermo. Prima della firma, `sign` richiede la ricevuta di completamento, la storia completa e la generazione approvata al cancello. Una ripresa prima della firma richiede una review del nuovo stage.

Il ritorno v29 ricollega lo stesso CID conservato e usa l’image ID e il riferimento Docker originali. **V13 resta applicata al database.** L’immagine precedente ignora le aggiunte introdotte da V13. La verifica applicativa di questa compatibilità sulle immagini effettive appartiene al task-24c. La prova nativa A2 con due immagini distinte verifica l’identità e il rilascio al cancello in entrambe le direzioni. [Suite Engine](../tests/test_privileged_executor_native.py)

## Quiescenza, rilascio e ritorno

Il plan verifica Java PID 1 e la readiness corrente, risolve il riferimento immagine e prepara la sonda C sul CID originale. La prova MCP usa l’identità concordata per il chatbot. I wrapper R3 esistenti scrivono fotografie e stato privato di preparazione già in modo `plan`. L’esecutore riserva uno HOME di root per run e conserva il `planSha256` originale per l’apply. Il solo retry automatico dello stop richiede il diniego strutturato pre-effetto `R3_PLAN_DIGEST_CHANGED`, zero richieste Docker e un successivo rinnovo osservato. Sono ammessi tre tentativi complessivi. La nuova directory di evidenza e il relativo digest possono cambiare. Tutto il resto del sottopiano, inclusa l’osservazione, deve coincidere.

L’apply rilegge la coda prima del fermo. Lo stop verifica ruoli e tabelle, supervisore in attesa e lease chiuso. Il vecchio CID viene scollegato e rinominato. Ogni effetto ha un claim privato sincronizzato su disco prima dell’invocazione. La preparazione termina con shell PID 1, handler pronto ed epoca uguale in due osservazioni. PostgreSQL vieta il lock `SHARE` in una transazione read-only. Root esegue la proiezione SQL della PR 48 con `docker exec -i` e `psql -X -w` sul socket locale del container. Prima del segnale confronta due snapshot indipendenti in `REPEATABLE READ READ ONLY` con l’intero inventario approvato. Il secondo controllo avviene sotto il lock del coordinatore, entro la scadenza verificata per SIGUSR1. Una differenza osservata o un job in esecuzione impediscono il segnale. Le letture rilevano le differenze osservabili tra snapshot. Rimane una finestra per nuovi enqueue dopo l’ultima lettura, perché PostgreSQL consente le scritture concorrenti. [Proiezione della coda](../tools/privileged_executor/discovery-queue.sql)

Lo start usa il runbook con ripristino D-047. Prima del segnale, sotto il lock del coordinatore, l’esecutore verifica il tick, l’epoca, il lease autorizzato, l’indice del veth, i set `semantic_open` bridge/inet e gli elementi a scadenza del lease. Il pidfd vincola SIGUSR1 al processo osservato. Un claim con esito incerto impedisce un secondo segnale. Dopo lo start confermato, un controllo funzionale fallito avvia lo stop governato dello stesso profilo e registra il readback di chiusura. La perdita del processo esecutore richiede la lettura dei claim e dello stato vivo.

Con `direction=return` il workflow identifica il successore dalla ricevuta di CREATE e ripristina nome e reti sul CID conservato. A testa 27 usa l’autorità originaria dopo riosservazione. A testa 28 prepara la successione distinta 29. Se la 28 è firmata e l’upgrade deve ancora iniziare, il plan di ritorno comprende la riconciliazione del wrapper e dell’unità tramite il runbook di upgrade. Un upgrade reclamato e privo di ricevuta ferma il percorso per riconciliazione. Il ritorno passa dagli stessi controlli di ingresso, processo, readiness e sonda; l’ENV approvato riporta il worker a false.

Per riprovare una fase già autorizzata serve un nuovo dispatch. Un nuovo run può riprendere la preparazione d’emissione al cancello dopo verifica di CID, epoca, chiusura e coda. Un diniego esplicito pre-firma può provare l’assenza di effetti. Un journal parziale resta disponibile per l’owner. Un rollback o un’interruzione conservano richieste, claim e candidati applicativi.

## Custodia e qualifica

Il modello considera sostituzione del commit, confusione fra le review sullo stesso environment, replay, deriva dell’immagine o del processo, job concorrenti e perdita della risposta dopo un effetto. La regola dedicata riduce il mandato di questo workflow. La garanzia di custodia sull’intero nodo dipende dai privilegi effettivi dell’identità runner. R-007 copre i privilegi equivalenti a root ottenibili indipendentemente da questo entrypoint. D-073 accetta R-007 per la prova in laboratorio e richiede un’identità runner isolata prima della produzione.

Il registro di componente D-065 descrive esecutore, profilo, giornali, sudoers e binding dell’unità R3 con metodi di cattura, ordine e prova di ripristino. [Voci del registro host](../tools/privileged_executor/host-register.json)

I test portabili esercitano la macchina delle fasi 27→28→29→30 e il ritorno 30→31 con confini host simulati. Il test Linux con `OUF_A2_NATIVE=1` usa una shell e un pidfd reali. La suite `test_privileged_executor_native.py` con `OUF_A2_NATIVE_ENGINE=1` richiede un daemon locale usa e getta etichettato `ouf.a2.fixture=true`, il percorso `OUF_A2_FIXTURE_SOCKET` e l’image ID locale `OUF_A2_FIXTURE_IMAGE` con il JAR di prova persistente. Crea una rete interna, due container e verifica gate, segnale e ritorno. Per qualificare l’installazione servono inoltre le prove native R3/D-047, le review reali, il giro integrato coda e sonda, la prova MCP e l’osservazione di almeno 60 minuti con rollover. [Suite pipeline](../tests/test_privileged_executor.py) · [Suite Engine](../tests/test_privileged_executor_native.py) · [Qualifica R3](OUF_SEMANTIC_PROVIDER_R3_V27.md)

Il workflow delle PR esercita il pidfd, il ritorno Docker A2, la coda su PostgreSQL con grant per colonna, il bootstrap e il rilascio di un modulo su una VM GitHub effimera. Le immagini a cancello derivano dal JDK del runner. La prova della coda usa i binari PostgreSQL locali individuati con `pg_config --bindir` in un container con rete disabilitata. [Prove native](../.github/workflows/privileged-executor-native.yml)

## Matrice delle interruzioni di moduli e Gateway

Il nuovo dispatch parte da `plan`. L'esecutore serializza i job con il lock host. Ogni job protetto consuma la propria review nel ledger `approvals` prima di poter produrre effetti. Se il processo muore, il riscontro viene pubblicato dal dispatch successivo. Le colonne della matrice descrivono tre momenti distinti. Quando più effetti condividono un intento, la tabella indica quale osservazione permette di distinguerli.

### Rilascio moduli

Il journal del modulo usa il digest del plan originale come directory. Il lock del modulo contiene `owner.json` con quel digest. Un plan di recupero congela profilo, frame dei tre nomi e impronte dei record della transazione. L'apply approvato li rilegge prima di agire. `HELD` espone owner, CID, stato Docker e numero di reti per servizio, predecessore conservato e candidato isolato. Una lettura Engine fallita compare come `unobserved`. La ricevuta privata del run è `<fase>.held`.

| Fase, claim → effetto → ricezione | Dopo il claim | Dopo l'effetto, prima della ricevuta | Dopo la ricevuta |
|---|---|---|---|
| Plan · prenotazione run, `plan.review` → lettura ZIP, predecessore, PID 1, HTTP e database se previsto → `plan` | Nuovo run di sola lettura | Stesse letture, senza effetti applicativi | L'apply richiede il digest approvato |
| Apply · `apply.review` → riserva lock, directory, `owner.json`, `plan.json` e `baseline.private.json` | Nuovo plan se manca il lock | Lock senza owner o baseline verificabile → HELD | La baseline ricostruita dal CID deve avere il digest originale |
| Apply · baseline → import immagine, controllo tag/image ID e frame prima dello stop → `database.private.json` se prevista, poi `stop-intent.json` | Il predecessore serve ancora | L'import è additivo. Se il database necessario al ritorno non è documentato, HELD | Il claim di stop identifica il solo CID interessato |
| Apply · `stop-intent` → stop → detach di ciascuna rete → rename al nome conservato | Se il CID serve ancora, verifica frame, processo e HTTP | Ritorno dal CID fermo: controlla reti residue, ripristina nome e reti mancanti, poi gate, segnale unico e HTTP | La verifica del predecessore fermo e isolato precede `create-intent.json` |
| Apply · `create-intent` con digest della richiesta → CREATE → `created.json` | Esito senza CID comprovato → HELD | Anche con il nome occupato, esito senza CID → HELD. Entrambi gli oggetti restano all'owner | Il recupero usa il CID registrato e confronta immagine, configurazione risultante, mount, comando e reti |
| Apply · `start-intent.json` → start del CID → `start-generation.json`, prova gate, `migration-plan.json` e `stage.json`, oppure rilascio diretto | Un CID ancora `created`, PID zero, tempi di start/fine nulli e zero restart può partire dopo il controllo del frame | Un CID running senza generazione registrata resta HELD. Con generazione confermata ammette la shell identificata nel rootfs, con argv e handler USR1 atteso | `GATED` richiede review migrate. In modalità `none` si arriva al segnale durante apply |
| Migrate · `migrate.review`, `migration-review-consumed.json` → verifica CID/generazione | Nuovo plan, apply e review migrate sullo stage originale | Digest o generazione diversi → HELD | I claim delle operazioni successive determinano quali effetti restano autorizzabili |
| Dedicated · `migration-intent.json` → exec/create, exec/start e osservazione esito → `migration-complete.json` | Se l'exec potrebbe essere in corso, nessun secondo comando | MCP verifica in sola lettura OID, intera storia preesistente, versioni e checksum aggiunti e impronta schema. Il target esatto consente la ricevuta mancante. Storia incerta o migrazione priva di osservatore → HELD | Successo verificato consente il segnale. Un exit fallito comprovato permette compensazione solo con DB compatibile |
| Spring · `flyway-plan.json` se acquisibile, `release-signal.json` → USR1, exec Java e Flyway → readiness | Il segnale reclamato si riconcilia in sola lettura | Servono stessa generazione, processo applicativo, HTTP e confronto con `ouf_onboarding.flyway_schema_history`. Prova mancante o diversa → HELD | `receipt.json` con `READY` e HTTP chiude il rilascio |
| Moduli · `release-signal.json` o `restore-signal.json` → USR1 → PID 1 applicativo e HTTP | Una claim esistente esclude un secondo invio | Attesa entro il budget del profilo, controllo dell'epoch e nuova verifica dopo HTTP. Nel forward con migrazione si applicano anche i controlli DB della riga pertinente | `receipt.json` o `return-receipt.json` attesta la direzione e il CID |
| Ritorno · `rollback-intent.json` su errore, oppure `rollback.review` e `return-intent.json` per MCP READY → stop/detach/rename del successore | Verifica CID personale, custodia e DB richiesto | Se la compensazione è interrotta, un nuovo apply di recupero la completa. Per il ritorno esplicito si usa un nuovo rollback approvato sul digest originale. Oggetto, DB o generazione incerti → HELD | Il candidato deve risultare fermo, isolato e nel nome previsto prima del ritorno in servizio |
| Ritorno · stesso intento → rename predecessore e reconnect per rete → `restore-start.json`, start, `restore-generation.json` | Il CID originale e i binding del plan guidano il ritorno | Ricollega solo le reti mancanti. Uno start con generazione successiva non identificabile lascia HELD | Gate, `restore-signal`, processo e HTTP del predecessore. MCP richiede 204 |
| Chiusura · ricevuta privata → rilascio lock → `apply.result`, `migrate.result` o `rollback.result` del run | Una ricevuta di rilascio terminale con lock residuo richiede una nuova verifica del servizio | Lock ambiguo, return già consumato o installazione già attiva → HELD con stato residuo | La review è consumata. Il ritorno da READY per MCP usa il digest del plan di rilascio originale |

Per Spring il lettore usa il CID PostgreSQL e il socket Unix del binding MCP installato sullo stesso Engine, verifica la rete condivisa e la destinazione JDBC di Onboarding e interroga la tabella in una transazione `READ ONLY`. Il checkpoint precede USR1 e confronta i checksum Flyway degli script nel JAR del candidato al gate con la storia iniziale. Se manca un binding verificabile, il percorso ordinario mantiene il contratto di avvio del profilo. Un esito Spring incerto resta all'owner. Per MCP la tabella dell'applicazione è `ouf_mcp.schema_migration`. Le due verifiche usano i checksum dei rispettivi owner.

I vecchi lock privi di un collegamento dimostrabile al plan e i claim CREATE privi di CID restano HELD. Nessuna procedura di recupero richiede di correggere il journal a mano. [Recupero dei moduli](../tools/module_release/recovery.py) · [Fasi applicative](../tools/module_release/operation.py) · [Ritorno MCP](../tools/module_release/return_operation.py)

### Gateway

La readiness della transazione Gateway consiste nella rilettura Admin API di tutte le risorse della release, sotto guardia di generazione. Il ritorno verifica anche l'assenza per le risorse create. I corpi e gli eventuali valori opachi restano nel journal privato.

| Fase, claim → effetto → ricezione | Dopo il claim | Dopo l'effetto, prima della ricevuta | Dopo la ricevuta |
|---|---|---|---|
| Plan · prenotazione run → verifica bundle e GET di ogni risorsa → `gateway.plan.review`, `gateway.plan` | Nuovo plan | Ripete le letture, verifica generazione, package e stato rispetto a prima/dopo | Snapshot approvabile con nonce, parent e digest |
| Apply · review del digest → nuova lettura e `gateway.snapshot` → `gateway.apply.review` e testa `PENDING` | Senza testa PENDING, un nuovo plan trova il precedente stato | Dopo PENDING recupera lo snapshot tramite run, fase e review. I digest della catena devono corrispondere | Ogni modifica passa per intent per indice |
| Apply/return · `gateway.<fase>.<i>.intent` → PUT o DELETE, ACK, GET → `<i>.receipt` | GET sul nuovo plan distingue prima e dopo | Nessun replay basato sul solo ACK. Prima compatibile → effetto mancante, dopo conforme → già effettuato, terzo stato → HELD | Nuova verifica complessiva anche per le righe invariate |
| Compensazione · intent delle righe tentate → GET, scrittura inversa e GET in ordine inverso → `gateway.<fase>.failure` | La testa rimane PENDING | Anche se la lista in memoria è persa, il nuovo plan riconcilia tutta la release dai journal. Stato non identificabile → HELD | `RESTORED` precede il ripristino della testa parent della transizione tentata |
| Chiusura apply · GET di tutte le righe → `gateway.apply.result` → testa `APPLIED` | PENDING conserva la provenienza | Un altro run verifica anche le risorse già scritte e può pubblicare la propria testa | Il digest di ritorno lega lo snapshot verificato |
| Return · verifica testa APPLIED, releaseRun e digest → `gateway.return.review`, PENDING → effetti inversi | Prima di PENDING resta valida la testa APPLIED | Da PENDING, un nuovo plan/apply può ricostruire la release. Una nuova review return risale fino allo snapshot precedente al primo run interrotto, anche attraverso più riprese | `gateway.return.result` segue tutti i GET di ritorno. Viene ripubblicata la testa originaria, anche se nulla |
| Perdita dopo la ricevuta finale e prima della testa | La ricevuta resta immutabile | Finché la testa è PENDING, il nuovo plan riconcilia le risorse sulla stessa generazione | Dopo la pubblicazione la testa determina la transizione disponibile |

La compensazione di un apply di recupero riporta al punto di partenza di quell'apply. Il ritorno approvato di una release recuperata usa la baseline completa autenticata da `returnBaseline`. Il diniego pubblico riporta `owner=gateway`, stato della testa e, se disponibile, l'ultima risorsa reclamata e la presenza della sua rilettura registrata. Gli errori inattesi di moduli e Gateway riportano tipo, basename del file e riga. [Transizioni Gateway](../tools/privileged_executor/gateway_operation.py) · [Prova di interruzione APISIX](../tests/test_gateway_release_native.py)

## Rilascio di UDP e Ingestion

Ogni modulo ha un profilo facoltativo in `modules`. Copiare il relativo esempio nel profilo privato dell’esecutore e completare tutti i segnaposto. La compatibilità del predecessore con le migrazioni proposte richiede una verifica umana prima di impostare `migration.rollbackCompatible`. [UDP](../config/module-release/udp.example.json) · [Ingestion](../config/module-release/ingestion.example.json)

1. Dal PR del modulo acquisire repository, nome del workflow, numero del PR, commit e tree revisionati, ID del run, tentativo, ID e prefisso dell’artefatto, SHA-256 dello ZIP, schema del manifest, nome e ID dell’immagine qualificata. Il formato supportato contiene `manifest.json`, `SHA256SUMS` e `image.tar.gz` con le coordinate del tested-image. Confrontare il formato con il publisher del PR.
2. Per il trasporto preparare una copia leggibile dal runner con le sole chiavi `module` e `ci`. Impostare `UDP_RELEASE_TRANSPORT_PROFILE` o `INGESTION_RELEASE_TRANSPORT_PROFILE` al suo percorso e `MODULE_RELEASE_INBOX` alla directory di arrivo. Avviare il workflow manuale di trasporto con modulo, run e artifact ID. Il trasporto confronta i pin, verifica il commit testato e pubblica lo ZIP per digest. [Workflow di trasporto](../.github/workflows/java-module-artifact-transport.yml)
3. Avviare il workflow di rilascio del modulo. Il plan controlla la readiness del predecessore e fissa peer, database e storia Flyway. Il primo clic autorizza il passaggio al candidato trattenuto al cancello. La sintesi del job espone i nomi e i checksum Flyway degli script pendenti letti dal JAR indicato da `gate.command`, insieme ai digest della storia iniziale e attesa. Il secondo clic autorizza quel digest. La riconciliazione usa una transazione PostgreSQL read-only sulla tabella qualificata `flyway_schema_history` e la readiness HTTP della stessa generazione.
4. Dopo un’interruzione, un nuovo dispatch senza input propone la ripresa. Per tornare al predecessore, fornire a `return_plan` il digest del plan originale. Il ritorno verifica la storia attesa e il CID di proprietà prima di parcheggiare il candidato. Dopo un segnale incerto il lettore deve poter riconciliare la storia completa. Una CREATE senza CID registrato o uno start senza generazione attestata restano HELD secondo la matrice.

Sul VPS ricavare nome e image ID del predecessore con `docker inspect --format '{{.Name}} {{.Image}}'`. Per ciascuna rete leggere soltanto nome, IPv4 e alias funzionali. Confrontare localmente entrypoint, comando e nome dell’eseguibile con il gate R-039. Acquisire nomi di custodia, inbox, journal privato, socket Docker, nsenter e contratto di readiness dal profilo installato. Per PostgreSQL verificare CID, directory del socket, nomi delle variabili JDBC e utente, database e schema della history. Confermare i binding sulla configurazione applicativa revisionata e con una SELECT in transazione read-only. Conservare i valori delle variabili d’ambiente sul VPS.

### Argomenti di Ingestion e verifica di V21

In `modules.ingestion`, `gate.command` deve coincidere con il comando completo del predecessore. L’esempio recepisce il comando osservato il 21 novembre e dichiara il seguente delta. [Profilo Ingestion](../config/module-release/ingestion.example.json) · [Profilo dell’esecutore](privileged-executor.example.json)

| Campo | Valore nell’esempio | Effetto |
|---|---|---|
| `gate.command` | `["java","-jar","/app/app.jar","--spring.flyway.enabled=false","--ouf.ingestion.startup.schema-mode=VALIDATE_ONLY"]` | Identifica il processo originale anche durante il ritorno |
| `candidate.removeArgs` | `["--spring.flyway.enabled=false","--ouf.ingestion.startup.schema-mode=VALIDATE_ONLY"]` | Il candidato esegue `java -jar /app/app.jar` |
| `candidate.enableFlyway` | `true` | Imposta `SPRING_FLYWAY_ENABLED` sul candidato dopo il merge con i default dell’immagine |

Il blocco `candidate` è facoltativo per i profili Java con `migration.mode` uguale a `spring-flyway`. Ogni rimozione identifica una sola opzione completa `--nome=valore` dopo il JAR. Il riepilogo del plan mostra le rimozioni, le impronte dei due argv e l’operazione sull’ambiente. Per opzioni diverse dalle due costanti documentate espone solo il nome. Il digest approvato copre il delta e la richiesta CREATE. Il ritorno riavvia il CID trattenuto con argv e ambiente originali.

Per UDP completare `gate.command` nel profilo privato con tutti gli argomenti osservati, compresi quelli del lake S3. Il profilo UDP d’esempio eredita il comando completo.

Per l’immagine del task-12c, verificare nella review di `migrate` che la lista degli script pendenti contenga V21 con il checksum atteso. Con il candidato ancora al gate, la storia deve coincidere con la baseline del plan. Dopo il segnale, `READY` richiede sia la storia attesa sul database fissato sia la readiness HTTP dello stesso processo. Il ritorno richiede la compatibilità del predecessore con V21 già applicata.

### Dichiarazione del datasource effettivo

Per UDP e Ingestion gli esempi adottano l’opzione 1. Nel blocco `migration.flyway`, `effectiveDatasource` uguale a `profile-env` dichiara che applicazione e Flyway usano effettivamente URL e utente identificati da `urlEnv` e `userEnv`, e la history nel database e nello schema dichiarati. Nel profilo privato inserire i **nomi** delle variabili `OUF_*_DB_URL` e `OUF_*_DB_USER` del modulo. Chi firma il profilo deve verificare questa corrispondenza anche per le sorgenti caricate da `SPRING_CONFIG_ADDITIONAL_LOCATION` e per entrambe le immagini durante il rilascio. Il contenuto dei file esterni è coperto dalla dichiarazione dell’operatore. Il lettore non interpreta quei file.

Il lettore controlla `SPRING_APPLICATION_JSON` in memoria, dal `Config.Env` del predecessore, dalla configurazione prevista nel plan e dal candidato effettivo prima del segnale. JSON malformato, chiavi duplicate, override del datasource o di Flyway (anche annidati, puntati o con grafia alternativa) e selettori di configurazione ambigui portano a `HELD`. Il plan e i messaggi di errore omettono i valori dell’ambiente. Senza la dichiarazione rimangono i controlli restrittivi del lettore.

Per Onboarding si può dichiarare lo stesso binding dopo aver verificato la configurazione esterna. Il suo profilo esistente senza blocco `migration.flyway` mantiene il percorso del 20 novembre, con avvio Spring e readiness. In quel percorso un esito incerto del segnale richiede comunque una prova Flyway per la riconciliazione.

## Stop R3 durante il rinnovo e successione dei moduli

Lo stop attende la pubblicazione atomica di un nuovo journal con `state=LEASE_READY` e `leaseAuthorized=true` immediatamente prima dell’apply. L’attesa ha un limite di 15 secondi. Alla scadenza, il primo tentativo può usare il digest approvato se il lease risulta ancora autorizzato e pronto. Ogni ritentativo richiede una pubblicazione fresca. Il runbook registra ogni invocazione in `book-*`. La claim conserva il primo piano, mentre `stop-retry-1` e `stop-retry-2` conservano i piani ammessi per i due ritentativi. Solo una collisione attestata prima di qualsiasi effetto consente di ripianificare.

Il runbook `r3-operate.sh` chiama `operate.observe`. Sia `observation.lease` sia `lastObservation.lease` contengono esattamente `state` e `leaseAuthorized`. La scadenza `leaseDeadlineMonotonic` appartiene allo scheduler. Il segnale di pubblicazione è la coppia `st_ino`, `st_mtime_ns` del journal. Nessuno di questi tre valori entra nel piano di stop. Nel confronto tra piani possono variare soltanto `outputDirectory` e il digest complessivo `planSha256`. Le epoche correnti e precedenti dei candidati, `supervisor.epochs` e il digest d’identità `supervisor.semanticEpoch` restano vincolanti in entrambe le osservazioni.

Per abilitare il predecessore da ricevuta, il profilo privato del modulo accetta questo binding opzionale per una chiave Ed25519 dedicata, custodita dall’installazione. La chiave pubblica è in formato DER SubjectPublicKeyInfo. Il pin è lo SHA-256 del file DER. La chiave privata deve essere accessibile solo a root e utilizzabile da OpenSSL senza interazione.

```json
{
  "receiptSigning": {
    "publicKey": {"path": "<percorso-assoluto-DER>", "sha256": "<sha256-DER>"},
    "privateKey": "<percorso-assoluto-chiave-privata>"
  }
}
```

A completamento `READY`, l’esecutore conserva run, fase e digest in `module-<modulo>.ready`. Con il binding configurato, firma i byte di `receipt.json` in `receipt.ed25519`. Il plan successivo risale dalla ricevuta al piano approvato e al suo `ci.imageId`. Verifica firma, review consumata, completamento della fase, CID e frame vivo. L’apply ripete il controllo sotto lock. Un ritorno avviato, una firma assente o una ricevuta diversa fermano questo percorso. Il percorso da `oldImage` resta disponibile anche per le installazioni con ricevute storiche prive di firma. Ogni candidato richiede i propri pin CI e nomi di custodia disponibili.
