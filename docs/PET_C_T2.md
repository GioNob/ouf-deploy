# PET C della T2 · procedura 55n

Il banco B qualifica gli owner candidati sotto guasto e carico. La finestra A qualifica l'IAM e i pool dell'installazione e raccoglie un campione dal chatbot. Il custode registra due manifesti privati, con run distinti e gli stessi digest dei candidati. La matrice D-082 comprende dieci obblighi di sede per otto scenari.

## Preparare il manifesto

Copiare `config/pet-c/manifest.template.json` nell'area privata del run e sostituire ogni segnaposto con il valore del tipo indicato in `manifest.schema.json`. Le due quote IAM al minuto sono interi ricavati dal profilo effettivo. Registrare data di avvio e scadenza in UTC, UUIDv4, digest OCI delle tre immagini e SHA-256 esadecimali del bundle Gateway (`resourcesSha256`), del profilo `ouf.iam-profile.v1` e del profilo dell'esecutore. In B è possibile pianificare con digest parziali. Il rapporto richiede tutti e sei i digest per chiudere una riga.

Registrare almeno due tenant e una sorgente PET dedicati con identificativi sintetici `pet-…`, il prefisso degli oggetti e il percorso relativo dell'inventario JSON privato. Risolvere i riferimenti agli owner in sede. Nel fascicolo usare riferimenti opachi, conteggi, tempi e digest. Conservare credenziali, inventario nominativo, header, query, body e indirizzi dell'installazione fuori dalle tracce. Il manifesto accetta l'origine HTTPS del simulatore. Per HTTP in B configurare il loopback oppure il nome di servizio a etichetta singola sul banco isolato. La configurazione della rete deve impedire l'uscita dal banco.

Per A scegliere `site=A`, un intervallo positivo di massimo otto ore, gli scenari 55n-06/07/08 e `provider={"mode":"real-probe","search":1,"fetch":3}` per il run con sonda. Il contatore autorizzativo della finestra deve essere durevole e condiviso dai worker, addebitare ogni invio fisico prima della consegna e includere i retry. Tenere la rotta della sonda distinta dal traffico PET di carico confinato. È possibile pianificare una sessione A confinata con simulatore HTTPS. La ricevuta della sonda richiede la modalità reale.

Confermare capacità D-091, popolazione, mix e soglie D-095 prima di raccogliere i campioni. Le cinque capacità sono 1 piano per soggetto, 1 slot per soggetto/provider, 4 piani attivi nell'installazione, 1 invio in volo verso il provider e 2 slot riservati al controllo. Ciascuna rotta ha una quota aggregata di 20 richieste per 60 s.

I comandi seguenti usano variabili di percorso dell'operatore. Gli strumenti richiedono Python 3.11 o successivo con libreria standard. `plan` stampa il piano. La CLI restituisce 0 per un'elaborazione riuscita e 2 per un rifiuto. Il verdetto scientifico è nel contenuto del rapporto.

```sh
python -B -m tools.pet_c validate "$MANIFEST"
python -B -m tools.pet_c plan "$MANIFEST"
```

## B · banco isolato

1. Predisporre sul banco i digest del manifesto per MCP, Gateway, Onboarding/THS e Semantic, PostgreSQL persistente e popolato, migrazioni reali, APISIX e Keycloak con policy UMA. Configurare due repliche, barriere sui commit e identità sintetiche. Provare il percorso Semantic → APISIX → simulatore, la stessa chiave logica di capacità su tutte le uscite e il blocco dell'uscita nazionale.
2. Configurare indirizzo e porta di ascolto del simulatore. APISIX può riscrivere le due rotte sui percorsi sintetici oppure si possono specificare `--search-path` e `--fetch-path`. GET sulla ricerca produce `results` con `id` e `href`. GET sul percorso di lettura con l'ID restituisce ID e label sintetici. Il seme e la richiesta determinano la fixture. Il server espone HTTP interno. Per un'origine HTTPS il terminatore TLS del banco presenta il certificato verificato.
3. Eseguire nell'ordine gli scenari prenotati della tabella. Avviare in tempo utile la prova di almeno due ore e il caso con 1.000 residui unici. Usare lo stesso stato persistente dopo il restart del worker. Il clock controllato serve a coprire i confini di lease e mandato.
4. Esportare le ricevute, i log di uscita, i checkpoint e le metriche private di ciascun processo. Confrontare i contatori per DB tenendo conto della retention, dei GET utili/esclusi/ripetuti e dell'origine attestata dei 429 (`UNKNOWN` in assenza di prova).
5. Provare D-080 su DB popolato dopo scritture del candidato. Eseguire lettura, scrittura e retry col predecessore esatto, tornare al candidato e confrontare i checkpoint. Dopo l'esportazione eliminare realm e volumi dedicati al run.

```sh
python -B -m tools.pet_c simulate "$MANIFEST" "$ARRIVI" \
  --address "$BIND" --port "$PORT" --scenario 55n-06
```

Il simulatore applica finestre fisse di `count/windowSeconds` dal proprio avvio, indipendenti per search e fetch. Nel manifesto, `latencyMs` specifica la latenza per rotta. Ogni elemento di `outages` ha `startSeconds`, `durationSeconds`, `route` (search/fetch/both), `effect`, `delayMs` e `retryAfterSeconds`. Vale il primo intervallo attivo, dopo il controllo della quota locale. Per le due ore effettive impostare durata ≥ 7.200 s. Usare `503` o `close` per l'outage, `upstream429` per la limitazione upstream, `timeout` con ritardo oltre la deadline del client e successiva chiusura, `late` per una risposta ritardata. La quota locale invia 429 con secondi interi fino alla prossima finestra. Interrompere il simulatore dopo il drenaggio. La traccia conserva anche gli ingressi di richieste ancora pendenti.

| ID | Sede | Passi e verifica sul destinatario |
|---|---|---|
| 55n-01 | B | Provare scadenza a 30 s, body e path alterati, decisione negata, revoca in pausa e durante l'inoltro. IAM indisponibile deve produrre zero nuovi invii. |
| 55n-02 | B | Fermare prima dell'inserimento owner, dopo il commit owner con risposta trattenuta e prima del commit MCP. Riprovare ogni volta. Leggere una chiave owner, un job, un esito corrente e un consuntivo per tentativo. |
| 55n-03 | B | Mettere in gara due repliche, poi rilasciare il worker tardivo. Verificare fence, job, esito corrente e spesa. |
| 55n-04 | B | Outage effettivo ≥ 2 h, restart durante la pausa, pressione e cancellazione. Verificare notBefore, spesa e chiavi alla ripresa. |
| 55n-05 | B | Inviare due conferme concorrenti del titolare. Verificare una sessione, un rinnovo per incidente, ogni incremento ≤ 25%, durata ≤ 1 h entro mandato. |
| 55n-06 | B e A | Contendere l'ammissione tra avvio/rinnovo. Misurare FIFO, slot unico, quote per rotta, lock, costo IAM, controllo a saturazione e costo dello scrape. |
| 55n-07 | B e campione A | Sul banco incrociare 18/1.000 colonne, cache calda/fredda e quota libera/coda. Tenere separati i 1.000 residui unici. In A cronometrare un campione funzionale. |
| 55n-08 | A | Dal chatbot con soli MCP e THS, due HUMAN sullo stesso client. A legge A, riceve 404 su B e produce zero inoltri sul mandato B. |

### Driver R-043

`schedule(manifest, waves)` genera una sequenza di ondate con la popolazione viva di workflow. Ogni workflow ha un indice, un tenant sintetico (indice nella lista di cleanup), un soggetto espresso come SHA-256 salato con l'UUID del run e un'azione per ondata. Il seme governa l'ordine delle classi. La ripartizione ai maggiori resti conserva il totale anche quando una frazione corrisponde a un numero non intero di azioni. I workflow mantengono soggetto e tenant fra ondate.

`execute(calendar, transport, emit)` avvia le coroutine dell'ondata e attende gli esiti prima della successiva. Un adattatore implementa `async execute(action) -> int`, usa la sessione autorizzata del soggetto, mantiene lo stato applicativo del workflow e restituisce il codice HTTP. Il banco prepara workflow nei diversi stati necessari al mix. Un timeout o un errore del trasporto produce codice 0 e il relativo esito. Il callback sincrono riceve `actionStart` e `actionEnd`, classe, workflow, ondata, digest soggetto, indice tenant, istante monotono e, alla fine, durata in secondi, codice ed esito.

```sh
python -B -m tools.pet_c load "$MANIFEST" "$AZIONI" --waves 2
```

La CLI usa il trasporto finto. Per qualificare R-043 occorrono ricevute di attività reale di 100 soggetti IAM distinti e 3.000 workflow concorrenti con il mix registrato. Verificare i vivi, la frequenza per classe, pressione CPU/I/O, storico, pool e latenze. Contare separatamente processi applicativi, processi di sistema, richieste owner e piani ammessi.

## A · finestra sul VPS di laboratorio

1. Inventariare code, sorgenti, dati e checkpoint E2E prima del run. Preparare fixture dedicata e pulizia selettiva tramite owner. In assenza di cancellazione selettiva predisporre uno spazio dati separabile. Verificare T2 installata spenta nell'ordine Semantic/THS, Gateway, MCP con migrazioni e ricevuta amministrativa 019. Drenare i worker precedenti e controllare DB, identità e profilo comuni tra repliche.
2. Verificare applicazione governata del profilo IAM, `qualify` superata e ricevuta riletta senza deriva. Nel piano della finestra vincolare i digest, i soggetti, i tenant, i lavori, le rotte consentite, la scadenza e il ritorno. L'operatore approva l'apply tipizzato previsto. La scadenza deve chiudere durevolmente le ammissioni anche se il runner cade.
3. Con dispatch ordinario chiuso, saturare dati e relay con traffico PET confinato. Acquisire `controlProof` per due controlli e i due relay sui pool reali, inclusi Gateway, MCP, DB e Semantic. Consentire il dispatch soltanto nello scope PET dopo entrambe le ricevute valide.
4. Eseguire 55n-06 e il campione 55n-07 tramite i pool effettivi. Con soli due HUMAN disponibili lasciare aperta la misura IAM a 100 soggetti. Avviare 55n-08 da un chatbot senza istruzioni OUF, usare solo MCP e conferme THS secondo D-071. Correlare il 404 con la ricevuta custodita di zero inoltri su B.
5. Con quota disponibile al netto degli altri lavori, eseguire sulla fixture nota **1 search e al massimo 3 fetch complessivi**, retry inclusi. Registrare ogni invio reale, filtro prima del GET, tempi e contatori. Interrompere al raggiungimento del tetto. Se l'esito è incerto conservarlo e riconciliarlo prima di autorizzare un altro invio.
6. Arrestare in caso di deriva dei digest o del profilo, ricevuta assente, scadenza, violazione di isolamento o quota, perdita di autorità o di capacità di controllo. Chiudere il dispatch, recintare i worker, riconciliare gli effetti pendenti e verificare T2 spenta. Revocare i grant PET. Cancellare tramite i rispettivi owner solo gli oggetti del manifesto di creazione. Conservare audit, ledger ed effetti incerti secondo retention. Confrontare inventario e checkpoint E2E prima/dopo.

## Fascicolo delle tracce e calcolo

Il raccoglitore privato prepara un file JSONL UTF-8 per manifesto. Ogni riga ha `runId`, `site`, `scenario`, `kind` e `manifestSha256` (SHA-256 esadecimale del JSON UTF-8 compatto con chiavi ordinate). Gli istanti `t`, `end`, `request`, `acquired` e `commit` sono secondi sulla stessa base temporale. Normalizzare gli orologi di sorgenti diverse prima di unire i dati e conservare la prova dell'allineamento. Un semplice accostamento di clock monotoni di host diversi invalida gli intervalli. I produttori CLI creano file nuovi. Il raccoglitore conserva i byte sorgente e lega le ricevute al run.

| kind | Campi specifici e uso |
|---|---|
| proof | `name` è una chiave degli oracoli di `CATALOG` in `scenarios.py`. `passed` booleano e `receipt` SHA-256 dell'evidenza custodita dopo verifica dell'owner. Ogni barriera di crash richiede una ricevuta. |
| observation | In 55n-06, un solo intervallo `t,end` comune agli invii fisici di entrambe le rotte. Includere i periodi senza invii. |
| send | `route` search/fetch, `t,end` di un invio fisico, inclusi retry. Aggregare tutte le uscite a un solo livello di osservazione. |
| arrival, arrivalEnd | Alternativa a send. Il simulatore registra ingresso e fine con lo stesso `seq,t,route,inFlight,utc`. La fine aggiunge `end,latency,code,outcome`. Per più produttori assegnare un indice `source` stabile alla coppia. Un ingresso senza fine mantiene aperta la concorrenza. |
| queue, slotTimeout, acquire | `intent,t` per ogni enqueue, timeout, riaccodamento e acquisizione. Identificativo d'intento univoco fra le sorgenti. |
| lock | Un'acquisizione con `request,acquired,commit`. Distinguere a monte attesa del pool e rifiuto per quota. |
| iamDone, iamCall | `decision` identifica una decisione ordinaria completata. Ogni chiamata fisica ha `t,call` (introspection/decision) e l'eventuale riferimento alla decisione. Anche retry, rifiuti e altro traffico concorrono al picco. |
| control | Un campione client con `operation` (status/revoke/reconcile), `ms`, `outcome` (ok/timeout/error), `saturated=true` e booleano `scrape`. Ripetere lo stesso carico per ciascuna operazione, con e senza scrape. |
| scrape | `seconds` per ogni scrape. Conservare anche tempo DB e attese di pool. |
| e2e | In 55n-07 un record per avvio distinto con `sample,t,end,columns,residuals,cache,queue,outcome`. Cache warm/cold, coda free/queued, esito summary/timeout/incomplete/budget. Per 1.000 residui unici aggiungere `spent` (tentativi fisici). |
| probeSend | Un evento per invio fisico reale in A con `route` search/fetch. Aggregare tutti gli scenari del run e conservare la ricevuta di percorso 55n-08. |
| actionStart, actionEnd | Tracce del driver R-043 per 55n-06. Il custode confronta attività, sessioni distinte e occupazione con le tracce dei destinatari prima di attestare l'oracolo r043. |

Per il provider calcolare `60 × invii / secondi osservati` per rotta. Verificare anche il massimo su qualsiasi intervallo di 60 s e il massimo degli intervalli in volo sovrapposti di tutte le sorgenti. Usare intervalli semiaperti. L'attesa slot va dal primo enqueue all'acquisizione finale e include timeout e riaccodamenti. Riportare p95, p99 descrittivo e pendenti. Per il lock calcolare attesa da request ad acquired e possesso da acquired a commit. Per IAM dividere introspezioni e chiamate di decisione per il numero di decisioni ordinarie complete, verificare ogni decisione e calcolare capacità teorica `min(I/2,J/3)` al minuto.

| Misura | Soglia iniziale D-095 |
|---|---|
| Provider | ≤ 1 in volo, ≤ 20 inoltri/60 s per rotta, attesa slot p95 ≤ 30 s |
| Lock | p99 attesa ≤ 250 ms e p99 possesso ≤ 50 ms |
| IAM | 2 introspezioni e 3 chiamate per decisione ordinaria, picco su 60 s ≤ 80% di ciascuna quota |
| Controllo | p99 ≤ 2.000 ms per operazione con dati saturi, zero timeout |
| Scrape | Aumento del p99 del controllo ≤ 10%, p99 durata dello scrape ≤ 2 s |
| E2E | p95 avvio → SUMMARY inclusivo di coda ≤ 600 s fino a 50 residui, ≤ 900 s da 51 a 80 |

Il percentile nearest-rank seleziona il campione ordinato di indice `ceil(p × n / 100)`, contando da 1. Occorrono almeno 20 campioni per un p95 e 100 per un p99. La soglia si applica a ciascuna cella e operazione. Per il controllo pubblicare il peggior p99, per lo scrape il peggior incremento relativo. Un gruppo insufficiente produce `INSUFFICIENT_SAMPLES`. Rilevare timeout e run incompleti. Pubblicare a parte durata, spesa ed esito dei 1.000 residui unici, inclusa l'eventuale conclusione per budget. Allegare turni modello, poll logici e fisici, conteggi locali/residui e tempi di coda. In A il campione 55n-07 attesta la funzionalità.

```sh
python -B -m tools.pet_c measure "$MANIFEST" "$TRACCE"
python -B -m tools.pet_c report "$B_MANIFEST" "$B_TRACCE" \
  --also "$A_MANIFEST" "$A_TRACCE" > "$RAPPORTO_JSON"
python -B -m tools.pet_c report "$B_MANIFEST" "$B_TRACCE" \
  --also "$A_MANIFEST" "$A_TRACCE" --format markdown > "$RAPPORTO_MD"
```

Il rapporto identifica sede, data del run, candidati, digest del manifesto, misure e SHA-256 dei byte del fascicolo. Una misura assente o insufficiente lascia la riga APERTA. Una violazione resta visibile nelle singole misure anche a riga aperta. L'attivazione richiede tutte le ricevute e l'approvazione HUMAN del profilo misurato a 1.000 colonne.

## Lavoro successivo

Restano da realizzare il banco B in Compose con gli owner e le barriere, l'operazione tipizzata di apertura/chiusura con scadenza e contatori durevoli, i trasporti reali MCP pubblico e THS e l'apply IAM governato con le relative ricevute. Queste interfacce e i test offline preparano il PET. Le prove B e A spettano alle rispettive sedi.
