# R3 v16 — codice di diniego del driver nel journal dell’epoca

Sprint 01, task 73 · D-053.3 · R-030

Il driver v7 emette `SEMANTIC_PREEXEC_HOOK=DENIED <CODICE>` quando
`hook` o `start` fallisce. La v16 può conservare fase e codice
nel journal privato dell’epoca. Il motivo pubblico continua a descrivere
il punto del runtime che ha ricevuto il diniego.

## Runtime e formato

`compose.py` applica l’overlay ai byte emessi di `runtime_v52` ed `epochs`
da v16 in avanti. Ogni sostituzione richiede un solo ancoraggio nei
sorgenti sigillati. I percorsi logici restano gli stessi. Hash di runtime,
broker e supervisore seguono i byte emessi, come il digest della
configurazione runtime legato al payload `OPERATE`.

- Per `hook` e `start`, il runtime legge stderr da una pipe anonima e
  conserva in memoria al massimo 16.385 byte, compreso il byte che rileva
  lo sforamento. Svuota la pipe a blocchi fino al completamento o al
  timeout. Il cap di stdout di `start` resta 16.384 byte, misurati senza
  conservare l’output. Lo stdout di `hook` viene scartato come in v15.
- Il dettaglio richiede un exit status positivo e uno stderr composto
  interamente dal marker, un singolo codice ASCII `[A-Z0-9_]{1,80}` e LF.
  Testo estraneo, marker ripetuti, sforamento, segnale o timeout lasciano
  `driverDenial` a `null`. Il runtime conserva soltanto il codice validato
  e la fase scelta localmente. Stderr, argv ed eccezioni restano fuori dal
  journal e dal log pubblico.
- I timeout massimi di `hook` e `start` restano 10 e 20 secondi, entro il
  residuo della stessa sezione di ammissione. Restano i motivi pubblici
  `OCI_ADMISSION_GATE_DENIED` e `ADMISSION_OR_DRIVER_FAILED` per i dinieghi
  di `hook` e `start`. Una rilettura `runc state` non acquisibile o
  malformata dopo `start` usa `STARTED_RUNTIME_STATE_UNPROVEN`. La non
  corrispondenza del processo mantiene `STARTED_PROCESS_GENERATION_UNPROVEN`.
  La scadenza dell’intera sezione conserva il suo codice dedicato.

Ogni nuova epoca usa `ouf.semantic-docker-runtime-journal.v3`. Il campo
`driverDenial` è obbligatorio, con valore `null` o una coppia esatta di
campi, per esempio `{"phase":"start","code":"DRIVER_GATE_FAILED"}`.
La coppia è ammessa solo in `FAILED`. Il campo `failure` continua a
contenere il motivo pubblico. Il validatore v16 accetta le forme esatte
di v2 e v3 e restituisce i record v2 nella loro forma originale.
Durante il cleanup preparato di un’epoca `FAILED` il passaggio temporaneo
a `DELETING` azzera `failure` e il dettaglio, se il campo esiste. Il
runtime ripubblica il record `FAILED` originale sia a cleanup completato
sia nel ramo di errore recuperabile.

## Cronologia e ripristino

`upgrade` carica il runtime dalla configurazione legata al payload
autenticato. Con il validatore v16 inventaria anche le epoche terminali
di una cronologia mista. Nell’inventario di `upgrade` il validatore v15
rifiuta una v3 sia come epoca corrente sia come epoca storica dietro un
puntatore v2 valido. L’upgrade R3 esistente
applica solo la transizione dalla versione `N` alla testa autenticata
`N+1`. Il restore 41b rimane riservato al ripristino iniziale prima di
qualsiasi epoca e non fornisce un downgrade R3.

Dal primo journal v3 la procedura di recupero deve mantenere un lettore
v3. Conservare journal e puntatori, mantenere la coppia ferma se serve
un intervento e correggere in una versione successiva. Il ripuntamento
manuale di wrapper o unità alla v15 è incompatibile con la cronologia.
Il lettore precedente rifiuta una v3 con `EXACT_EPOCH_JOURNAL_REQUIRED`.
Un dettaglio v3 fuori contratto produce `EPOCH_DRIVER_DENIAL_INVALID`.
Il restore iniziale, quando trova epoche, usa `R3_EPOCH_PRESENT_RESTORE_DENIED`.
Conservare i record originali anche in presenza di questi dinieghi.

`operate.observe` seleziona il runtime dal wrapper. Prima di compilarlo
ammette soltanto il digest del sorgente base consegnato o quello prodotto
applicando lo stesso overlay v16 ai byte base di runtime ed `epochs`.
Un runtime estraneo a questo insieme chiuso produce `R3_SOURCE_HASH_DRIFT`.
Dopo il controllo, `operate` carica la configurazione, verifica i file
vincolati e legge le epoche corrente e precedente con il validatore installato.

## Aggiornamento dei lettori sul VPS

`r3-status.py`, `r3-epoch-timeline.py` e `r3-epoch-diag.py` proiettano il
dettaglio validato del solo `adapter.json` dell’epoca. La chiave è assente
per v2 e compare con valore `null` per v3 in assenza di dettaglio.
Il riconoscimento del wrapper in `r3_common.py` usa il percorso logico
storico, valido anche per v16.

1. Il manifest in `ops/vps/r3-readers-install.sh` contiene gli SHA-256
   dei blob LF aggiornati. Il pin `C` è a zeri e impedisce l’esecuzione.
   Dopo review e commit della consegna integrata, Claude fissa il pin
   e verifica la corrispondenza dell’intero manifest al commit scelto.
2. L’operatore root esegue `bash ops/vps/r3-readers-install.sh plan`,
   verifica hash e destinazioni e poi esegue
   `bash ops/vps/r3-readers-install.sh apply <planSha256>`. Escludere
   letture concorrenti durante la pubblicazione del set in
   `/usr/local/libexec/ouf-readers/r3/`. I modi e i grant sudo esistenti
   sono sufficienti.
3. Confrontare gli hash installati con il piano. Verificare `r3-status.py`
   e `r3-epoch-timeline.py both <epoca>` su un’epoca storica, poi su una v3
   quando disponibile. Per `r3-epoch-diag.py` indicare la versione e
   l’epoca desiderate.

Le consegne di emissione, upgrade e `operate` per v16 devono includere
il modulo overlay, i sorgenti base di runtime ed `epochs` e i digest dei
file aggiornati. Coordinare i pin con l’integrazione del task 72. Il test
del manifest confronta i digest della consegna con i file dei lettori.

## Prove offline

Il workflow R3 esegue i golden v1–v14 della suite v13 e il golden v15
acquisito alla base `c1c17d55`. La suite v16 esercita il runtime emesso,
la lettura attraverso il validatore installato e il rifiuto della
cronologia mista da parte della v15. La prova Linux usa solo figli Python
sintetici per esercitare le pipe, lo sforamento e il timeout. La suite dei
lettori copre le tre proiezioni con fixture locali.
