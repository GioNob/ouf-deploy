# R3 v27 · Verifica dell’ingresso dopo il rinnovo

La v27 attua la correzione B di R-002. Il supervisore nasce con i set di ingresso chiusi. La prima guardia di avvio verifica la catena di autorizzazioni. Dopo un rinnovo riuscito, il supervisore usa il tempo già destinato all’attesa per verificare l’ingresso. L’apertura richiede la verifica completa del peer e il readback dei membri nelle due famiglie.

## Che cosa riusa la guardia

L’istanza di `Guards` creata dal bootstrap possiede un solo `SignatureMemo`. La guardia del lease e quella dell’ingresso chiamano la stessa `head`. Ogni posizione della catena può conservare un risultato crittografico positivo. La chiave comprende gli SHA-256 del frame firmato completo, della firma e della chiave pubblica, oltre a percorso, SHA-256, versione e attributi del file OpenSSL. La prima verifica esegue `openssl version`, `openssl pkeyutl -verify` e i due controlli integrali dell’eseguibile. Il memo inserisce la voce dopo il successo, il confronto finale degli attributi e il controllo del budget. Ogni riuso ricontrolla gli antenati del percorso e l’identità del file. Un cambio di identità richiede una nuova verifica completa.

Ogni chiamata inventaria la catena, rilegge payload e firme con i controlli di custodia, verifica sequenza, predecessori, tempi, mandato all’emissione e revoche. Rilegge l’inventario e il ledger. Per il percorso con memo confronta anche l’identità della directory e di ciascun file ai due estremi della verifica. Questo rileva, fra l’altro, la sostituzione di un file con altri byte allo stesso nome e la sostituzione con una copia identica su un altro inode. Il limite è `MAX_CHAIN` (256 posizioni). Un inventario più corto elimina le posizioni superate. Un errore o un’interruzione della verifica svuota il memo. Il riavvio del processo lo perde integralmente. D-065 conserva gli stessi archivi persistenti.

Durante il tick, sotto il lock comune, il supervisore prende in lettura i lock operativi dei CID in ordine e poi il lock di directory usato dall’emittente. Le acquisizioni sono non bloccanti perché uno scrittore può già attendere il lock comune. I lock coprono controllo di autorità, epoche, driver, transazione di apertura e riconferma finale. Il writer del ledger mandati pubblica le generazioni con un hard link atomico. Una rilettura di scope dopo il readback intercetta la revoca divenuta visibile durante l’apertura e fa richiudere l’ingresso. Quel writer non partecipa a un lock condiviso con la transazione nft. Rimane quindi possibile un intervallo fra pubblicazione della revoca e sua osservazione.

Se un `flock(LOCK_SH | LOCK_NB)` trova uno scrittore esclusivo, il tick rilascia anche i descrittori già acquisiti. Sotto il solo lock comune svuota i set, rilegge `bridge/semantic_port`, `bridge/semantic_open` e `inet/semantic_open` e verifica che siano vuoti entro la riserva. Registra `CLOSED`, conserva `ACTIVE` e il lease già pubblicato. Il tentativo successivo riparte dalla verifica dell’autorità e dell’epoca. Solo `EWOULDBLOCK` restituito da quella chiamata a `flock` identifica la contesa. Un errore di apertura o custodia segue il percorso di errore ordinario. Un readback di chiusura fallito produce `R3_SEMANTIC_CLOSE_UNVERIFIED`.

## Dal readback all’attesa

1. Il readback della pubblicazione verifica tutti i membri e i TTL in entrambe le famiglie. In memoria conserva il riferimento del journal READY, la fine della lettura e il limite inferiore della scadenza, ottenuto sommando il minimo TTL all’istante precedente alla lettura.
2. Sia il rinnovo ordinario sia `collect_cache` completano i controlli finali e salvano `ACTIVE/RENEWED`. Solo al ritorno dal gestore della pubblicazione la corrispondenza fra `resultRef` durevole e readback abilita il passaggio del campione al giro successivo dello stesso processo. Un errore nel tick d’ingresso non può riclassificare un commit riuscito come pubblicazione ambigua.
3. Prima dell’attesa il supervisore completa le guardie obbligatorie, ricampiona il lease e pubblica l’osservazione del servizio. Nel ramo ordinario usa il primo fra il risveglio ricalcolato e quello ricavato dal readback del rinnovo. Tiene conto anche del tempo residuo dello scope. In attesa di cache usa il primo obbligo fra heartbeat, raccolta, residuo dello scope e confini dei singoli elementi. Una raccolta già dovuta passa direttamente al raccoglitore.
4. Subito prima di dormire, il supervisore consuma la singola opportunità. Il tick misura il tempo disponibile, tenta di riacquisire il lock comune entro il budget ordinario e riconferma journal READY, autorizzazione e scadenze. Alla fine si dorme soltanto fino al risveglio assoluto già pianificato. Anche il ciclo interno che attende la raccolta usa un risveglio assoluto. Un rinnovo immediato riceve una finestra di zero secondi.

## Composizione e progresso

Il file v27 riprende i byte della policy v25. Il budget ordinario è 0,70 s, la riserva di chiusura 0,20 s, la tolleranza di scheduling 0,05 s e l’intervallo di osservazione completa 30 s. Ne segue **H = 0,95 s**. La validazione in composizione e nel bootstrap conserva le disuguaglianze di 13b. Con `R = max(dnsTimeoutSeconds + lockWaitSeconds, driverBudgetSeconds) + applyBudgetSeconds + 2 + 1 + 1` devono valere tutte le condizioni seguenti.

- `R + 2 ≤ immediateMinimumSeconds`
- `immediateMinimumSeconds + H ≤ renewalMarginSeconds`
- `H ≤ lockWaitSeconds`
- `H < min(heartbeatSeconds, pollSeconds)`

Per il progresso, la v27 scarta anche un profilo in cui già la migliore finestra nominale sarebbe insufficiente. Con `L = min(maxLeaseSeconds − applyBudgetSeconds, leaseSeconds di ogni flusso)` richiede `H ≤ min(L/2, L − renewalMarginSeconds − GUARD_SECONDS)`. Le condizioni su tentativi, retry e lease effettivo restano attive.

Nel profilo temporale supportato deve esserci, in ogni intervallo sano di osservazione, almeno un tentativo per cui

```text
H ≤ min(prossimo obbligo, fine lease provata) − inizio tick − costo residuo obbligatorio
```

Il punto di ammissione nel ciclo di servizio segue il lavoro obbligatorio pre-attesa, inclusa la pubblicazione dello stato. Quel lavoro ha già consumato parte della finestra misurata. A questo punto il costo residuo di guardie, campionamenti e scritture obbligatorie è zero. La consegna al timer rientra nei 50 ms già inclusi in H. Il replay verifica la finestra residua e la distanza fra opportunità con rinnovi ogni circa 5,5 s, un rinnovo immediato, contesa e raccolta. La configurazione firmata da sola non fissa un limite alla successione di risposte DNS corte, alla contesa o alla latenza del filesystem. Una prova statica di progresso per tutte le esecuzioni resta aperta.

## Tetto di composizione e ritorno alla v24

**Il candidato è riproducibile offline. L’emissione con tetto è bloccata dal contratto di firma corrente.** Il compositore legge l’intero opzionale `compositionCeiling` in `files.settings`. Il limite inferiore è 24 e quello superiore è la minore fra la sequenza richiesta e la versione più recente del compositore (27). Sovrapposizioni, insiemi di input, validatori e configurazioni seguono la versione effettiva. Il payload candidato contiene il tetto esplicito, il numero di sequenza reale e l’hash dell’autorizzazione precedente in `supersedes`. Le directory e i riferimenti assoluti usano `versions/<sequenza-reale>/`.

Una sequenza con tetto 24 richiede questi input.

- Il manifest ordinario `ouf.semantic-provider-r3-inputs.v1`, con tutti e soli i binding di `DATA_INPUTS_V24` e `SOURCE_INPUTS_V24`. Restano necessari `semanticPeer`, il peer dell’identity provider, i documenti A2 e di accettazione, la migrazione e le proiezioni richieste dalla v24. Il contratto v24 usa il `BRIDGE_PORT` dell’ingresso approvato nei documenti A2.
- I byte canonici di `settings` con `"compositionCeiling":24` e il corrispondente SHA-256 nel manifest. Il binding `leaseRenewal` deve contenere la policy adottata dalla v24, conservata in [r3-lease-renewal-v22.json](../ops/vps/r3-lease-renewal-v22.json). Il set v24 esclude `semanticProfile` e il sorgente `semantic_identity_v25.py`.
- Il predecessore effettivo della catena per la nuova sequenza. Il confronto di riproducibilità verifica i byte di ogni sorgente e ricalcola gli hash dei documenti storici dopo aver aggiornato esclusivamente i percorsi di versione e gli hash dei documenti a cui puntano. [Prova dei tetti](../tests/test_semantic_provider_r3_ceiling.py)

L’emittente firma il payload dell’autorizzazione. Il piano conserva anche `compositionInputHashes`, che resta esterno al frame Ed25519. A parità di sequenza e documento di rinnovo i tetti 25 e 26 possono generare gli stessi identici documenti. Il valore esplicito nel payload distingue le due scelte, ma il validatore a schema chiuso, presente anche nei sorgenti storici, lo rifiuta con `EXACT_OPERATION_AUTHORIZATION_REQUIRED`. Inoltre l’emittente seleziona il probe del kernel dalla sequenza reale e accede a `semanticIngress`, assente in v24. Per abilitare l’emissione occorre concordare il binding firmato compatibile con i verificatori e la selezione del probe. [Contratto di autorizzazione](../tools/semantic_provider_operation/authorization.py) · [Emittente](../scripts/issue-semantic-provider-operation-authorization.py)

## Stato, chiusura e riavvio

`lastSemanticWindowMs` è la finestra disponibile **all’inizio dell’ultimo tentativo**, troncata a millisecondi. Prima del primo tentativo vale `null`. Un lease incompleto o un obbligo già dovuto danno zero. I successivi aggiornamenti dello stato e i checkpoint del journal riportano questa misura insieme a `lastSemanticTick` e `lastSemanticVerifiedAgeMs`. L’esito distingue una finestra corta, una verifica riuscita e una chiusura. I campi diagnostici non contengono CID, IP o MAC.

Un rinvio mantiene l’abilitazione precedente. I set d’ingresso restano senza timeout kernel. Un tick ammesso verifica oppure chiude e rilegge i set entro la riserva. Se la conferma fallisce, pubblica `R3_SEMANTIC_CLOSE_UNVERIFIED`, rilascia il lock e fa fallire lo scope. Il lease finito continua a limitare l’uscita. Al riavvio il supervisore riconcilia la quiescenza e riparte con ingresso chiuso fino alla verifica completa (F3).

## Prove

La catena di prova ha 26 autorizzazioni Ed25519 firmate con una chiave effimera. Il replay esegue realmente OpenSSL e modella il tempo trascorso con 25 ms per verifica e 14, 18 o 22 ms per comando di rete. Il confronto parte con i tre set vuoti e usa il codice emesso per ciascuna versione. Controlla l’epoca e i membri alla prima apertura, gli istanti di rinnovo con e senza lavoro Semantic, il cambio di autorità fra le guardie e la chiusura alla scadenza. Partire con l’ingresso aperto avrebbe esercitato solo il percorso a regime. Una catena corta avrebbe nascosto il costo delle verifiche ripetute. [Suite v27](../tests/test_semantic_provider_r3_v27.py)

Nel confronto fra le tre versioni, la prima risposta DNS sintetica dura 31 s, il profilo DNS ammette fino a 60 s e ogni flusso limita il lease a 30 s. Questo produce una finestra compatibile con gli esiti di esercizio. Il replay assegna 18 ms a ciascun comando nft del lease, inclusi i due dump per controllo di proprietà. Il confronto di puntualità usa gli stessi costi e le stesse risposte DNS con e senza tick Semantic.

La prova opt-in `OUF_R3_V27_NATIVE=1` richiede Linux ≥ 6.6, root, OpenSSL e i prerequisiti della prova nativa v25. Usa namespace privati, veth e nft reali e le risposte Engine sintetiche della prova di traffico. Stampa separatamente il costo della guardia fredda e i tempi reali dei tick a memo caldo. Il limite del tick verificato è 0,70 s. Le durate del replay portabile e quelle del kernel nativo hanno significati distinti.

La prova di contesa su Linux, eseguita come root per verificare anche la custodia dei percorsi, parte con l’ingresso aperto. Un secondo processo mantiene un lock esclusivo prima su un `operation.lock` e poi sulla directory delle autorizzazioni. Per ogni caso il test controlla le tre riletture, lo stato `ACTIVE`, il lease e il ritorno a `VERIFIED` dopo il rilascio. Nel replay portabile due tick ricevono `EWOULDBLOCK` dalla chiamata a `flock` durante la sequenza dei 14 rinnovi.
