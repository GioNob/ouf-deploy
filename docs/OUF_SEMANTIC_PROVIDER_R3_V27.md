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

## Ritorno a una versione precedente

Con testa `OPERATE` 27, una sola nuova autorizzazione può selezionare la composizione v24. Nel documento puntato dal binding `files.settings` si imposta `"compositionCeiling":24`. L’emittente incorpora lo stesso intero nel payload Ed25519. La sequenza avanza a 28, `supersedes` contiene lo SHA-256 dei byte della 27 e i nuovi documenti usano `versions/28/`. Sono ammessi gli interi da 24 a `min(sequenza, 27)`. Per proseguire con la composizione corrente, omettere il campo. Fissare il runbook dedicato alla consegna che include il validatore esteso. Il commit `685b6252` identifica la v27 in esercizio dal 20 novembre e i byte usati per i sigilli storici.

| Composizione per la sequenza 28 | Manifest e preparazione | Binding `leaseRenewal` |
|---|---|---|
| Tetto 24 | Indice base v24, esattamente `DATA_INPUTS_V24` e `SOURCE_INPUTS_V24`. Il preparatore restituisce questo indice con `--sequence 28 inputs`. Il peer `semanticPeer` e il `BRIDGE_PORT` approvato in A2 servono anche qui. | [Policy usata dalla v24](../ops/vps/r3-lease-renewal-v22.json) |
| Tetto 26 | Impostare il tetto a 26 nei settings dell’indice base. Usare il preparatore v25 in modalità `inputs` con il profilo Semantic approvato, il suo hash e quello di `semantic_identity_v25.py`. | [Policy v26](../ops/vps/r3-lease-renewal-v26.json) |
| Senza tetto | Settings ordinari. Estendere l’indice base con gli stessi binding di profilo e sorgente usati per il tetto 26. | [Policy v27](../ops/vps/r3-lease-renewal-v27.json) |

**Input esatti per la v24.** Il manifest canonico ha schema `ouf.semantic-provider-r3-inputs.v1` e mappe `files` e `sources`. Ogni valore è un binding `{"path":…,"sha256":…}` ai byte consegnati. La mappa `files` contiene le seguenti voci.

- `settings`, `coordinator`, `coordinationJournal`, `a2Manifest`, `successors`, `semanticPeer`, `rootfs`, `acceptance`
- `migrationReceipt`, `migrationPlan`, `generationReceipt`, `bootPointer`, `identityProviderPeer`, `installationProfile`, `driverBudget`, `leaseRenewal`
- `southbound/routesProjection`, `adapter/configProjection` e, per ciascun prefisso `adapter/` e `southbound/`, le cinque voci `historicalTemplate`, `template`, `launch`, `context`, `policy`

Generare le chiavi di `sources` con `sorted(C.SOURCE_INPUTS_V24)` importando `tools.semantic_provider_r3.compose` dal commit dell’emissione. Calcolare i binding sui file di tale consegna, incluso il validatore esteso. Il ramo v24 esclude `semanticProfile` e `tools/semantic_provider_r3/semantic_identity_v25.py`. Scrivere i settings in JSON canonico, aggiornare il loro binding e calcolare lo SHA-256 del manifest definitivo. Invocare `scripts/prepare-semantic-provider-r3-v25-inputs.py --v24-inputs <indice-base> --v24-inputs-sha256 <hash> --sequence 28 inputs`. Per la v24 bastano questi argomenti. Per la v26 e per la composizione corrente aggiungere `--profile`, `--profile-sha256`, `--source-sha256`, `--lease-renewal` e `--lease-renewal-sha256`. Il preparatore riceve l’indice base con la policy v22 e sostituisce il binding di rinnovo con quello della riga scelta.

### Argomenti e ricevute del runbook

Per il tetto 26 e per la v27, il comando completo di preparazione è il seguente. `PROFILE` identifica il profilo Semantic approvato, `IDENTITY_SHA256` il digest del sorgente `tools/semantic_provider_r3/semantic_identity_v25.py` nella consegna e `RENEWAL` la policy indicata in tabella. Nel manifest prodotto verificare l’uguaglianza delle chiavi di `files` e `sources` rispettivamente con `C.DATA_INPUTS_V25` e `C.SOURCE_INPUTS_V25`.

```text
"$PYTHON" -I -B "$SCRIPT/prepare-semantic-provider-r3-v25-inputs.py" \
  --v24-inputs "$BASE_INPUTS" --v24-inputs-sha256 "$BASE_SHA256" --sequence 28 inputs \
  --profile "$PROFILE" --profile-sha256 "$PROFILE_SHA256" --source-sha256 "$IDENTITY_SHA256" \
  --lease-renewal "$RENEWAL" --lease-renewal-sha256 "$RENEWAL_SHA256"
```

Salvare lo stdout canonico del preparatore come manifest definitivo. Usare il suo percorso e lo SHA-256 dei **byte salvati** per `--inputs` e `--inputs-sha256` in entrambe le operazioni. Il profilo di autorità è quello vincolato da `settings.anchorBinding`. Scegliere una directory di output nuova per ciascuna fase. Piano e applicazione della stessa fase condividono directory e argomenti.

Le variabili negli esempi Bash rappresentano i binding dell’installazione. `SCRIPT` è la directory `scripts` della consegna con il validatore esteso. `KEY_ARGS` è un array di coppie `--private-key-path <percorso>`, una per ogni percorso distinto in `keyBindings` del profilo di autorità. Il runbook passa solo i percorsi. Fissare `ISSUED_AT` una sola volta, in secondi Unix. `DOCKER_SOCKET` è l’URI completo `unix:///…`.

```bash
common=(--inputs "$INPUTS" --inputs-sha256 "$INPUTS_SHA256" --install-root "$INSTALL_ROOT"
        --issued-at "$ISSUED_AT" --table-name "adapter=$ADAPTER_TABLE" "southbound=$SOUTHBOUND_TABLE")
engine=(--docker "$DOCKER" --docker-sha256 "$DOCKER_SHA256" --docker-socket "$DOCKER_SOCKET"
        --systemctl "$SYSTEMCTL" --systemctl-sha256 "$SYSTEMCTL_SHA256")
issue=("$PYTHON" -I -B "$SCRIPT/issue-semantic-provider-operation-authorization.py" --supersede
       "${common[@]}" --authority-profile "$AUTH_PROFILE" --authority-profile-sha256 "$AUTH_PROFILE_SHA256"
       "${KEY_ARGS[@]}" --output-directory "$ISSUE_OUT")
upgrade=("$PYTHON" -I -B "$SCRIPT/upgrade-semantic-provider-r3.py" "${common[@]}" "${engine[@]}"
         --wrapper "$WRAPPER" --current-wrapper-sha256 "$WRAPPER_27_SHA256" --lock "$LOCK"
         --output-directory "$UPGRADE_OUT")
```

1. **Emettere una volta.** Con i due candidati fermi, epoche terminali o assenti e coordinatore in quiescenza, eseguire `"${issue[@]}" --plan`. Nel `PLAN_READY` verificare `previousHead.sequence=27`, `payload.sequence=28`, `payload.decision=OPERATE` e `payload.supersedes=previousHead.sha256`. Il campo `payload.compositionCeiling` deve corrispondere alla scelta della tabella, inclusa l’omissione per la v27. Conservare il piano con `payloadSha256` e `documentHashes`. Eseguire `"${issue[@]}" --apply --plan-sha256 "$ISSUE_PLAN_SHA256"` con il `planSha256` appena verificato. In `$ISSUE_OUT/result.json` attendere `SEMANTIC_PROVIDER_OPERATION_AUTHORIZATION_ISSUED`, `planSha256` e `payloadSha256` identici ai rispettivi valori del piano, `sequence=28` e `signaturesIssued=1`. La coppia pubblicata è `authorization/28.json` e `authorization/28.signature.json` sotto la radice installata.
2. **Installare la composizione.** Eseguire `"${upgrade[@]}" --plan`. Nel `PLAN_READY` controllare `versionBefore=27`, `versionAfter=28`, `authorization.payloadByteMatch=true` e `authorization.sha256` uguale al digest del payload emesso. Eseguire `"${upgrade[@]}" --apply --plan-sha256 "$UPGRADE_PLAN_SHA256"` con il digest di questo secondo piano. In `$UPGRADE_OUT/result.json` verificare `SEMANTIC_PROVIDER_R3_UPGRADED_WAITING`, `switchOutcome=REPLACED`, lo stesso passaggio 27 → 28 e `wrapperAfter=wrapperProposed.sha256` del piano. Per ciascun percorso in `documentHashes` della ricevuta confrontare l’hash con quello del piano di emissione.
3. **Avviare.** Preparare il comando seguente con `WRAPPER_28_SHA256` uguale a `wrapperAfter`. Per il ripristino volatile usare il risultato D-042 preparato per i due CID, il suo hash e la directory sorgente corrispondente al suo `sourceManifestSha256`. Eseguire prima `"${start[@]}" --plan` e poi, dopo `PLAN_READY`, `"${start[@]}" --apply --plan-sha256 "$START_PLAN_SHA256"` con il digest del terzo piano. In `$START_OUT/result.json` attendere `SEMANTIC_PROVIDER_R3_STARTED`, `dockerStartRequests=2` e `signaturesIssued=0`.

```bash
start=("$PYTHON" -I -B "$SCRIPT/operate-semantic-provider-r3.py" --action start "${engine[@]}"
       --install-root "$INSTALL_ROOT" --wrapper "$WRAPPER" --wrapper-sha256 "$WRAPPER_28_SHA256"
       --nft "$NFT" --nft-sha256 "$NFT_SHA256" --output-directory "$START_OUT"
       --volatile-rootfs-result "$ROOTFS_RESULT" --volatile-rootfs-result-sha256 "$ROOTFS_RESULT_SHA256"
       --volatile-source "$VOLATILE_SOURCE")
```

### Verifica finale del supervisore in esecuzione

- **Testa e configurazione.** In `lastObservation` dello start verificare `authorization.sha256` uguale a `payloadSha256` dell’emissione, decisione `OPERATE`, sequenza 28 e tetto scelto (campo assente nel caso senza tetto). Confrontare `configurationSha256` con `payload.runtimeConfigurationSha256` del piano di emissione e con lo SHA-256 di `versions/28/runtime-configuration.json`. Da quel file leggere i binding `leaseQuiesce.entrypoint` e `leaseQuiesce.configuration`. Verificare entrambi i percorsi e gli hash su disco, poi gli hash dei sorgenti elencati in `sourceHashes` rispetto a `sourceRoot` nella configurazione del supervisore.
- **Processo.** Per `ouf-semantic-lease-supervisor-v2.service` leggere con il `systemctl` vincolato `FragmentPath`, `NeedDaemonReload`, `DropInPaths`, `ExecStart`, `MainPID`, `ActiveState` e `SubState`. Confrontare percorso e SHA-256 del fragment con `unit.path` e `unit.sha256` della ricevuta di upgrade. Richiedere reload `no`, drop-in vuoti e servizio `active/running`. Confrontare gli argomenti caricati in `ExecStart` e quelli di `/proc/<MainPID>/cmdline` (separati da NUL) con la riga `ExecStart` di `unit.text`. Il processo deve usare l’interprete vincolato, `-I -B`, l’entrypoint in `versions/28/source/` e la coppia `--configuration` e `--configuration-sha256` del binding appena verificato. Confermare lo stesso PID e la stessa istanza del processo a fine lettura.
- **Stato applicativo.** Dal `statusPath` della configurazione verificata leggere `state=ACTIVE`, `authorizationSequence=28` e le epoche dei due ruoli. Devono coincidere con le epoche vive dei due candidati in `lastObservation`, entrambi `running` e `STARTED`, con lease `LEASE_READY` e `leaseAuthorized=true`. Per la v24 verificare l’assenza di `semanticIngress` nella configurazione e di `semanticEpoch` nella proiezione dello start. Per v26 e v27 verificare il profilo in `semanticIngress`, la policy `leaseRenewal` scelta e `semanticEpoch` valorizzata. La distinzione fra v26 e v27 si ricava dal payload autenticato e dai sorgenti vincolati al processo.

Nella ricomposizione della v24 cambiano i byte di `source/tools/semantic_provider_operation/authorization.py` e, per i relativi hash, quelli di `broker/adapter.json`, `broker/southbound.json`, `supervisor/configuration.json` e `runtime-configuration.json`. Il payload firma i nuovi binding. I runbook delle versioni già installate conservano i propri commit. [Confronto dei documenti](../tests/test_semantic_provider_r3_ceiling.py)

Per ogni comando usare l’interprete della consegna con `-I -B` e percorsi e hash dell’installazione. Un esito parziale dopo il claim richiede la riconciliazione della ricevuta prima di procedere. Il replay portabile esercita i tre passaggi con firme effimere. [Prova di ciclo di vita](../tests/test_semantic_provider_r3_ceiling_lifecycle.py)

## Stato, chiusura e riavvio

`lastSemanticWindowMs` è la finestra disponibile **all’inizio dell’ultimo tentativo**, troncata a millisecondi. Prima del primo tentativo vale `null`. Un lease incompleto o un obbligo già dovuto danno zero. I successivi aggiornamenti dello stato e i checkpoint del journal riportano questa misura insieme a `lastSemanticTick` e `lastSemanticVerifiedAgeMs`. L’esito distingue una finestra corta, una verifica riuscita e una chiusura. I campi diagnostici non contengono CID, IP o MAC.

Un rinvio mantiene l’abilitazione precedente. I set d’ingresso restano senza timeout kernel. Un tick ammesso verifica oppure chiude e rilegge i set entro la riserva. Se la conferma fallisce, pubblica `R3_SEMANTIC_CLOSE_UNVERIFIED`, rilascia il lock e fa fallire lo scope. Il lease finito continua a limitare l’uscita. Al riavvio il supervisore riconcilia la quiescenza e riparte con ingresso chiuso fino alla verifica completa (F3).

## Prove

La catena di prova ha 26 autorizzazioni Ed25519 firmate con una chiave effimera. Il replay esegue realmente OpenSSL e modella il tempo trascorso con 25 ms per verifica e 14, 18 o 22 ms per comando di rete. Il confronto parte con i tre set vuoti e usa il codice emesso per ciascuna versione. Controlla l’epoca e i membri alla prima apertura, gli istanti di rinnovo con e senza lavoro Semantic, il cambio di autorità fra le guardie e la chiusura alla scadenza. Partire con l’ingresso aperto avrebbe esercitato solo il percorso a regime. Una catena corta avrebbe nascosto il costo delle verifiche ripetute. [Suite v27](../tests/test_semantic_provider_r3_v27.py)

Nel confronto fra le tre versioni, la prima risposta DNS sintetica dura 31 s, il profilo DNS ammette fino a 60 s e ogni flusso limita il lease a 30 s. Questo produce una finestra compatibile con gli esiti di esercizio. Il replay assegna 18 ms a ciascun comando nft del lease, inclusi i due dump per controllo di proprietà. Il confronto di puntualità usa gli stessi costi e le stesse risposte DNS con e senza tick Semantic.

La prova opt-in `OUF_R3_V27_NATIVE=1` richiede Linux ≥ 6.6, root, OpenSSL e i prerequisiti della prova nativa v25. Usa namespace privati, veth e nft reali e le risposte Engine sintetiche della prova di traffico. Stampa separatamente il costo della guardia fredda e i tempi reali dei tick a memo caldo. Il limite del tick verificato è 0,70 s. Le durate del replay portabile e quelle del kernel nativo hanno significati distinti.

La prova di contesa su Linux, eseguita come root per verificare anche la custodia dei percorsi, parte con l’ingresso aperto. Un secondo processo mantiene un lock esclusivo prima su un `operation.lock` e poi sulla directory delle autorizzazioni. Per ogni caso il test controlla le tre riletture, lo stato `ACTIVE`, il lease e il ritorno a `VERIFIED` dopo il rilascio. Nel replay portabile due tick ricevono `EWOULDBLOCK` dalla chiamata a `flock` durante la sequenza dei 14 rinnovi.
