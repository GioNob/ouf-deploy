# R3 v23 — Rinnovo alla scadenza della cache DNS

Nell’incidente del 19 novembre alle 19:18:44, otto scambi DNS riusciti hanno dato un minimo di 16 s per entrambi i flussi, con contributo della SOA negativa. Le due compilazioni hanno prodotto 13 e 12 s. Al tick successivo i 10,97 s ancora dimostrabili erano sotto il minimo di ammissione di 19 s. La v23 usa il TTL per scegliere **quando raccogliere di nuovo**. L’autorizzazione kernel continua a dipendere dalle scadenze assolute dell’evidenza che ha prodotto ciascun elemento.

## Condizione e istanti

Per ogni flusso il client DNS sigillato calcola `minimumObservedTtlSeconds` sulle risposte complete dei resolver ammessi. Concorrono A, AAAA, i passaggi CNAME e, per una risposta negativa, il minimo fra TTL della SOA e campo MINIMUM. Restano applicabili i controlli di integrità, famiglia e indirizzi e la politica v22 per i resolver mancanti.

Sia `Tᵢ` quel minimo per il flusso i. Dopo una prima compilazione valida, il supervisore seleziona i flussi che soddisfano entrambe le condizioni.

1. `Tᵢ < min(maxLeaseSeconds, leaseSecondsᵢ)`. Il DNS limita la finestra prima dei tetti configurati.
2. `expiresMonotonicᵢ − adesso − applyBudgetSeconds < M + 1`. Il timeout intero ottenibile è al massimo M. La scadenza assoluta include già il costo del round, arrotondato per eccesso. A M esatti anche una piccola latenza di lettura può rendere insufficiente il residuo. Con M = 19 e apply = 1, senza altri costi, un TTL di 20 s entra nel caso speciale e 21 s segue il percorso ordinario.

Fra i flussi selezionati si prende il Tᵢ più piccolo. La stima di scadenza della cache è `fine monotona della raccolta + Tᵢ`. La fine del round include anche la risposta più tardiva. Il prossimo DNS parte **al più presto un secondo dopo** questa stima, per coprire la granularità intera del TTL. Il valore serve soltanto al risveglio. Il compilatore continua a usare gli `expiresMonotonic` originali. Un piano già in diniego, compreso un TTL inutilizzabile, segue la chiusura v22.

## Lease installato e pausa

| Situazione | Azione del supervisore |
|---|---|
| Rinnovo già ammesso, indirizzi identici per ciascun flusso | Salva l’attesa nel checkpoint. Conserva i timeout installati e verifica scope, journal, ownership, membership e TTL delle due famiglie durante l’attesa. Il lock è libero durante l’attesa e il DNS. Alla data pianificata può proseguire la stessa operazione con una raccolta fresca, entro la deadline originaria. |
| Il lease uscente finisce prima della raccolta | Il kernel conserva i suoi timeout finiti. Alla perdita della finestra dimostrabile il supervisore verifica la quiescenza e passa a `RETRY_WAIT`. Il prossimo tentativo di recovery ha come destinazione la data della cache, anche se il normale backoff sarebbe più lungo. |
| Recovery da `QUIESCED`, oppure indirizzi cambiati | La pubblicazione ordinaria può installare un lease corto, limitato dal DNS. Dopo il readback si controlla il residuo effettivo di ciascun flusso limitato dal DNS, compresi i costi della seconda compilazione e dell’apply. Un residuo inferiore a M + 1 arma l’attesa sul digest del relativo `LEASE_READY`. |
| Tick sul lease corto appena pubblicato | Il supervisore controlla il digest del risultato della stessa invocazione, rilegge le due famiglie sotto lock e attende al massimo un heartbeat o il residuo provato. Sotto M questo percorso consente solo letture. Al termine del limite inferiore, la proiezione passa a `WAITING` durante la frazione di scadenza incerta. Il limite superiore deriva dalla lettura in secondi interi ed è circoscritto dalla scadenza DNS. Segue la verifica di quiescenza, anche per gli eventuali flussi con timeout più lunghi. |
| Seconda raccolta ancora corta | Registra `cacheShort`, chiude il lease e applica il backoff ordinario. Nello stesso episodio i successivi tentativi ordinari con TTL ancora corto restano in pausa. Una pubblicazione valida conclude l’episodio. |

Il minimo M resta il controllo di ingresso di ogni rinnovo ordinario. I budget restano DNS 6 s, lock 3 s, driver 12 s, apply 1 s e commit 1 s. La seconda raccolta di un rinnovo in corso usa il minimo fra il suo budget DNS e la deadline già ammessa, ulteriormente riducibile al readback del lease precedente. Può quindi avere meno di 6 s a disposizione. Il supervisore addebita il tentativo al contatore durevole e contabilizza il tempo dell’attesa. La raccolta mirata ammette un solo round, anche con una risposta non cacheabile. Gli scambi UDP e l’eventuale fallback TCP restano vincolati alla deadline del round.

La pubblicazione usa la ricompilazione sotto lock, il limite `mustApplyByMonotonic`, il readback esatto e i controlli di cancellazione e autorità della v22. Un errore ambiguo di rinnovo dopo la mutazione conserva il percorso di riconciliazione. Il supervisore può revocare prima della scadenza in presenza di un diniego di sicurezza. Il checkpoint diagnostico e un journal `ACTIVE` di una precedente invocazione non autorizzano l’adozione del lease.

## Traccia e lettura operativa

Gli eventi hanno la forma `[tag, istanteEvento, scadenzaStimataCache, raccoltaPianificata, ingressoEffettivoDNS]`, in secondi monotoni. L’ultimo campo vale zero fino all’ingresso nella raccolta mirata. I tag sono `cacheWait`, `cachePaused`, `cacheCollect`, `cacheShort`, `cacheRenewed` e `cacheFailed`. Il recorder li include nella normale traccia a dimensione limitata. Il checkpoint conserva anche l’ultimo evento in `leaseRecovery.lastCacheRollover`, leggibile dopo un successo senza incidente. `lastIncident.revocation` continua a descrivere l’esito della verifica di quiescenza.

## Qualifica offline

Con una SOA a 16 s, il test del lease uscente valido verifica otto scambi per raccolta, zero scritture nft durante l’attesa, un solo apply con evidenza fresca e zero revoche. La riproduzione da recovery verifica invece 13 s, 12 s e il tick a 10,97 s, con scadenza autonoma dei quattro set simulati prima della quiescenza. Sono coperti anche TTL persistentemente corto, seconda risposta non cacheabile, evidenza tardiva, cancellazione, deriva di membership, autorità revocata, esaurimento dei tentativi e ciclo di servizio con pausa e ripresa. [Suite v23](../tests/test_semantic_provider_r3_v23.py)

## Consegna e pin

Per issue, upgrade e operate usare `C.DATA_INPUTS_V23` e `C.SOURCE_INPUTS_V23`. `C.SOURCE_MAP_V23` conserva i percorsi installati. L’unica nuova dipendenza da distribuire al compositore è l’overlay v23. Gli input dati restano quelli della v22, incluso il file associato a `leaseRenewal`. Il compositore applica tutti gli overlay prima del sigillo finale e riusa i digest fra pin interni, alias e `sourceHashes`. L’upgrade ordinario collega la sequenza 23 alla 22 con lo stesso owner g2.

| File di consegna | SHA-256 del blob LF |
|---|---|
| `tools/semantic_provider_r3/compose.py` | `6aaafd8b0f7851d2ccacc5ff26d76fd0f46392e5f7ab373c1118272a79fdb333` |
| `tools/semantic_provider_r3/cache_rollover_overlay_v23.py` | `2f6596c7b1897da8f559891efed7cc2e93baaf724e56b12f03824c4d96124929` |
| `ops/vps/readers/r3_common.py` | `309fe1f8fa6514810b0330d03ad440ea6eaefef594685dc634aeca073bf8afae` |
| `ops/vps/r3-lease-renewal-v22.json` | `7a53b38d9ecc3f75f1221a637d0c439bc0d31291fdcaedc4daf0414eaa122d53` |
| `ops/vps/r3-driver-budget.json` | `2fc0921fd26cdb69adf6ab7dc683b3fea321bb59c5db24db95428d7ac59a1e16` |

Nella composizione di prova il DNS emesso ha digest `880b038cd66f702b4562198bd6802b434f5044bf0104f7f487346ce7f5a27cd9`, il modulo supervisore `bdda37e17c5f0d17589e8856f07496f1b9f6e10919994f50f483f06163739c19` e il runtime `90166dcb75ab640dc1ebb536f016f6fdda7fdb49c672d03e8a3c45350c0438c9`. Per la consegna dal commit approvato restano da rigenerare i runbook, il manifest di autostart e il manifest del lettore. La verifica sul VPS resta aperta.
