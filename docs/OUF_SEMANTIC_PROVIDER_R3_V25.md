# R3 v25 · Identità stabile del Semantic

La firma OPERATE v25 lega il profilo del Semantic al trasporto southbound. Un restart o una ricreazione conforme può ricevere una porta nuova sotto la stessa firma. Il riferimento di confronto è una v24 riautorizzata sulla generazione viva e riconciliata. La qualifica Linux con traffico è prevista nel workflow R3.

## Profilo, epoca e autorità

Il campo `peerIngress` del flusso `WORKLOAD_GATEWAY` contiene il tipo `SEMANTIC_PROFILE` e la sua dichiarazione. Entrano nel digest firmato ruolo, nome approvato, digest immagine Docker, digest della configurazione, nome e ID rete, bridge, IPv4 sorgente e destinazione, direzione, TCP e porta. La composizione incrocia la tupla con A2 e il trasporto storico e verifica la faccia backend con la dichiarazione dell’identity provider. A2 e l’accettazione rimangono evidenza della preparazione originale. Il supervisore riceve lo stesso profilo tramite la configurazione riferita dal runtime firmato.

Il digest di configurazione copre Config (anche ENV e label), HostConfig, mount, eseguibile, argomenti e configurazione degli endpoint. L’hostname automatico è rappresentato come tale. I nomi DNS generati dal CID e le MAC hanno durata di generazione. Una modifica del digest immagine o della configurazione richiede approvazione ed emissione di un nuovo profilo. I valori ENV e l’inspect completo non entrano nella proiezione pubblicabile.

L’osservatore usa Docker API 1.44 e gli eseguibili vincolati per hash. Confronta l’inspect per nome con l’inventario della rete, esige un solo proprietario del nome e dell’IP e riconcilia l’endpoint con entrambe le estremità del veth e il bridge. L’epoca comprende boot, CID, PID, start ticks, namespace, endpoint e indici osservati. Il supervisore pubblica nel campo `semanticEpoch` del proprio stato il digest dell’epoca aperta. La sonda C rilegge il trasporto firmato, il driver dell’epoca southbound, i membri nft e la generazione Semantic prima di entrare nel netns per file descriptor. Il percorso delle versioni precedenti resta basato sull’evidenza A2.

## Filtro e transizioni

Il pre-exec prepara e verifica il template con tre set vuoti, ciascuno con capacità uno. Le catene e i predicati v24 restano la base del filtro. In bridge il dispositivo deve essere membro di `semantic_port`. In entrambe le famiglie il flusso deve inoltre corrispondere all’IPv4 abilitato in `semantic_open`. Rimangono i controlli su bridge, tupla TCP, conntrack e i drop terminali. Le regole ARP continuano a usare i binding L2 previsti dalla v24.

1. Il supervisore campiona il lease e calcola l’istante di risveglio. Se c’è tempo per il tick Semantic, sotto il lock comune rilegge lo stesso journal, controlla l’autorità e riconcilia la generazione southbound con il driver vincolato per hash.
2. A regime legge da `/proc` PID, start ticks e identità del netns prima e dopo i controlli di rete. Nel netns verifica IPv4 e indice del peer. Sull’host verifica tipo, nome, indici reciproci del veth e master. Ripete il controllo attorno alla lettura delle due tabelle nft. Al cambio d’epoca servono l’inspect per nome, l’inventario Docker della rete, i tre set vuoti riletti e osservazioni concordi prima di installare la porta.
3. Il supervisore prepara il nuovo indice con entrambe le abilitazioni vuote. Rilegge il template intero e i set, poi riconferma l’epoca. Un solo batch nft sostituisce il contenuto nelle due famiglie e abilita l’indirizzo. Il readback finale e una nuova osservazione precedono la pubblicazione dell’epoca.
4. Una discordanza richiude entrambi i versi. Il tick successivo può riconciliare una generazione valida. Un footprint estraneo o una chiusura non verificabile fanno fallire il controllo. La pubblicazione di QUIESCED verifica la chiusura sotto lo stesso lock. Le mutazioni del binding Semantic non rinnovano elementi DNS né concedono un lease.

### Tempi del tick e rinnovo

Il documento firmato `leaseRenewal` v25 include tre parametri espliciti.

| Parametro | Secondi ammessi | Criterio |
| --- | --- | --- |
| `semanticTickBudgetSeconds` | 0,70–3 | La fascia ordinaria è 1–3 s. Il minimo permette anche un heartbeat di 1 s con riserva di 0,20 s e tolleranza di 0,05 s. L’attesa di acquisizione consuma lo stesso budget. |
| `semanticCloseReserveSeconds` | 0,20–0,75 | Un solo budget per la transazione nft locale e tutte le riletture di chiusura. |
| `semanticFullObservationSeconds` | 5–60, intero | Intervallo tra un’osservazione completa e il momento in cui torna dovuta. La esegue il primo tick ammesso da quel momento. |

Siano `H = semanticTickBudgetSeconds + semanticCloseReserveSeconds + 0,05` e `R = max(dnsTimeoutSeconds + lockWaitSeconds, driverBudgetSeconds) + applyBudgetSeconds + 2 + 1 + 1`. Gli ultimi tre termini di R sono il minimo nft, il margine di commit e la guardia v24. Compose e bootstrap impongono `R + 2 ≤ immediateMinimumSeconds`, `immediateMinimumSeconds + H ≤ renewalMarginSeconds`, `H ≤ lockWaitSeconds` e `H < min(heartbeatSeconds, pollSeconds)`. Restano le verifiche v24 su tentativo, lease effettivo e retry. La corsia immediata conserva l’intero minimo anche dopo un tick di durata H. I 50 ms coprono il ritardo di scheduling previsto per consegnare il timeout, terminare il comando e rilasciare il lock. Un kernel sospeso o I/O ininterrompibile possono superare tale ipotesi temporale.

La v25 esegue il controllo nell’attesa già calcolata dalla v24. Nei cicli di cache usa il primo tra heartbeat, budget residuo dello scope, raccolta DNS e confini provati degli elementi. La raccolta dovuta ha priorità immediata. `inspect_cache()` conserva le sole letture v24. Il ciclo che la richiama sorveglia l’ingresso durante le attese lunghe.

Un rinnovo immediato rinvia soltanto la verifica. Anche dopo più rinnovi consecutivi, un ingresso verificato resta abilitato e uno chiuso resta chiuso. In entrambe le famiglie il supervisore installa l’indirizzo in `semantic_open` senza scadenza e lo rimuove esplicitamente alla chiusura. La v24 riautorizzata, riferimento del criterio (b), usa una regola statica sulla stessa porta e sulla stessa tupla. Mantenere quell’abilitazione durante il rinvio conserva il limite di ammissione della v24.

Il timer monotono copre anche verifica dell’autorità, file del driver e letture locali. Alla scadenza ordinaria il supervisore passa direttamente alla riserva. Dopo la transazione rilegge i tre set e, se ha già il footprint del driver, confronta l’intero template. Una chiusura provata permette la riconciliazione al prossimo tick. Una transazione fallita, una conferma tardiva o set ancora popolati producono `R3_SEMANTIC_CLOSE_UNVERIFIED`. Il tick rilascia il lock e lo scope fallisce.

Se il supervisore muore prima di rimuovere gli elementi, il lease finito scade e chiude l’uscita. L’ingresso può restare aperto come nella v24 con regola statica. È lo stesso rischio residuo accettato per la chiusura non verificata.

Lo stato espone `lastSemanticTick` con `durationMs` e `outcome`. Gli esiti sono `VERIFIED`, `DEFERRED`, `CLOSED` e `R3_SEMANTIC_CLOSE_UNVERIFIED`. Il campo `semanticEpoch` contiene il digest dell’epoca ammessa e torna nullo alla chiusura o quando la chiusura è incerta. Stato e checkpoint del journal riportano `lastSemanticVerifiedAgeMs`, il tempo monotono trascorso dall’ultimo tick verificato, anche a regime. Prima della prima verifica del processo il valore è nullo. Durante i rinvii l’età cresce a ogni pubblicazione e permette di osservare il ritardo per R-009. La sonda C usa il digest e verifica direttamente l’epoca e i membri correnti.

**F3.** `last_verified` vive solo in memoria. Un riavvio del supervisore richiude l’ingresso sotto lock prima dell’attivazione. Per riaprirlo occorrono una nuova osservazione completa e la riconciliazione con il driver firmato. All’interno dello stesso processo il controllo di monotonia conserva l’ultima epoca verificata anche dopo la chiusura.

Restart e ricreazione ordinari cambiano il processo o il netns. Un cambio di indirizzo, di rete o di veth altera l’indirizzo osservato, gli indici reciproci o il master. Una variazione esclusivamente amministrativa in Docker, ad esempio una rinomina del container che lascia intatti processo e rete, emerge al controllo completo successivo.

## Modello di minaccia e confronto

Il modello comprende workload non privilegiati sul bridge, crash, restart, reboot, ricreazioni governate ed errori di apply. L’attribuzione del traffico si fonda sul dispositivo d’ingresso del netns host. Il controllo del demone Docker e CAP_NET_ADMIN nel netns host equivalgono a root. La scelta esplicita di un ifindex, la rinomina a caldo e le modifiche amministrative a caldo sono fuori modello. Per la rinomina è accettato il tempo fino alla successiva osservazione completa.

Il gate richiede Linux dalla 6.6. Il plan di emissione e il preparatore all’avvio campionano il comportamento del kernel creando e distruggendo tre coppie veth con allocazione automatica in un netns privato. Il percorso di upgrade e il plan di start verificano anche la versione del kernel. La garanzia tra due osservazioni assume allocazione automatica crescente sul boot, prima del giro del contatore. Il campione finito qualifica il kernel osservato. Il supervisore rifiuta anche un indice riusato o regressivo osservato per un’altra epoca sullo stesso boot.

| Sequenza e momento del verdetto | v24 riautorizzata sulla generazione riconciliata | v25 |
| --- | --- | --- |
| Veth sostituito, prima della verifica | La porta nuova resta esclusa | Il vecchio indice non corrisponde, ingresso chiuso |
| Restart, provider fermo o avviato | Ammette sulla nuova porta dopo verifica e nuova firma | Ammette la stessa tupla dopo verifica sotto la firma esistente |
| Ricreazione conforme, provider fermo o avviato | Ammette dopo riconciliazione del nuovo CID | Ammette la nuova epoca e conserva il profilo |
| IP, bridge, dispositivo, protocollo, porta o stato conntrack errati | Scarta il pacchetto | Scarta il pacchetto |
| Immagine o configurazione diversa, due proprietari, letture discordi | Manca la generazione univoca conforme da riautorizzare | Svuota i set e nega |
| Cambio porta durante stage o pubblicazione | Manca una riconciliazione valida sulla nuova porta | L’indice precedente non corrisponde, il controllo richiude |
| Kernel non qualificato o regressione osservata | Nessuna riautorizzazione nel confronto richiesto | Diniego |
| Rinomina amministrativa sulla porta ammessa | La regola installata continua a corrispondere. Al controllo il nome differisce | Chiude all’osservazione completa |
| Secondo processo in un container che condivide il netns ammesso | La stessa tupla arriva sullo stesso veth | Stesso verdetto |

**Rischio residuo comune.** Nel netns condiviso il filtro attribuisce la medesima tupla a entrambi i workload. Una mitigazione successiva può controllare le richieste di condivisione nelle creazioni governate e chiudere al rilevamento di un’ulteriore condivisione. La registrazione di dettaglio compete al registro privato.

## Emissione e upgrade offline

Usare una consegna locale revisionata e l’indice v24 vincolato. Il preparatore stampa JSON canonico. I parametri di installazione provengono dall’indice e dai profili dell’ente. I due modi del comando sono distinti.

```sh
python3.13 -I -B scripts/prepare-semantic-provider-r3-v25-inputs.py \
  --v24-inputs "$V24_INPUTS" --v24-inputs-sha256 "$V24_INPUTS_SHA" profile
python3.13 -I -B scripts/prepare-semantic-provider-r3-v25-inputs.py \
  --v24-inputs "$V24_INPUTS" --v24-inputs-sha256 "$V24_INPUTS_SHA" inputs \
  --profile "$APPROVED_PROFILE" --profile-sha256 "$APPROVED_PROFILE_SHA" \
  --lease-renewal "$APPROVED_RENEWAL" --lease-renewal-sha256 "$APPROVED_RENEWAL_SHA" \
  --source-sha256 "$REVIEWED_IDENTITY_SOURCE_SHA"
```

Il primo comando raccoglie la proiezione da sottoporre ad approvazione. Il secondo aggiunge il profilo e la sorgente v25 all’indice e vincola il documento di rinnovo con i tre parametri temporali. Usare i byte risultanti e il loro SHA-256 con il normale issuer in modalità supersede, plan e apply, quindi con il normale upgrade a provider fermo. Il controllo della catena verifica head, predecessore, autorizzazione, documenti e wrapper. I comandi di emissione e upgrade sono quelli della consegna v25. Il cambio di versione richiede una firma. I successivi restart conformi riusano quella firma.

## Prove

La suite portabile ricompone un payload v24 distinto per ciascuna porta di riferimento e confronta il testo completo delle regole con i set v25 specializzati alla stessa porta. Il replay del bootstrap copre dodici rinnovi immediati a ciascuna cadenza di 5, 30 e 60 s, la deriva al primo tick utile e il riavvio con i set ancora popolati. Esercita anche le quattro combinazioni del lifecycle, perdita di coerenza in osservazione, stage e pubblicazione, readback fallito, dinieghi del profilo e dell’allocatore, sonda C e upgrade. I dati Docker nelle prove portabili sono sintetici. [Test v25](../tests/test_semantic_provider_r3_v25.py)

La prova Linux usa namespace e processi privati, veth e nft reali, con risposte Engine sintetiche. Esegue TCP sul percorso riconciliato, sostituisce il veth, verifica lo scarto prima del rebind e la ripresa dopo il readback, con br_netfilter disattivato e attivato. Controlla che l’indirizzo resti presente in entrambe le famiglie attraverso tre rinnovi simulati e che `QUIESCED` svuoti i tre set. Le quattro combinazioni di lifecycle riusano gli stessi byte del trasporto. Il controllo storico con assegnazione esplicita rimane un caso fuori modello. La qualifica richiede Linux con privilegi, nftables, iproute2 e i moduli di conntrack del bridge. [Workflow R3](../.github/workflows/semantic-provider-r3-integration.yml)
