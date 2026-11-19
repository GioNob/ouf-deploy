# R3 v25 · Identità stabile del Semantic

La firma OPERATE v25 lega il profilo del Semantic al trasporto southbound. Un restart o una ricreazione conforme può ricevere una porta nuova sotto la stessa firma. Il riferimento di confronto è una v24 riautorizzata sulla generazione viva e riconciliata. La qualifica Linux con traffico è prevista nel workflow R3.

## Profilo, epoca e autorità

Il campo `peerIngress` del flusso `WORKLOAD_GATEWAY` contiene il tipo `SEMANTIC_PROFILE` e la sua dichiarazione. Entrano nel digest firmato ruolo, nome approvato, digest immagine Docker, digest della configurazione, nome e ID rete, bridge, IPv4 sorgente e destinazione, direzione, TCP e porta. La composizione incrocia la tupla con A2 e il trasporto storico e verifica la faccia backend con la dichiarazione dell’identity provider. A2 e l’accettazione rimangono evidenza della preparazione originale. Il supervisore riceve lo stesso profilo tramite la configurazione riferita dal runtime firmato.

Il digest di configurazione copre Config (anche ENV e label), HostConfig, mount, eseguibile, argomenti e configurazione degli endpoint. L’hostname automatico è rappresentato come tale. I nomi DNS generati dal CID e le MAC hanno durata di generazione. Una modifica del digest immagine o della configurazione richiede approvazione ed emissione di un nuovo profilo. I valori ENV e l’inspect completo non entrano nella proiezione pubblicabile.

L’osservatore usa Docker API 1.44 e gli eseguibili vincolati per hash. Confronta l’inspect per nome con l’inventario della rete, esige un solo proprietario del nome e dell’IP e riconcilia l’endpoint con entrambe le estremità del veth e il bridge. L’epoca comprende boot, CID, PID, start ticks, namespace, endpoint e indici osservati. Il supervisore pubblica nel campo `semanticEpoch` del proprio stato il digest dell’epoca aperta. La sonda C rilegge il trasporto firmato, il driver dell’epoca southbound, i membri nft e la generazione Semantic prima di entrare nel netns per file descriptor. Il percorso delle versioni precedenti resta basato sull’evidenza A2.

## Filtro e transizioni

Il pre-exec prepara e verifica il template con tre set vuoti, ciascuno con capacità uno. Le catene e i predicati v24 restano la base del filtro. In bridge il dispositivo deve essere membro di `semantic_port`. In entrambe le famiglie il flusso deve inoltre corrispondere all’IPv4 abilitato in `semantic_open`. Rimangono i controlli su bridge, tupla TCP, conntrack e i drop terminali. Le regole ARP continuano a usare i binding L2 previsti dalla v24.

1. Al tick, compresi i controlli durante l’attesa cache, il supervisore entra nel lock comune, controlla il lease e l’autorità, verifica la generazione southbound e legge il driver vincolato dal journal.
2. Per un’epoca già aperta confronta il profilo vivo, l’indice installato e il footprint. Per una nuova epoca svuota i set in una transazione nft e rilegge la coppia chiusa. Occorrono osservazioni concordi prima di installare la porta.
3. Il supervisore prepara il nuovo indice con entrambe le abilitazioni vuote. Rilegge il template intero e i set, poi riconferma l’epoca. Un solo batch nft sostituisce il contenuto nelle due famiglie e abilita l’indirizzo. Il readback finale e una nuova osservazione precedono la pubblicazione dell’epoca.
4. Una discordanza richiude entrambi i versi. Il tick successivo può riconciliare una generazione valida. Un footprint estraneo o una chiusura non verificabile fanno fallire il controllo. La pubblicazione di QUIESCED verifica la chiusura sotto lo stesso lock. Le mutazioni del binding Semantic non rinnovano elementi DNS né concedono un lease.

## Modello di minaccia e confronto

Il modello comprende workload non privilegiati sul bridge, crash, restart, reboot, ricreazioni governate ed errori di apply. L’attribuzione del traffico si fonda sul dispositivo d’ingresso del netns host. Il controllo del demone Docker e CAP_NET_ADMIN nel netns host equivalgono a root. La scelta esplicita di un ifindex, la rinomina a caldo e le modifiche amministrative a caldo sono fuori modello. Per la rinomina è accettato il tempo fino al tick successivo.

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
| Rinomina amministrativa sulla porta ammessa | La regola installata continua a corrispondere. Al controllo il nome differisce | Chiude al tick |
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
  --source-sha256 "$REVIEWED_IDENTITY_SOURCE_SHA"
```

Il primo comando raccoglie la proiezione da sottoporre ad approvazione. Il secondo usa il profilo approvato e aggiunge solo il profilo e la sorgente v25 all’indice. Usare i byte risultanti e il loro SHA-256 con il normale issuer in modalità supersede, plan e apply, quindi con il normale upgrade a provider fermo. Il controllo della catena verifica head, predecessore, autorizzazione, documenti e wrapper. I comandi di emissione e upgrade sono quelli della consegna v25. Il cambio di versione richiede una firma. I successivi restart conformi riusano quella firma.

## Prove

La suite portabile ricompone un payload v24 distinto per ciascuna porta di riferimento e confronta il testo completo delle regole con i set v25 specializzati alla stessa porta. Esercita le quattro combinazioni del lifecycle, perdita di coerenza in osservazione, stage e pubblicazione, readback fallito, dinieghi del profilo e dell’allocatore, sonda C, tick del supervisore e upgrade. I dati Docker nelle prove portabili sono sintetici. [Test v25](../tests/test_semantic_provider_r3_v25.py)

La prova Linux usa namespace e processi privati, veth e nft reali, con risposte Engine sintetiche. Esegue TCP sul percorso riconciliato, sostituisce il veth, verifica lo scarto prima del rebind e la ripresa dopo il readback, con br_netfilter disattivato e attivato. Le quattro combinazioni di lifecycle riusano gli stessi byte del trasporto. Il controllo storico con assegnazione esplicita rimane un caso fuori modello. La qualifica richiede Linux con privilegi, nftables, iproute2 e i moduli di conntrack del bridge. [Workflow R3](../.github/workflows/semantic-provider-r3-integration.yml)
