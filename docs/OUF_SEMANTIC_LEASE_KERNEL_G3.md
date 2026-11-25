# Kernel del lease g3 · contratto v1

Linea A3, sprint-03/63h e 63j, passi 1 e 2a di DN-A-2. Il contratto distingue l'autorizzazione a eseguire una politica dall'identità delle tabelle che la realizzano durante un boot. La libreria calcola e verifica valori JSON in memoria. Il guard e la riconciliazione applicano le transizioni di boot. Il passo 2b riguarda supervisore e start governato.

## Autorità e origine dei riferimenti

| Riferimento | Origine e contenuto | Durata |
|---|---|---|
| Politica | La testa R3 corrente con decisione `OPERATE` firma l'ID della proiezione e `footprint`, SHA-256 della coppia vuota attesa. L'emittente usa la configurazione autorizzata e il compilatore sigillato per generare l'immagine dichiarativa secondo la proiezione canonica. Può usare un ambiente di riferimento isolato. Gli input e l'output devono essere riproducibili indipendentemente dal kernel osservato sul destinatario. | Per la testa. L'osservazione locale serve esclusivamente al confronto. |
| Owner | La stessa testa firma lo SHA-256 dei byte dell'owner immutabile. L'owner fissa generazione 3, scope (famiglie, nome tabella, flussi), lock comune, percorsi privati di journal, sigillo e ricevute, percorsi e digest di binari/compilatore, profilo nft ammesso, politica di ammissione degli indirizzi, massimi TTL e fonte autorizzata delle scadenze. | Per la configurazione. ID del boot, handle, contatori, membri, scadenze correnti e stato operativo vivono negli archivi locali. |
| Sigillo locale | Documento JSON `ouf.lease-kernel.seal.g3.v1` con `head` (SHA-256 della testa autenticata), `owner` (SHA-256 dei byte), `generation`, `bootId`, `handles` e `structureHash`. I due vettori di handle seguono le dichiarazioni nel loro ordine canonico. Il digest copre l'associazione di ciascun handle alla dichiarazione in quella posizione. | Una sola istanza qualificata per testa, owner, generazione e boot. Il sigillo ha custodia locale e nessuna firma R3 propria. |

D-057 riconosce che un identificatore allocato dall'ambiente può avere un consumatore funzionale senza appartenere all'identità permanente. Il kernel rialloca gli handle. Qui il consumatore è il controllo di sostituzione della stessa istanza nel boot corrente. Un reboot conforme può quindi riusare la stessa testa (D-045). La transizione iniziale a g3 richiederà una firma.

## Formato nft e proiezioni

L'owner immutabile contiene `nftPath`, `nftSha256` e `nftProfile`. Prima della firma, l'installazione chiama `read_nft_profile(nftPath, nftSha256)`. Il comando esistente verifica percorso, custodia e SHA-256 del binario prima e dopo la lettura `-j list tables`. Dal primo record `metainfo` la funzione ricava il candidato `{"version": <stringa>, "jsonSchemaVersion": <intero positivo>}`. L'emittente qualifica la forma JSON e firma il digest dell'owner che contiene il candidato. Boot e tick ricevono il profilo solo dopo la verifica della testa e del digest dell'owner.

Per entrambe le famiglie il contratto confronta esattamente versione e schema con i valori firmati prima di proiettare il listato. Un profilo assente o malformato, una versione diversa o uno schema diverso danno `G3_NFT_VERSION`. Le forme di listato estranee alla grammatica danno `G3_NFT_FORMAT`. Al cambio del pacchetto nftables si acquisiscono il nuovo pin e il profilo candidato, si ripete la qualifica sulle tabelle del lease e si autorizza il nuovo owner tramite migrazione per generazioni D-050 o nuova firma della politica. Boot, riconciliazione e tick possono solo verificare il profilo selezionato.

* L'ingresso è un oggetto JSON con le sole chiavi `inet` e `bridge`. Il lettore deve rifiutare chiavi duplicate e numeri non JSON prima della decodifica. Ogni documento contiene la sola lista `nftables`. Il primo record ha la sola chiave `metainfo` con `version`, `json_schema_version` intero e `release_name` stringa facoltativa. Il record si verifica prima di escluderlo da entrambe le impronte.
* Segue una sola `table` per famiglia. Le due tabelle hanno lo stesso nome. Ogni record ha un solo tipo. Le dichiarazioni successive sono `set`, `chain` e `rule`, legate esattamente alla famiglia e tabella. Ogni chain referenziata deve figurare nel listato completo. Nel listato vivo ogni dichiarazione porta un handle intero positivo. Nell'immagine del compilatore gli handle possono essere omessi.
* Si conservano nomi, tipi, flag, hook, priorità, policy di chain, espressioni e verdetti. I set nominati sono `provider_N` di tipo `ipv4_addr` o `ipv6_addr` con flag `timeout`. Le chain base hanno tipo `filter`, hook input/output/forward, priorità intera e policy accept/drop. Le istruzioni ammesse sono `match` (op, left, right), `jump` (target), `counter` anonimo (packets, bytes), `accept` e `drop`. Gli operandi di match del compilatore si confrontano integralmente, compresi i set costanti inline.
* La proiezione strutturale elimina soltanto il record metadati verificato, i due valori osservati dei contatori anonimi e i membri `elem` delle dichiarazioni di set. Conserva l'istruzione counter. L'impronta politica esclude anche gli handle. Il sigillo li associa nuovamente all'intera proiezione. L'ordine delle chiavi JSON è irrilevante. La proiezione raggruppa tabella, set, chain e regole. Conserva la sequenza relativa di set e di chain. Raggruppa le regole per nome della chain e conserva il loro ordine al suo interno e quello delle istruzioni. Gli handle seguono la stessa permutazione. Invertire due regole distinte nella stessa chain cambia entrambe le impronte. Per due regole identiche il sigillo rileva l'inversione dei loro handle.

`P = {"schema": "ouf.lease-kernel.structure.g3.v1", "tables": …}`, dove ogni famiglia contiene la lista dei record proiettati. L'impronta firmata è `digest(P)`; `structureHash = digest({"projection": P, "handles": handles})`. Il digest usa la serializzazione canonica g2. Gli helper g2 per struttura e stabilità si applicano solo ai contatori e alle intestazioni dichiarative validate. Applicarli ricorsivamente al listato intero perderebbe la distinzione tra membri mutabili e dati delle regole.

### Qualifica del formato

I due campioni `inet sample` sono **reali nel formato, sintetici nel contenuto**. In 1.0.9 i set precedono la chain. In 1.1.3 la chain precede i set. Entrambi emettono una lista per uno o più flag, omettono `flags` per il set privo di flag ed esprimono `timeout` ed `expires` del membro in secondi interi. A3-20 confronta tutti i record dei due campioni e calcola l'impronta del sottoinsieme del lease nelle due serializzazioni, ciascuna con il proprio profilo dichiarato. I set aggiuntivi del campione illustrano forme esterne al contratto del lease. La fixture a due famiglie riproduce l'ordine della 1.1.3. [Campione 1.0.9](../tests/fixtures/inet-v1.0.9.json) · [Campione 1.1.3](../tests/fixtures/inet-v1.1.3.json) · [Fixture sintetica](../tests/fixtures/lease-kernel-g3-nft-1.1.3-synthetic.json)

**Prima dell'installazione g3**, al passo 3 e all'approvazione n. 6, l'operatore confronta i listati reali di entrambe le tabelle del lease con il profilo dell'owner. Per ciascuna famiglia verifica metadati, dichiarazioni, forma dei membri e handle. La verifica della forma popolata richiede l'osservazione di un lease già attivo. Conserva ogni listato in un nuovo file privato. Il comando usa il binario qualificato per digest.

```sh
(umask 077; set -C; <nftPath> -j list table <famiglia> <tabella> > <file-privato>)
```

## API pura

| Funzione | Precondizione, verifica ed esito |
|---|---|
| `policy_footprint(tables, nft_profile)` | Verifica il profilo e richiede set vuoti (campo assente o lista vuota). Restituisce il digest esadecimale. |
| `local_seal(head, owner, generation, boot_id, tables, nft_profile)` | Richiede due digest SHA-256 esadecimali minuscoli, generazione intera 3, UUIDv4 canonico minuscolo del kernel e coppia viva vuota con handle conforme al profilo. Costruisce il documento. Il writer deve già avere verificato origine, custodia e uguaglianza con la politica firmata. |
| `verify_boot(seal, current_boot_id, head, owner, tables, nft_profile, footprint)` | Verifica in una sola proiezione profilo, vuoto, impronta firmata, binding e sigillo con handle. |
| `verify_tick(policy, seal, tables, membership_policy, now)` | Il contesto richiede `head, owner, generation, footprint, nftProfile, bootId`. I primi cinque valori provengono dalla testa e dall'owner autenticati. Il chiamante legge il boot ID corrente dal kernel. Sulla stessa lettura il tick verifica metadati, impronta politica, struttura e handle del sigillo, membri e scadenze. |
| `classify_journal(journal, current_boot_id)` | Restituisce una delle tre classificazioni sotto. Il chiamante verifica sotto lock custodia del journal e corrispondenza esatta con testa/owner/generazione selezionati. |

Le funzioni di verifica terminano con `None` al successo. Proiezione, costruzione e verifiche sollevano `ValueError(codice)` al diniego. Un successo della libreria può soddisfare una precondizione del writer. La concessione di autorità richiede l'intera transizione.

### Membri e scadenze al tick

`membership_policy` associa ciascun nome di set a `{"maxSeconds": N, "validUntil": {indirizzo: scadenza, …}}`. Per ogni flusso il chiamante ricava il massimo dall'owner e gli indirizzi con le rispettive scadenze dalla ricevuta di ammissione corrente, verificata per lo stesso binding e per il rinnovo in esame. Deve verificarne anche scope, provenienza DNS e restrizioni sugli indirizzi. Ricavare questi dati dal listato da verificare renderebbe circolare il controllo.

La verifica esige esattamente i set e gli indirizzi attesi in entrambe le famiglie; un set atteso vuoto ha mappa vuota. Un membro assente, estraneo, duplicato o di famiglia errata dà `G3_MEMBERS`. Le chiavi sono indirizzi canonici e senza zone. Ogni membro nft è `{"elem": {"val": indirizzo, "expires": secondi, "timeout": secondi}}`; `timeout` è facoltativo. Vengono ammessi solo secondi interi. Deve valere `0 < expires <= timeout <= maxSeconds`, usando il massimo se il timeout manca. Inoltre `now + expires <= validUntil[indirizzo]`. `now` è l'istante di osservazione in secondi monotoni interi di questo boot e le scadenze sono sulla stessa base. L'owner fissa `tickSeconds` e `renewalMarginSeconds` in secondi positivi finiti. Il margine deve superare il periodo del tick più un secondo, per il troncamento di `expires`. La riconciliazione verifica il vincolo con `verify_renewal_margin`. Il tick del passo 2b dovrà rispettare il margine nella pianificazione. Il writer usa osservazioni fresche e verifica i propri limiti di tempo prima dell'effetto. Un limite superato, TTL zero o tipo errato dà `G3_TTL`. Un rinnovo legittimo può aggiornare membri e scadenze mantenendo entrambe le impronte strutturali.

## Journal, residuo e transizioni

Il documento di stato ha forma chiusa con `schema = ouf.lease-kernel.journal.g3.v1`, `head`, `owner`, `generation = 3`, `bootId`, `state`, `leaseAuthorized` e `startAuthorized`. I writer datano ogni transizione sotto il lock comune. La ricevuta di ammissione dei membri appartiene alla transazione di rinnovo. Va custodita e riletta con il journal. Il flag di start rimane falso nel journal del lease; lo start governato verifica la propria autorità R3.

* `QUIESCENT` richiede `QUIESCED` o `BLOCKED`, entrambi i flag falsi e ID validi. Copre una forma di journal ammissibile al guard. Solo `QUIESCED` è candidato allo start.
* `RESIDUE_PREVIOUS_BOOT` richiede ID validi diversi e una transizione coerente: `LEASE_READY` o `LEASE_UPDATING` con lease vero, oppure `QUIESCING` con lease falso. Il guard deve ancora escludere writer e coorte attiva prima di Docker, con evidenza indipendente dal suo socket.
* `DENY` copre anche ID mancante o malformato, journal attivo del boot corrente, binding malformato, stato sconosciuto e flag incoerenti. Un binding sintatticamente valido ma diverso dalla selezione corrente dà `G3_BINDING` al chiamante. La scadenza degli elementi non data un journal.

| Operazione | Ingresso e controlli sotto lock | Pubblicazione o diniego |
|---|---|---|
| Boot / primo guard | Journal classificato, binding e coorte verificati. Conservare evidenza e claim prima di effetti. All'ingresso nel nuovo boot ricostruire dalla closure solo se manca l'intera coppia. Se presente verificare coppia completa, vuoto, footprint firmato e provenienza. | Al cambio di boot, anche con handle coincidenti, CAS a `BLOCKED/false/false` con ID corrente e ricevuta. Il guard consente il proseguimento di Docker, R3 rimane chiuso. Coppia parziale, altro contenuto o set popolati danno `G3_NFT_FORMAT`, `G3_POLICY_DRIFT` o `G3_SETS_NOT_EMPTY`. Journal ambiguo dà `DENY`. |
| Boot / ripresa o seconda invocazione | Rileggere selezione, claim, ricevuta per questo boot e coppia. Dopo caduta tra nft e CAS, riprendere solo il claim custodito e il suo readback qualificabile. | Ripetere la verifica dell'esito già pubblicato. Una ricevuta attesa mancante o una sostituzione nello stesso boot lascia il gate chiuso (`G3_BINDING` o `G3_SEAL_DRIFT`). |
| Riconciliazione | Da `BLOCKED`. Plan e apply legati al digest, stessa testa corrente, owner e coorte ferma, epoche terminali, supervisore in attesa, set vuoti e politica esatta. Verificare l'evidenza del guard e gli handle già registrati per questo boot. | Pubblicare/verificare il sigillo e CAS a `QUIESCED/false/false`. Un secondo apply verifica il risultato. Drift o binding diverso negano con `G3_SEAL_DRIFT`, `G3_POLICY_DRIFT` o `G3_BINDING`. |
| Start governato | Solo da `QUIESCED/false/false` del boot corrente. Testa OPERATE valida, supervisore ed epoche conformi, vuoto, confronto con politica e sigillo. | `LEASE_READY/true/false` solo nel percorso di apertura governato. Da `BLOCKED` o stato incompatibile: `DENY`. Un riferimento scaduto o alterato dà `G3_BINDING` o `G3_SEAL_DRIFT`. |
| Tick / rinnovo | Da `LEASE_READY/true/false`. Prima del rinnovo verificare l'istanza e i membri attesi, poi `LEASE_UPDATING/true/false`; per il commit verificare il nuovo readback con la nuova ricevuta. | Successo a `LEASE_READY/true/false`. `G3_POLICY_DRIFT`, `G3_SEAL_DRIFT`, `G3_BINDING`, `G3_MEMBERS`, `G3_TTL` o formato/versione negati chiudono R3. Nessun rinnovo su tabelle sostituite. |
| Stop | Il writer pubblica `QUIESCING/false/false` prima della revoca. Verifica identità delle tabelle prima di modificarle. | Stato intermedio chiuso durante la revoca. Un errore di binding/struttura conserva evidenza e impedisce la riapertura. |
| Quiescenza | Verificare revoca, set vuoti, binding e sigillo, CID fermi ed epoche concluse per lo stop R3. | CAS a `QUIESCED/false/false`. Set residui: `G3_SETS_NOT_EMPTY`. Tabella estranea: `G3_POLICY_DRIFT` o `G3_SEAL_DRIFT`. |

Al diniego del tick il writer inibisce il rinnovo, conserva l'evidenza e pubblica `BLOCKED/false/false` con CAS sul journal conosciuto. Può revocare soltanto attraverso un backend di cui abbia verificato l'identità. Un CAS perso conserva il documento concorrente e lascia il gate chiuso. La scomparsa della coppia dopo l'emissione del sigillo nello stesso boot è drift, anche se sarebbe possibile ricostruire le regole dal compilatore.

## Boot

Il dispatcher seleziona la ricevuta di generazione 3 e acquisisce il lock comune. `runner` indica il file eseguibile dalla closure. Gli helper `source/tools/g3_contract.py` e `source/tools/g3_journal.py` vengono letti per hash nella stessa closure e caricati in un namespace privato. La ricostruzione usa i due moduli `materialize_southbound_kernel*` già sigillati dal dispatcher. Il profilo punta tramite percorso e digest all'owner e alla configurazione di boot. Quest'ultima contiene `head`, `projection`, `expectedFootprint`, kernel, lock e percorso nft. Il passo 3 deve pubblicarla a partire dalla testa autenticata e dalla politica qualificata in modo indipendente.

La composizione riserva le directory di evidenza alla selezione. L'owner specifica `generation`, `kernel`, `commonLockFile`, `journalFile`, `nftPath`, `nftSha256`, `nftProfile`, i tempi di rinnovo e due directory private preesistenti, `receiptDirectory` e `sealDirectory`. In `cohortCgroups` associa i ruoli `adapter` e `southbound` alle foglie cgroup v2 dei rispettivi CID completi, in forma cgroupfs o systemd. Il guard legge `cgroup.events` sotto il lock. Ammette una foglia assente nella gerarchia unificata host verificata oppure `populated 0`, che comprende i discendenti. La composizione deve legare i percorsi effettivi ai due CID e garantire la visibilità della gerarchia host nella sandbox dei precomandi. Tutti i writer del coordinatore devono rispettare il lock comune.

Per ogni nuovo boot, il guard copia i byte del journal in `previous.json` in una directory temporanea privata sotto `receiptDirectory`. Legge le due famiglie nft e scrive `claim.json` nella stessa directory. Il claim lega ID corrente, digest del predecessore e modo di recupero. Per la coppia presente fissa anche gli handle. Una rinomina esclusiva pubblica insieme i due file sincronizzati in `receiptDirectory/<bootId>/`. Se il guard si interrompe dopo la copia o fallisce la lettura nft, la copia temporanea resta disponibile. Il tentativo successivo riparte dal journal e dalle tabelle correnti. Anche in ripresa, il guard sincronizza `receiptDirectory` e verifica copia e claim prima di eseguire un batch nft.

Solo la coppia interamente assente autorizza una ricostruzione vuota. Il readback verificato con l'impronta firmata entra in `guard.json` prima del CAS a `BLOCKED/false/false`. Il dispatcher può così consentire Docker con R3 chiuso. Un batch già eseguito si riprende dalla coppia qualificabile. Dopo `guard.json`, anche una ricostruzione identica con altri handle dà diniego.

Il guard scrive e sincronizza i byte in un file privato con nome univoco nella directory del boot. Su Linux pubblica `guard.json` con `renameat2(RENAME_NOREPLACE)` e sincronizza la directory prima del CAS. Se la scrittura si interrompe, il tentativo successivo ignora il temporaneo e verifica di nuovo la coppia nft. Se la rinomina è già avvenuta, sincronizza la directory e verifica la ricevuta definitiva prima del CAS. Una collisione al momento della pubblicazione conserva entrambi i file e interrompe il tentativo.

Nel boot corrente, `BLOCKED` richiede la ricevuta del guard. `QUIESCED` richiede inoltre sigillo e riconciliazione completata. Per la prima attivazione nello stesso boot della migrazione, il passo 3 può fornire `initialSeal`, nome di un file della closure il cui digest vincola il sigillo già installato. Il ramo iniziale verifica la coppia vuota, il binding corrente e quel digest. Un journal attivo nello stesso boot dà sempre diniego al guard. I writer del passo 2b possono usare `transition_locked` soltanto sotto lock e dopo i controlli della loro operazione. Il CAS verifica i byte precedenti e lega l'autorità all'ID riletto dal kernel.

Al replay il guard rilegge i byte del journal sotto il lock comune e sincronizza la directory che contiene `journalFile` prima di consentire Docker. Questo completa anche un CAS interrotto subito dopo `os.replace`. Se verifica una riconciliazione completata, il guard sincronizza anche la ricevuta finale verificata e la sua directory.

## Riconciliazione

`g3_reconcile.plan(pointer, observe)` e `apply(pointer, plan_sha256, observe)` acquisiscono, nell'ordine, i due `operationLockFiles` dei ruoli nell'ordine canonico di D-050, il flock su `authorizationDirectory` e il lock comune. Rileggono la selezione sotto questi lock. Il chiamante fornisce un osservatore attendibile. A ogni invocazione `observe(state)` autentica la testa corrente e l'owner dai byte firmati, osserva entrambi i CID fermi, le epoche terminali e il supervisore in attesa sulla stessa testa. Usa lettori compatibili con i lock già acquisiti e restituisce un oggetto con i campi seguenti.

| Campi | Fonte |
|---|---|
| `head`, `owner`, `generation`, `decision`, `projection`, `footprint` | Testa OPERATE vigente e digest autenticato dell'owner |
| `bootId` | Boot corrente |
| `cohortStopped`, `epochsTerminal`, `supervisor` | Letture correnti dei due ruoli e del supervisore, valori richiesti `true`, `true`, `WAITING` |

La CLI usa lo stesso contratto. L'owner indica in `reconcileObserver` il percorso e lo SHA-256 di un eseguibile di sola lettura. La chiamata `observe <head>` restituisce il JSON su stdout. Il passo di composizione deve collegare questo ingresso ai lettori autenticati dell'installazione. Gli argomenti operativi sono i seguenti, con `<riconciliazione-g3>` per il launcher del modulo installato.

```sh
<riconciliazione-g3> --pointer <puntatore> plan
<riconciliazione-g3> --pointer <puntatore> apply <planSha256>
```

Il plan verifica il binding del journal bloccato, il digest della copia precedente, il claim, la ricevuta del guard, i set vuoti, la politica firmata e gli handle. Restituisce il piano canonico e il suo SHA-256 in sola lettura. L'apply ripete i controlli, confronta il digest e riserva `<bootId>/reconcile/`. Scrive in esclusiva `plan.json`, poi `seal-intent.json`, poi il sigillo in `sealDirectory/<bootId>.json`. Esegue il CAS a `QUIESCED/false/false`, verifica il digest dei byte pubblicati e scrive `receipt.json` in esclusiva. Le scritture e la directory vengono sincronizzate. La ricevuta lega piano, boot, sigillo e journal conclusivo.

| Interruzione o esito | Ripresa o codice |
|---|---|
| Dopo la scrittura completa di `plan.json` | Il nuovo plan verifica gli stessi input. L'apply verifica i byte del piano custodito, sincronizza il file e la sua directory prima di procedere al sigillo e al CAS. |
| Dopo la prenotazione del sigillo con sigillo mancante | `HELD / G3_SEAL_DRIFT`. Restano leggibili piano e prenotazione. |
| Dopo la scrittura completa del sigillo, anche prima di `fsync` | L'apply verifica i byte attesi e l'identità del file aperto, sincronizza il file e poi `sealDirectory`. Solo a quel punto esegue il CAS. Un errore di sincronizzazione lascia il journal in `BLOCKED`. |
| Dopo la rinomina del journal, prima della ricevuta | L'apply rilegge il journal e sincronizza la sua directory prima di completare la ricevuta. La stessa verifica su `BLOCKED` precede la prenotazione della riconciliazione. |
| Dopo la scrittura completa di `receipt.json` | Il ritentativo verifica i byte, sincronizza il file e la sua directory, poi restituisce la ricevuta. Un errore di sincronizzazione dà `HELD`. |
| Directory incompleta, lock occupato o file privato illeggibile | `HELD`, evidenza conservata. |
| `G3_JOURNAL_DENIED`, `G3_BINDING`, `G3_TRANSITION_DENIED` | Journal incompatibile, binding o transizione errati. |
| `G3_COHORT`, `G3_RECONCILE_OBSERVATION` | Prova di coorte ferma o contesto autenticato insufficiente. |
| `PARTIAL_TABLE_PAIR_PRESERVED`, `G3_NFT_FORMAT`, `G3_NFT_VERSION` | Coppia parziale, grammatica o profilo discordanti. |
| `G3_SETS_NOT_EMPTY`, `G3_POLICY_DRIFT`, `G3_SEAL_DRIFT` | Membri presenti, politica diversa o istanza cambiata. |
| `G3_PLAN_DRIFT`, `FOREIGN_PUBLICATION_PRESERVED` | Piano variato o perdita del CAS. |
| `G3_TTL` | Margine insufficiente o scadenza incompatibile. |
| Exit 0 / 1 | Il dispatcher consente / nega Docker. La CLI restituisce piano o ricevuta / `HELD`. |

## Custodia del sigillo · D-065

Archivio nuovo: evidenza operativa privata per boot, durevole e locale. L'owner indica la directory di stato della generazione e il percorso del riferimento attivo. Il sigillo e la ricevuta che lo vincola per digest sono separati dalla closure firmata. Custodia root, directory private, file regolari privati, protezione da link e sostituzioni. Solo guard e riconciliazione scrivono, entrambi sotto il lock comune. Il supervisore e `operate` verificano in lettura.

Alla cattura si conservano i byte del journal precedente, binding, claim e ricevuta, poi il sigillo con i digest prima/dopo. Pubblicazione esclusiva delle evidenze, CAS e sincronizzazione durevole del riferimento. Per la stessa tupla un sigillo già emesso è un riferimento fisso: guard e riconciliazione possono confermarlo, mai ricalcolarlo per assorbire drift. Anche la perdita del sigillo dopo una prima emissione impone il diniego. La prova di prima emissione o di ripresa proviene dalla catena custodita. Un semplice percorso vuoto è insufficiente. La custodia e l'assenza di writer estranei sono parte del modello di fiducia locale.

Cambio di boot, testa, owner o generazione invalida il riferimento attivo. Un ripristino recupera l'archivio come evidenza, verifica custodia, digest, claim e catena su host isolato. Il nuovo boot deve ricostruire o qualificare la propria coppia e passare dalla riconciliazione prima della riapertura. Copiare handle o scadenze monotone da backup non conferisce autorità. La registrazione in distinta D-065 è affidata a Claude.

## Interfaccia 2→3 e qualifica

D-080 conserva il formato g2, i byte della closure e il confronto esatto g2. Il passo 3 aggiungerà a D-050 la transizione esplicita da g2 quiescente, a coorte ferma: plan approvato, staging separato di owner/journal/profilo/ricevuta g3, verifica e switch con CAS, emissione della testa N+1, upgrade e finalize. Prima della firma il predecessore esatto deve poter riprendere o fare restore; dopo `supersedes` serve ripresa governata o testa successiva autorizzata. Questo contratto non seleziona una generazione.

| PET D-082 · linea A3 | Osservazione decisiva |
|---|---|
| `Contract.test_a3_01`–`04` (prefissi dei metodi) | Politica compilata senza handle, nuova istanza, cambio di binding e riordino con sigillo locale coerente ma politica firmata diversa. |
| `Contract.test_a3_05`–`09` | Rinnovo valido, contatori e metadati, appartenenza nelle due famiglie, unità e limiti TTL, formati chiusi, ordine e dati inline. |
| `Contract.test_a3_10` | Matrice stato/autorità del journal con ID corrente, precedente, mancante o invalido. |
| `NativeContract.test_a3_11_recreated_pair` | Linux opt-in, creazione e ricreazione in una sola netns. Il nuovo handle cambia il sigillo con politica uguale. |
| `Boot.test_a3_12`–`19` | Guard, residuo e prima attivazione, rifiuti, CAS, replay e interruzioni a ogni pubblicazione. |
| `Boot.test_a3_15` | 63j-d, 6 casi portabili superati su Windows. La ripresa dopo la copia, dopo la pubblicazione del claim e durante la pubblicazione del guard raggiunge `BLOCKED/false/false` con un solo batch nft. Una collisione conserva la ricevuta preesistente. |
| `Boot.test_a3_18_resume_complete_seal_before_fsync` | 63j-d, superato su Windows. Dopo l'arresto con tutti i byte scritti, la prova osserva nell'ordine il sync del sigillo, il sync della sua directory e il CAS. Verifica anche il diniego se fallisce uno dei due sync. |
| `Boot.test_a3_15_sweep_boot_publications` | 63j-e, 50 interruzioni su fixture nuove. Con coppia assente la ripresa arriva a `BLOCKED` con un solo batch nft. Con coppia presente preserva gli handle e usa zero batch. |
| `Boot.test_a3_18_sweep_apply_publications` | 63j-e, 24 interruzioni. In 12 casi il ritentativo completa o conferma la ricevuta. Negli altri 12 il plan e l'apply rifiutano l'evidenza incompleta e ne preservano i byte. |
| `Boot.test_a3_15_and_18_retry_journal_directory_after_replace`, `Boot.test_a3_18_retry_plan_and_receipt_before_fsync` | 63j-e, errore di sync al ritentativo sul journal dopo la rinomina e su piano e ricevuta dopo l'ultimo byte. Il guard e l'apply propagano l'errore. |
| `Format.test_a3_20`–`21` | Ordini reali 1.0.9/1.1.3 e limite del margine di rinnovo. |
| `NativeContract.test_a3_22_runner_reconcile_and_tick` | Netns opt-in, dispatcher, ricostruzione nft, riconciliazione e diniego del tick a handle sostituiti. |

Per 63j-e le suite portabili su Windows hanno superato 31 prove di boot e riconciliazione g3, 14 di contratto g3, 28 di kernel e migrazione g2, 12 di R3 v12 e 24 di operate. Lo sweep usa il CAS del dispatcher e file reali nella fixture. Il modello portabile simula il batch nft e la sincronizzazione delle directory. L'esito CI Linux di questa revisione, inclusa l'esecuzione nativa di A3-22, resta da acquisire.

R-025/A3 resta aperto per il tick e il riconoscimento in operate del passo 2b, la transizione del passo 3 e la qualifica del passo 4 con due boot reali, systemd e Docker. Le prove del passo 1 misurano le verifiche in memoria e, nel caso nativo, l'identità delle tabelle in un unico boot.
