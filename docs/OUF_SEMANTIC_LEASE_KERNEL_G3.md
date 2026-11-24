# Kernel del lease g3 · contratto v1

Linea A3, sprint-03/63h, passo 1 di DN-A-2. Il contratto distingue l'autorizzazione a eseguire una politica dall'identità delle tabelle che la realizzano durante un boot. La libreria calcola e verifica valori JSON in memoria. La tabella delle transizioni specifica gli obblighi dei futuri writer.

## Autorità e origine dei riferimenti

| Riferimento | Origine e contenuto | Durata |
|---|---|---|
| Politica | La testa R3 corrente con decisione `OPERATE` firma l'ID della proiezione e `footprint`, SHA-256 della coppia vuota attesa. L'emittente usa la configurazione autorizzata e il compilatore sigillato per generare l'immagine dichiarativa nell'ordine del listato. Può usare un ambiente di riferimento isolato. Gli input e l'output devono essere riproducibili indipendentemente dal kernel osservato sul destinatario. | Per la testa. L'osservazione locale serve esclusivamente al confronto. |
| Owner | La stessa testa firma lo SHA-256 dei byte dell'owner immutabile. L'owner fissa generazione 3, scope (famiglie, nome tabella, flussi), lock comune, percorsi privati di journal, sigillo e ricevute, percorsi e digest di binari/compilatore, profilo nft ammesso, politica di ammissione degli indirizzi, massimi TTL e fonte autorizzata delle scadenze. | Per la configurazione. ID del boot, handle, contatori, membri, scadenze correnti e stato operativo vivono negli archivi locali. |
| Sigillo locale | Documento JSON `ouf.lease-kernel.seal.g3.v1` con `head` (SHA-256 della testa autenticata), `owner` (SHA-256 dei byte), `generation`, `bootId`, `handles` e `structureHash`. I due vettori di handle seguono l'ordine delle dichiarazioni nelle rispettive famiglie. Il digest copre l'associazione di ciascun handle alla dichiarazione in quella posizione. | Una sola istanza qualificata per testa, owner, generazione e boot. Il sigillo ha custodia locale e nessuna firma R3 propria. |

D-057 riconosce che un identificatore allocato dall'ambiente può avere un consumatore funzionale senza appartenere all'identità permanente. Il kernel rialloca gli handle. Qui il consumatore è il controllo di sostituzione della stessa istanza nel boot corrente. Un reboot conforme può quindi riusare la stessa testa (D-045). La transizione iniziale a g3 richiederà una firma.

## Formato nft e proiezioni

L'owner immutabile contiene `nftPath`, `nftSha256` e `nftProfile`. Prima della firma, l'installazione chiama `read_nft_profile(nftPath, nftSha256)`. Il comando esistente verifica percorso, custodia e SHA-256 del binario prima e dopo la lettura `-j list tables`. Dal primo record `metainfo` la funzione ricava il candidato `{"version": <stringa>, "jsonSchemaVersion": <intero positivo>}`. L'emittente qualifica la forma JSON e firma il digest dell'owner che contiene il candidato. Boot e tick ricevono il profilo solo dopo la verifica della testa e del digest dell'owner.

Per entrambe le famiglie il contratto confronta esattamente versione e schema con i valori firmati prima di proiettare il listato. Un profilo assente o malformato, una versione diversa o uno schema diverso danno `G3_NFT_VERSION`. Le forme di listato estranee alla grammatica danno `G3_NFT_FORMAT`. Al cambio del pacchetto nftables si acquisiscono il nuovo pin e il profilo candidato, si ripete la qualifica sulle tabelle del lease e si autorizza il nuovo owner tramite migrazione per generazioni D-050 o nuova firma della politica. Boot, riconciliazione e tick possono solo verificare il profilo selezionato.

* L'ingresso è un oggetto JSON con le sole chiavi `inet` e `bridge`. Il lettore deve rifiutare chiavi duplicate e numeri non JSON prima della decodifica. Ogni documento contiene la sola lista `nftables`. Il primo record ha la sola chiave `metainfo` con `version`, `json_schema_version` intero e `release_name` stringa facoltativa. Il record si verifica prima di escluderlo da entrambe le impronte.
* Segue una sola `table` per famiglia. Le due tabelle hanno lo stesso nome. Ogni record ha un solo tipo. Le dichiarazioni successive sono `set`, `chain` e `rule`, legate esattamente alla famiglia e tabella. Una regola fa riferimento a una chain già dichiarata. Nel listato vivo ogni dichiarazione porta un handle intero positivo. Nell'immagine del compilatore gli handle possono essere omessi.
* Si conservano nomi, tipi, flag, hook, priorità, policy di chain, espressioni e verdetti. I set nominati sono `provider_N` di tipo `ipv4_addr` o `ipv6_addr` con flag `timeout`. Le chain base hanno tipo `filter`, hook input/output/forward, priorità intera e policy accept/drop. Le istruzioni ammesse sono `match` (op, left, right), `jump` (target), `counter` anonimo (packets, bytes), `accept` e `drop`. Gli operandi di match del compilatore si confrontano integralmente, compresi i set costanti inline.
* La proiezione strutturale elimina soltanto il record metadati verificato, i due valori osservati dei contatori anonimi e i membri `elem` delle dichiarazioni di set. Conserva l'istruzione counter. L'impronta politica esclude anche gli handle. Il sigillo li associa nuovamente all'intera proiezione. L'ordine delle chiavi JSON è irrilevante. **L'ordine delle dichiarazioni, delle regole e delle istruzioni conta**. Invertire due regole distinte cambia entrambe le impronte. Per due regole identiche il sigillo rileva l'inversione dei loro handle.

`P = {"schema": "ouf.lease-kernel.structure.g3.v1", "tables": …}`, dove ogni famiglia contiene la lista dei record proiettati. L'impronta firmata è `digest(P)`; `structureHash = digest({"projection": P, "handles": handles})`. Il digest usa la serializzazione canonica g2. Gli helper g2 per struttura e stabilità si applicano solo ai contatori e alle intestazioni dichiarative validate. Applicarli ricorsivamente al listato intero perderebbe la distinzione tra membri mutabili e dati delle regole.

### Confronto fra 1.0.x e 1.1.x prima del passo 2

La versione riferita per il runner è 1.0.9. La lettura di laboratorio del 24 novembre riporta `nftables v1.1.3` da `nft --version`. La [fixture 1.1.3 sintetica](../tests/fixtures/lease-kernel-g3-nft-1.1.3-synthetic.json) riproduce la grammatica attesa nelle due famiglie. Il confronto fra i listati reali delle due serie resta aperto.

| Aspetto da confrontare | Comportamento da verificare |
|---|---|
| Campi nuovi | Solo `release_name` è facoltativo nei metadati. Le chiavi sconosciute nei record a grammatica chiusa danno diniego. Gli operandi di `match` si confrontano per intero con la politica firmata, incluse le eventuali nuove chiavi. |
| Ordine | La serializzazione canonica ordina le chiavi degli oggetti. Il listato conserva la sequenza di dichiarazioni, regole e istruzioni. |
| Set con timeout | Confrontare la rappresentazione del vuoto (assenza di `elem` o lista vuota) e, se già popolati, l'involucro dei membri, i tipi, la presenza di `timeout` e il significato in secondi di `expires`. Il tick controlla l'appartenenza e i limiti descritti sotto. |
| Handle | Verificare presenza, posizione e tipo di `handle` per tabella, set, chain e regole. Gli handle vivi devono essere interi positivi. Il sigillo li associa alle dichiarazioni nello stesso boot. I valori numerici di una fixture non identificano le tabelle del laboratorio. |

**Condizione per il passo 2.** Un operatore usa il binario corrispondente a `nftPath` e `nftSha256` e ripete la seguente lettura per ciascuna tabella del lease (`inet` e `bridge`). Sostituisce i segnaposto e sceglie per ogni famiglia un file nuovo in una directory privata.

```sh
(umask 077; set -C; nft -j list table <famiglia> <tabella> > <file-privato>)
```

L'operatore confronta i due output con la fixture per i quattro aspetti in tabella e registra l'esito senza pubblicare i listati. Un set vuoto consente di verificare solo la forma vuota. La forma popolata richiede una lettura privata di un lease già attivo. Se una forma necessaria resta inosservata o differisce, la qualifica corrispondente resta aperta prima del passo 2.

## API pura

| Funzione | Precondizione, verifica ed esito |
|---|---|
| `policy_footprint(tables, nft_profile)` | Verifica il profilo e richiede set vuoti (campo assente o lista vuota). Restituisce il digest esadecimale. |
| `local_seal(head, owner, generation, boot_id, tables, nft_profile)` | Richiede due digest SHA-256 esadecimali minuscoli, generazione intera 3, UUIDv4 canonico minuscolo del kernel e coppia viva vuota con handle conforme al profilo. Costruisce il documento. Il writer deve già avere verificato origine, custodia e uguaglianza con la politica firmata. |
| `verify_boot(seal, current_boot_id, head, owner, tables, nft_profile)` | Verifica profilo, binding e intero sigillo su coppia vuota. Il guard confronta anche `policy_footprint(tables, nft_profile)` con la testa sulla stessa lettura. |
| `verify_tick(policy, seal, tables, membership_policy, now)` | Il contesto richiede `head, owner, generation, footprint, nftProfile, bootId`. I primi cinque valori provengono dalla testa e dall'owner autenticati. Il chiamante legge il boot ID corrente dal kernel. Sulla stessa lettura il tick verifica metadati, impronta politica, struttura e handle del sigillo, membri e scadenze. |
| `classify_journal(journal, current_boot_id)` | Restituisce una delle tre classificazioni sotto. Il chiamante verifica sotto lock custodia del journal e corrispondenza esatta con testa/owner/generazione selezionati. |

Le due funzioni `verify_*` terminano con `None` al successo. Proiezione, costruzione e verifiche sollevano `ValueError(codice)` al diniego. Un successo della libreria può soddisfare una precondizione del writer. La concessione di autorità richiede l'intera transizione.

### Membri e scadenze al tick

`membership_policy` associa ciascun nome di set a `{"maxSeconds": N, "validUntil": {indirizzo: scadenza, …}}`. Per ogni flusso il chiamante ricava il massimo dall'owner e gli indirizzi con le rispettive scadenze dalla ricevuta di ammissione corrente, verificata per lo stesso binding e per il rinnovo in esame. Deve verificarne anche scope, provenienza DNS e restrizioni sugli indirizzi. Ricavare questi dati dal listato da verificare renderebbe circolare il controllo.

La verifica esige esattamente i set e gli indirizzi attesi in entrambe le famiglie; un set atteso vuoto ha mappa vuota. Un membro assente, estraneo, duplicato o di famiglia errata dà `G3_MEMBERS`. Le chiavi sono indirizzi canonici e senza zone. Ogni membro nft è `{"elem": {"val": indirizzo, "expires": secondi, "timeout": secondi}}`; `timeout` è facoltativo. Vengono ammessi solo secondi interi. Deve valere `0 < expires <= timeout <= maxSeconds`, usando il massimo se il timeout manca. Inoltre `now + expires <= validUntil[indirizzo]`. `now` è l'istante di osservazione in secondi monotoni interi di questo boot e le scadenze sono sulla stessa base. Il writer usa osservazioni fresche e verifica i propri limiti di tempo prima dell'effetto. Un limite superato, TTL zero o tipo errato dà `G3_TTL`. Un rinnovo legittimo può aggiornare membri e scadenze mantenendo entrambe le impronte strutturali.

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

R-025/A3 resta aperto per i writer del passo 2, la transizione del passo 3 e la qualifica del passo 4 con due boot reali, systemd e Docker. Le prove del passo 1 misurano le verifiche in memoria e, nel caso nativo, l'identità delle tabelle in un unico boot.
