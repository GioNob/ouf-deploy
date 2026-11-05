# G0: collector dei corpi, export DB e riconciliazione

## Risultato e perimetro

Questa coppia rimuove due lacune software della richiesta G0: lettura corrente dei corpi S3 e raccolta dei riferimenti PostgreSQL con confronto offline. Riusa `tools/storage_inventory` e `tools/storage_planning`. Nessuna modifica ai servizi, alle immagini installate, al source-lock o al JSON storico congelato. Nessun endpoint, grant, ammissione, merge o deploy.

**Non chiude G0.** Il collector completo delle otto sezioni della [richiesta](OUF_STORAGE_G0_COLLECTION_REQUEST_20261105.md) richiede ancora collegamenti effettivi e custodia degli input, roster/capacità correnti, classificazione ACL/policy, censimento writer autenticato, finestra e percorso operativo ammesso. I due strumenti non costituiscono una capability operativa né una conferma HUMAN. Non assegnano il controllo18 e non rinnovano i controlli13–17 consumati.

MiniPET invariato: **18,3/46 = 39,78%; 0/8 gate; 0/21 AT; 0/120 oggetti reali**. Le fixture contengono dati sintetici; riprendere conteggi storici identici non li trasforma in dati del target.

## 1. Osservazione S3 condizionale

`inventory g0-collect CONFIG SCOPE_NUOVO_ASSOLUTO` aggiunge un percorso esplicito al reader esistente. Il vecchio comando metadata rimane invariato. Il file CONFIG0600 contiene schema `ouf.storage-g0-collection-input.v1`, operationId, installationRef e connection secondo il Config esistente: endpoint, region, accessKeyFile, secretKeyFile, caCertificateFile. Gli input sono riferimenti privati, non autorità runtime.

Ogni richiesta GET/HEAD viene riservata e sincronizzata su disco prima dell'invio; metodo, endpoint e budget sono vincolati. Credenziali statiche esplicite, TLS verificato, niente redirect, proxy, retry automatici o decompressione automatica. Il collector non contiene PUT/DELETE S3. Scrive soltanto evidenze locali private.

Limiti:256oggetti,16MiB per corpo,64MiB di corpi verificati,128MiB su rete,3000richieste,300secondi per tentativo. Inventario iniziale e finale completi per il profilo, HEAD/tag completi supplementari, GET con If-Match, hash SHA256 calcolato in streaming senza conservare il contenuto. Hash dichiarato discordante blocca. Le ricevute distinguono READ_RESERVED e VERIFIED_AT_READ; nessun file completo in caso di raccolta parziale.

Il profilo corrente ammette solo bucket non versionati senza marker o multipart in corso. Versioning Enabled/Suspended, versioni/marker/multipart o namespace non rappresentabile fermano la raccolta prima dei corpi. Gli esiti API non supportati rimangono tali: ACL/publicAccessBlock non vengono dichiarati assenti o sicuri. VersionId può essere null per il profilo non versionato.

`collection.private.json` collega input, installationRef, operationId, osservazioni prima/dopo e ricevute per corpo con bucket/key, dimensione, hash, ETag e digest della HEAD. `summary.json` è redatto. L'uguaglianza prima/dopo non prova un istante atomico né l'assenza di scritture intermedie. Custodia, autenticazione dell'origine e correlazione con la finestra sono responsabilità del pacchetto governato.

Lo scope viene creato una volta; rimane consumato anche dopo crash/fallimento. Non cancellarlo né cambiarne il nome per riottenere il budget. Un operationId diverso richiede una decisione separata nel percorso governato; il programma locale non è un registro globale di ammissione.

## 2. PostgreSQL e confronto con i corpi

`python3 -m tools.storage_planning.g0_database CONFIG SCOPE_NUOVO_ASSOLUTO` usa un solo processo psql con ambiente controllato, niente psqlrc o query del chiamante. Le SELECT sono proiezioni fisse. Ogni export usa una transazione REPEATABLE READ READ ONLY, row_security=off per rifiutare il filtraggio invisibile, timeout statement5s/lock1s/idle15s, connessione3s e processo120s. Al massimo10000righe per sezione,32MiB totali,256KiB per riga; il record10001 fa fallire l'export, senza presentare una troncatura come completezza.

I profili sono vincolati ai sorgenti:

| Profilo | Commit schema | Sezioni |
|---|---|---:|
| onboarding-retained | 73498c17596ae155a3ed9ab36acfd6bb69da9846, migrazioni1–38 | 7 |
| onboarding | d5155899b09dda298494b68cefa7e1f281167652, migrazioni1–41 | 10 |
| udp | 0d40da05408a14db31d4d41af2372d6a71480291, migrazioni1–36 | 9 |
| ingestion | 4165b9e149be467d5d7c6bed35e4e1af4e249db1, migrazioni1–18 | 11 |

I primi38blob SQL dei due commit Onboarding sono identici. La fixture esegue il profilo mantenuto prima delle migrazioni39–41 e ne verifica il diniego dopo l'upgrade. Nessuna migrazione applicata al target. Il sourceSchemaCommit indica la provenienza della proiezione, **non attesta il commit installato**. Catalogo colonne/tipi, OID numerici, database, ruolo, endpoint, avvio postmaster e snapshot sono conservati nell'export privato; il roster operativo deve ancora verificarne il binding.

CONFIG0600 richiede schema `ouf.storage-g0-db-input.v1`, operationId, installationRef, profile, host, hostaddrIPv4, port, database, user, passwordFile e rootCertificateFile. TLS verify-full con CA esplicita per endpoint remoti; disable è ammesso soltanto con host=hostaddr IPv4 loopback ed è usato nella fixture isolata. Il test non qualifica TLS PostgreSQL remoto. Password tramite file passfile privato0600, nessuna password in argv o rapporto. Nessun provisioning/GRANT nel collector; i ruoli SELECT della fixture sono creati solo nel database usa-e-getta.

Claim e SQL vengono salvati prima del processo; output parziale fsync conservato, file completo solo dopo exit0, footer COMMIT e validazione di tutte le sezioni. Errori pubblici per codice, niente diagnostica SQL privata in chat. Scope consumato senza replay. Export differenti e S3 rimangono snapshot separati; nessun common-cut, restore o esito owner dedotto.

Le proiezioni includono asset, profili/job, tentativi, riconciliazioni owner e vecchio catalogo ingestion; intenti/control/proiezione di autorità nel candidato; lake/manifest/shadow, handoff/materializzazione/replay/maintenance UDP; run, partizioni, tentativi/lineage, outbox, watermark, checkpoint/configuration, quarantena/replay/scheduler Ingestion. I documenti JSON business non vengono esportati integralmente: hash PostgreSQL della rappresentazione JSONB e riferimenti strutturali selezionati. Nessuna esportazione di token, credenziali, campioni o motivazioni.

Il comando offline `python3 -m tools.storage_planning.g0_reconciliation INPUT OUTPUT_NUOVO` riceve collectionFile, exports (mappa profilo→file), buckets espliciti onboarding/udp e writerCensusFile. Valida i tre owner, poi verifica hash/dimensioni e collegamenti asset/upload, catalogo, lineage/run, handoff/ACK/receipt e watermark senza scavalcare predecessori non ACKED. `object://managed-files/...` diventa la chiave letterale managed-files/... nel bucket esplicito; `lake://UUID` è un riferimento di catalogo, non una chiave S3. Non decodifica URL delle chiavi.

L'hash RAW viene confrontato con rawHash della lineage; il contentHash dell'handoff corrisponde all'output canonico, non ai byte RAW né al recovery envelope. La fixture usa intenzionalmente hash diversi. Oggetti non classificati non diventano automaticamente orfani eliminabili. Riferimenti mancanti o discordanti producono findings con fingerprint, senza riportare chiavi o righe nel rapporto pubblico.

**Copertura limitata esplicita:** slice dei manifest richiedono verifica dei range/corpi; lifecycle di shadow/previous_locator, sample/output/binding/quarantine refs richiedono classificazione. Il collector restituisce HOLD quando incontra queste casistiche, anziché ignorarle o dedurne l'assenza. Lo schema contiene queste sezioni anche se vuote nella fixture; non è una qualifica di ogni stato applicativo possibile o di tutti i tenant. Il confronto non esegue riparazioni, non cancella oggetti e non altera ACK/watermark/latch.

L'intake writer schema `ouf.storage-g0-writer-census.v1` richiede installationRef e paths, con gli11identificativi della richiesta G0. Ogni record distingue PRESENT/ABSENT/UNKNOWN e TECHNICAL_OBSERVATION/OPERATOR_DECLARATION/UNKNOWN; una dichiarazione nota richiede digest evidenza, capturedAt e ownerRef. Mancante/UNKNOWN non significa ABSENT. L'intake verifica forma e copertura, **non autenticità/freschezza delle prove, identità degli owner o quiescenza**. Non raccoglie processi/consumer sul target. Il riepilogo resta g0Complete=false, runtimeAuthorityIssued=false, acceptanceCreditAdded=0 anche senza findings.

## Qualifica e prove

Le ricevute complete, digest, dimensioni e storia dei tentativi sono in [storage-g0-collectors-qualified-20261105.json](../evidence/storage-g0-collectors-qualified-20261105.json). Verificatore offline `scripts/readback-storage-g0.py`, con alberi Git indipendenti esatti; non estrae né esegue codice dell'archivio.

Corpi: candidato f4b4152f78af7ca5a220714b517a458de5c494cc, run42111278483/job127539175986.120corpi sintetici/203743byte,10senza hash annunciato,1370richieste riservate, replay e crash reale del processo, mismatch hash e profilo versionato respinti.12PASS Go includono parent/subtest, non12test principali. Scan dei due eseguibili zero rilievi. Readback12membri/11checksum/9sorgenti Git; tre alterazioni semantiche respinte con checksum ricalcolati.

Il primo run42110718911 sul3211f75d è funzionalmente PASS, ma lo scan fs copriva solo go.mod: qualificazione sicurezza incompleta. Il secondo scan rootfs copre i due eseguibili; il manifest invariato conserva lo scan del primo run. Non attribuire tutti e tre i target a un solo rapporto. Il codice del collector non cambia nella correzione dello scan.

DB: candidato60a97c3a55da66e110953ba113b210c1d74dd1a2, run42114275442/job127549616992 SUCCESS; readback27membri/26checksum/111sorgenti Git esatti (16deploy+95migrazioni applicative), join ricalcolato offline e tre alterazioni respinte. Prova nativa su PostgreSQL17.11/PostGIS con95migrazioni originali, quattro profili,2corpi sintetici/6byte letti dal collector effettivo e join di asset/intento/catalogo/lineage/ACK/watermark.12test Python,6alterazioni dei risultati nativi respinte; RLS e revoca SELECT devono produrre HOLD, privilegi DML negati anche tentando read-write. Gli ultimi risultati e il commit qualificato fanno fede nella ricevuta. Server usa-e-getta, namespace condiviso solo loopback, nessuna porta pubblicata, rootfs read-only/cap-dropALL; niente accesso al VPS. I GRANT/DDL/seed appartengono alla fixture amministrativa, non all'exporter.

Il primo candidato DB bc7478e0/run42113863433 ha fallito il parser retained: PostgreSQL serializzava OID come stringa. Correzione SQL con cast esplicito bigint, senza accettare stringhe nel parser. Tentativo conservato. Il readback non è una seconda esecuzione dei server; gli artifact Actions scadono il3febbraio2027 e non costituiscono custodia durevole. Lo scan dei tool non riqualifica l'immagine MinIO legacy, le immagini PostgreSQL o le dipendenze dei servizi completi.

## Prossima coppia verso la sostituzione

1. Comporre il pacchetto unico G0 dalle parti ora eseguibili e dai collector host già esistenti, con binding delle otto sezioni, custodia, budget cumulativo, classificazione ACL e condizioni esplicite di applicabilità dei profili. Preparare un solo risultato operativo revisionabile; nessun rilancio storico e nessuna nuova serie di test recovery indipendenti.
2. Chiudere gli input operatore indispensabili (canale di raccolta sul target, consumer esterni, finestra/capacità) e sottoporre il pacchetto concreto al gate applicabile; eseguire la raccolta reale solo dopo quel passaggio. Se i dati reali mostrano casistiche fuori profilo, conservarle in HOLD e sviluppare solo l'estensione necessaria. La migrazione con fermo completo resta la prima opzione da valutare su dati correnti.

G1 licenze/lifecycle/custodia e sicurezza dei servizi rimangono aperti insieme ai gate successivi. La qualifica dei due strumenti non è la sostituzione operativa; l'avanzamento MiniPET cambia solo quando sono soddisfatti i criteri previsti.
