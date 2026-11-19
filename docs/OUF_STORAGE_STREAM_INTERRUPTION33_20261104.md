# OUF — generazione33: PUT interrotto durante il corpo

Stato: **86 test locali/hosted e sei scenari nativi PASS**. Run [41821487900](https://github.com/GioNob/ouf-deploy/actions/runs/41821487900), job126545451454, producer `9c0f2968dba8528ced7c98643f30a7c5740ce400`. Estensione della fixture del checkpoint `009ab862d0966905be9e449d98948bb7dca2a443`, stessa OCI33/coorte. Nessuna modifica al target o al binario.

## Esito nativo e readback originale

- Nuovo PUT unico con4259841/8388865 byte inviati,4129024 omessi; zero letture della risposta/ACK e zero retry mutativi. Primo probe del volume: chunk4194304 byte in `ouf-identity-fixture_6.dat`, offset28, SHA256 `ab00f0a9983617f0f0556df4a93789539f94111e18f7ea04c3739a4492a303dd`, assente prima del PUT. Il log S3 registra **connection reset by peer** leggendo il chunk successivo all'offset4194304, dopo65537 byte ricevuti: evidenza lato server dell'interruzione durante il corpo.
- GET404/NoSuchKey, HEAD404 vuoto e LIST completo contenente solo la baseline, in tutte e tre le fasi: prima del crash, dopo riavvio, dopo probe rete. **Nessun oggetto S3 parziale pubblicato** per questa nuova chiave e questo guasto; nessun PUT/DELETE client di riconciliazione.
- Quattro SIGKILL137/non-OOM, tutti FinishedAt anteriori a ogni sostituto; quattro nuovi namespace/gate/processi e client invariato. Inventari fermo/gate identici: master4 file/1335 byte, filer40/5272, volume7.dat/12583416. Topologia e metadati invariati; primo probe di topologia e primo recupero del corpo PASS. Baseline8388865 byte integra in GET/HEAD/LIST, SHA256 `25809f4ef8ae5e9ab82c2688effb8da2ae66bb0b320befd55350dcb2cda9569d`. Contatori nuovi filer0→1954 e volume0→8398266 byte TCP; nessuna misura di prestazioni/RTO.
- Anche le cinque regressioni PASS:37 dinieghi/10 link ammessi per scenario, other_denied zero dopo i probe;41 container distinti,30 arresti finali puliti,11 SIGKILL intenzionali/non-OOM, sei reti rimosse. Originale **400 membri/399 checksum/24 sorgenti** verificati localmente. Nessuna chiave privata. Firma publisher coorte verificata hosted; nessuna verifica crittografica locale aggiuntiva dichiarata.
- Artifact13316679288 originale: **415546 byte**, SHA256 `6597d90489dc330ce7a4e8bf98c818827ec3f85185972bdb63c21e43a4bc8484`. [Archivio originale](../evidence/artifacts/storage-stream-interruption33-41821487900.zip), [receipt](../evidence/storage-stream-interruption33-readback-20261104.json). Nessuna seconda esecuzione nativa locale o esportazione dei corpi .dat/DB.

### Pulizia del chunk orfano: limite osservato

Il gateway tenta la cleanup di un chunk dopo l'errore di upload. Il log registra `deleteOrphanedChunks: failed to delete chunk` e `dial tcp 172.30.233.11:28080: connect: no route to host`. La policy della fixture **nega S3→volume gRPC28080**. Il link HTTP18080 necessario ai dati è ammesso; questo percorso di cleanup non è qualificato. Nessun allargamento della policy è stato fatto in questa prova.

L'assenza della chiave S3 e l'integrità della baseline sono PASS; la bonifica/reclamation del chunk orfano non è PASS. I .dat conservano il prefisso e i log mostrano il tentativo fallito. Non si deduce da ciò un difetto di GC in altre configurazioni né che il chunk sarebbe automaticamente recuperato in futuro. L'asserzione other_denied zero non esclude il diniego: questa destinazione ha una regola dedicata e i servizi sono stati poi sostituiti.

Prossimo singolo passo: qualificare nella fixture isolata la cleanup del chunk orfano e il collegamento gRPC minimo necessario, con evidenza del risultato e dei confini di rete. Nessuna apertura sul target o accettazione produttiva anticipata.

## Protocollo

1. Creare una volta bucket e oggetto baseline da8388865 byte con ACK. Nessun GET del corpo baseline prima del successivo crash.
2. Nuova chiave `staging/interrupted-stream.bin`: un solo PUT SigV4 su TLS verificato, Content-Length8388865 e firma/hash dell'intero corpo previsto. Inviare soltanto4259841 byte. Il client non legge una risposta e resta aperto fino al segnale di abort.
3. Prima del PUT il suo prefisso deve essere assente dai .dat. A connessione ancora aperta, osservare nel volume un chunk completo di4194304 byte esattamente uguale al nuovo payload sintetico. Ricerca bounded, solo hash/offset/dimensioni esportati. Non basta il successo del send locale.
4. Chiudere la connessione senza inviare i4129024 byte mancanti. Riconciliare con GET404/NoSuchKey, HEAD404 vuoto e LIST completo contenente solo la baseline. Nessun retry/replay mutativo o DELETE di pulizia.
5. SIGKILL di master/volume/filer/S3, quattro exit137/non-OOM prima dei sostituti. Stesse radici, quattro nuovi processi/namespace/gate, client invariato; tutti i firewall prima di ogni exec. Inventari master/LevelDB/.dat fermi e durante il gate identici, prefissi .dat preservati dopo avvio.
6. Ri-registrazioni/topologia/metadati e GET/HEAD/LIST baseline integri. Riconciliazione assenza della nuova chiave dopo riavvio e dopo i37 dinieghi di rete. Cinque arresti finali puliti e rete rimossa.

La CI conserva anche i cinque scenari precedenti e aggiunge il sesto stream-lab. Dodici test nuovi: corpo incompleto/distinto, chunk esatto e limiti scanner, file/marker non validi, invio unico senza lettura ACK, assenza senza scritture, rifiuto di risposte parziali/list incompleti/TLS discordante, modi CLI incompatibili. Totale86 con le74 regressioni.

## Limiti

Solo nuova chiave, singolo PUT con Content-Length e interruzione della connessione client prima del completamento del corpo. La successiva perdita dei processi verifica l'assenza persistente di una pubblicazione S3 parziale e la baseline confermata. Non è crash del server mentre riceve il corpo, SigV4 streaming-chunked, multipart, overwrite/versioning, prova di atomicità universale, garbage collection dei chunk orfani, power loss/reboot host/perdita disco o RPO/RTO. Byte osservati nei .dat possono essere nella page cache; non si dichiara fsync/durabilità al guasto del sistema operativo.

MiniPET invariato18,3/46=39,78%, circa40% ±10;0/8 gate,0/21 AT,0/120 oggetti reali. Nessun VPS/merge/deploy/replay/reset/grant. MinIO, scope17/52 Engine GET, Teatri/M1 e Farmacie preservati.
