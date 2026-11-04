# OUF — generazione33: PUT interrotto durante il corpo

Stato: **86 test locali PASS; qualifica nativa PENDING**. Estensione della fixture del checkpoint `009ab862d0966905be9e449d98948bb7dca2a443`, stessa OCI33/coorte. Nessuna modifica al target o al binario.

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
