# OUF — generazione33: cleanup logica del chunk orfano

Stato: **97 test locali PASS; qualifica nativa PENDING**. Checkpoint precedente `bf040e975ac0ea8060f6d2450205eb7b3b460da3`. Stessa immagine/coorte33; sette scenari distinti, con le sei regressioni conservate.

## Protocollo e confine

Il precedente stream-lab mantiene la policy originale: S3→volume gRPC28080 negata, cleanup fallita e assenza della chiave S3 verificata. Il nuovo cleanup-lab permette **soltanto questa tupla aggiuntiva**, dalle regole installate prima di ogni exec. Client e altri confini invariati:11 link ammessi,21 dinieghi tra ruoli e15 DNS/host. Le sei regressioni mantengono10 link/37 dinieghi.

1. Un solo PUT incompleto su una nuova chiave,4259841/8388865 byte inviati. Identificare il chunk4194304 byte nei .dat prima dell'abort, decodificando header/cookie/needleId e volumeId della fixture; hash completo del payload esatto. Un solo match, percorso regolare bounded e versione volume2/3 obbligatori.
2. Leggere l'indice .idx del medesimo needle: record originale positivo, offset/size corrispondenti. GET diretto dal namespace S3 al volume deve restituire200 e tutti i4194304 byte con hash esatto. Non è GET della baseline già confermata.
3. Registrare i contatori gRPC dedicati, chiudere il PUT senza leggere ACK, attendere al massimo20 osservazioni read-only dell'indice con intervallo1s. La cleanup è eseguita dal gateway, non da DELETE/PUT/retry del controller.
4. Richiedere record originale preservato e un'unica tombstone di size-1, GET diretto404 sul medesimo fileId e contatori request/response gRPC in aumento. Nessun errore viene reinterpretato come cancellazione:403/500/corpo errato falliscono.
5. Verificare GET404/NoSuchKey, HEAD404 vuoto e LIST baseline-only via S3; quattro SIGKILL/non-OOM e nuovi processi/namespace/gate, radici conservate e regole prima dell'exec. Baseline8388865 byte integra, topologia/metadati preservati. Tombstone e GET chunk404 persistono dopo riavvio e dopo probe rete.
6. Conservare inventari/hash, osservazioni dell'indice, chunk identity, HTTP status/hash, contatori, log e archivio originale; nessun corpo .dat/DB esportato.

Il parser è intenzionalmente vincolato al formato della fixture: header16byte + DataSize4, indici16byte (needleId8,offset4 in unità8,size4 signed). Rifiuta record parziali, mapping non corrispondente, aggiornamenti inattesi o symlink. Riferimenti upstream esatti della build: [needle_read.go](https://github.com/seaweedfs/seaweedfs/blob/153ab668c99731a6d29492bf6c61d0b4fa701101/weed/storage/needle/needle_read.go), [needle_map_memory.go](https://github.com/seaweedfs/seaweedfs/blob/153ab668c99731a6d29492bf6c61d0b4fa701101/weed/storage/needle_map_memory.go), [volume BatchDelete](https://github.com/seaweedfs/seaweedfs/blob/153ab668c99731a6d29492bf6c61d0b4fa701101/weed/server/volume_grpc_batch_delete.go). La lettura HTTP reale conferma il fileId derivato prima che la prova possa dichiarare assenza.

Undici nuovi test su delta esatto della policy, contatori, binding header/hash/identità, mapping indice e tombstone, file errati/symlink, letture reali simulate con errori permanenti, modi CLI incompatibili. Totale97 con le86 regressioni; YAML/shell PASS.

## Limiti

Cleanup **logica**, non recupero fisico dello spazio: i byte cancellati restano nel .dat append-only fino alla compattazione; nessun vacuum viene lanciato o qualificato. Il link aggiuntivo abilita la porta gRPC del solo ruolo S3, non autorizzazioni per singolo metodo né mTLS interno. Non si trasferisce questa policy al target.

Solo nuova chiave e singolo PUT Content-Length con abort client, seguito da crash processi su disco/page cache conservati. Non multipart, overwrite/versioning, retry durabile della cleanup dopo processo morto, quota/DoS, power loss/host reboot o RPO/RTO.

MiniPET invariato18,3/46=39,78%, circa40% ±10;0/8 gate,0/21 AT,0/120 oggetti reali. Nessun VPS/merge/deploy/replay/reset/grant. MinIO, scope17/52 Engine GET, Teatri/M1 e Farmacie preservati.
