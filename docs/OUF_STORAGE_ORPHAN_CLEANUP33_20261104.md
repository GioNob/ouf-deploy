# OUF — generazione33: cleanup logica del chunk orfano

Stato: **100 test locali/hosted e sette scenari nativi PASS**. Run [41824890871](https://github.com/GioNob/ouf-deploy/actions/runs/41824890871), job126557006058, producer `01431f652f75c737d18534708ca0e7f17535814b`. Checkpoint precedente `bf040e975ac0ea8060f6d2450205eb7b3b460da3`. Stessa immagine/coorte33; sette scenari distinti, con le sei regressioni conservate.

## Esito nativo e readback originale

- Chunk esatto `3,0497ea242b`, payload4194304byte/SHA256 `ab00f0a9983617f0f0556df4a93789539f94111e18f7ea04c3739a4492a303dd`, identificato in `ouf-identity-fixture_3.dat` offset28; needle offset8/size4194316. **GET diretto200 con corpo completo prima dell'abort**. Unico PUT incompleto4259841/8388865byte, nessuna risposta/ACK letta, log server connection reset dopo65537byte del secondo chunk.
- Al primo probe dopo abort, indice **16→32byte**: record positivo originale conservato e tombstone size-1 all'offset4194360. **GET diretto404** sullo stesso fileId dopo cleanup, dopo riavvio e dopo probe rete. Indice completo osservato con stessi hash/record dopo riavvio e probe. Contatori gRPC S3 **0→677** e volume **0→579 byte TCP** prima del crash; zero DELETE e retry mutativi del controller. Il gateway effettua la cleanup automaticamente; nessun errore deleteOrphanedChunks nel log di questo caso.
- **GET404/NoSuchKey, HEAD404 vuoto e LIST baseline-only** via S3 in tutte e tre le fasi. Quattro SIGKILL137/non-OOM precedono ogni sostituto; vecchi namespace mantenuti durante il confronto, quattro nuovi namespace/gate, tutti i pin rilasciati prima di ogni exec. Baseline8388865byte integra al primo recupero senza nuovi PUT, topologia/metadati invariati al primo probe.
- Inventari fermo/gate identici: master4file/1335byte, filer40/5268, volume7.dat/12583448. I byte .dat aumentano di32 per la tombstone e non vengono compattati: **cancellazione logica provata, recupero fisico dello spazio non qualificato**. Hash dei prefissi .dat conservati dopo restart. Contatori baseline nuovi filer0→1953 e volume0→8397434 byte TCP; non sono misure di payload esatto/prestazioni/RTO.
- Settimo caso: **11 link ammessi/36 dinieghi**; sei regressioni:10/37 ciascuna, compreso il caso che mantiene bloccata la cleanup. other_denied zero durante i probe. **50 container distinti,35 arresti finali puliti,15 SIGKILL intenzionali, sette reti rimosse**. Vecchi namespace mantenuti e pin rilasciati anche in tutte le regressioni con crash.
- Artifact13318842839 originale: **518542byte**, SHA256 `e6838878d7428ac07586d671d88881ef4adab9c57c40f542f83363f9741a7761`. **518 membri/517 checksum/26 sorgenti** verificati localmente, insieme a stati/timestamp/mount/namespace/pin, policy/counter, indici osservati, HTTP/hash/TLS e parità baseline. Nessuna chiave privata. Firma publisher coorte verificata hosted; nessuna verifica crittografica locale aggiuntiva dichiarata.

[Archivio originale riuscito](../evidence/artifacts/storage-orphan-cleanup33-41824890871.zip), [receipt di readback](../evidence/storage-orphan-cleanup33-readback-20261104.json). Le osservazioni degli indici sono metadati/hash prodotti e verificati sul runner; i corpi .idx/.dat/DB non sono esportati per una seconda analisi nativa locale. Il run fallito resta conservato separatamente sotto.

Prossimo singolo passo: qualificare la compattazione del volume della fixture per recuperare lo spazio del chunk tombstoned, verificando baseline, indice e assenza prima/dopo. Nessuna operazione target.

## Prima esecuzione conservata e correzione della fixture

Run [41823561384](https://github.com/GioNob/ouf-deploy/actions/runs/41823561384), source `2910750df27ccbff9c6e1f1a25f6c8eea8da8928`:97 test e sei regressioni PASS, cleanup-lab **FAILED** su `FRESH_NONHOST_REPLACEMENT_NAMESPACE_REQUIRED`. Prima del blocco: chunk `6,04996b75db` letto200/4194304byte, indice16→32byte con record originale e tombstone-1, GET404 e traffico gRPC0→677/579byte. Nessuna qualifica post-restart per questa esecuzione.

Il controllo confrontava gli inode dei nuovi namespace con numeri storici dopo aver distrutto quelli vecchi: non esclude il riuso dell'inode. L'inode del sostituto non è stato salvato prima dell'assert fallita, quindi non viene ricostruito o dichiarato noto. La correzione mantiene vivi i vecchi namespace con bind mount prima del SIGKILL, verifica ogni identità e li rilascia dopo creazione/confronto dei sostituti e prima di ogni exec. Il requisito di namespace distinti resta invariato. Rilascio anche in finally; tre test per pin esatto, mismatch con rilascio e input/symlink invalidi. [Semantica Linux namespace lifetime](https://man7.org/linux/man-pages/man7/namespaces.7.html).

Originale fallito artifact13316969633:470874byte, SHA256 `6d99724041aace57cd0aa4e18aea56c45d62ebdfcb38a2814e65786c6cba4af4`,456 membri/455 checksum/26 sorgenti del producer verificati. [ZIP fallito](../evidence/artifacts/storage-orphan-cleanup33-failed-41823561384.zip), [readback parziale](../evidence/storage-orphan-cleanup33-failed-readback-20261104.json). Il risultato fallito non viene sostituito da un PASS.

## Protocollo e confine

Il precedente stream-lab mantiene la policy originale: S3→volume gRPC28080 negata, cleanup fallita e assenza della chiave S3 verificata. Il nuovo cleanup-lab permette **soltanto questa tupla aggiuntiva**, dalle regole installate prima di ogni exec. Client e altri confini invariati:11 link ammessi,21 dinieghi tra ruoli e15 DNS/host. Le sei regressioni mantengono10 link/37 dinieghi.

1. Un solo PUT incompleto su una nuova chiave,4259841/8388865 byte inviati. Identificare il chunk4194304 byte nei .dat prima dell'abort, decodificando header/cookie/needleId e volumeId della fixture; hash completo del payload esatto. Un solo match, percorso regolare bounded e versione volume2/3 obbligatori.
2. Leggere l'indice .idx del medesimo needle: record originale positivo, offset/size corrispondenti. GET diretto dal namespace S3 al volume deve restituire200 e tutti i4194304 byte con hash esatto. Non è GET della baseline già confermata.
3. Registrare i contatori gRPC dedicati, chiudere il PUT senza leggere ACK, attendere al massimo20 osservazioni read-only dell'indice con intervallo1s. La cleanup è eseguita dal gateway, non da DELETE/PUT/retry del controller.
4. Richiedere record originale preservato e un'unica tombstone di size-1, GET diretto404 sul medesimo fileId e contatori request/response gRPC in aumento. Nessun errore viene reinterpretato come cancellazione:403/500/corpo errato falliscono.
5. Verificare GET404/NoSuchKey, HEAD404 vuoto e LIST baseline-only via S3; quattro SIGKILL/non-OOM e nuovi processi/namespace/gate, radici conservate e regole prima dell'exec. Baseline8388865 byte integra, topologia/metadati preservati. Tombstone e GET chunk404 persistono dopo riavvio e dopo probe rete.
6. Conservare inventari/hash, osservazioni dell'indice, chunk identity, HTTP status/hash, contatori, log e archivio originale; nessun corpo .dat/DB esportato.

Il parser è intenzionalmente vincolato al formato della fixture: header16byte + DataSize4, indici16byte (needleId8,offset4 in unità8,size4 signed). Rifiuta record parziali, mapping non corrispondente, aggiornamenti inattesi o symlink. Riferimenti upstream esatti della build: [needle_read.go](https://github.com/seaweedfs/seaweedfs/blob/153ab668c99731a6d29492bf6c61d0b4fa701101/weed/storage/needle/needle_read.go), [needle_map_memory.go](https://github.com/seaweedfs/seaweedfs/blob/153ab668c99731a6d29492bf6c61d0b4fa701101/weed/storage/needle_map_memory.go), [volume BatchDelete](https://github.com/seaweedfs/seaweedfs/blob/153ab668c99731a6d29492bf6c61d0b4fa701101/weed/server/volume_grpc_batch_delete.go). La lettura HTTP reale conferma il fileId derivato prima che la prova possa dichiarare assenza.

Undici nuovi test su delta esatto della policy, contatori, binding header/hash/identità, mapping indice e tombstone, file errati/symlink, letture reali simulate con errori permanenti, modi CLI incompatibili. Con i tre test sui pin namespace, totale100; YAML/shell PASS.

## Limiti

Cleanup **logica**, non recupero fisico dello spazio: i byte cancellati restano nel .dat append-only fino alla compattazione; nessun vacuum viene lanciato o qualificato. Il link aggiuntivo abilita la porta gRPC del solo ruolo S3, non autorizzazioni per singolo metodo né mTLS interno. Non si trasferisce questa policy al target.

Solo nuova chiave e singolo PUT Content-Length con abort client, seguito da crash processi su disco/page cache conservati. Non multipart, overwrite/versioning, retry durabile della cleanup dopo processo morto, quota/DoS, power loss/host reboot o RPO/RTO.

MiniPET invariato18,3/46=39,78%, circa40% ±10;0/8 gate,0/21 AT,0/120 oggetti reali. Nessun VPS/merge/deploy/replay/reset/grant. MinIO, scope17/52 Engine GET, Teatri/M1 e Farmacie preservati.
