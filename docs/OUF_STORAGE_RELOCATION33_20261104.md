# OUF — generazione33: rilocazione di un needle valido oltre un record cancellato

Stato: **134 test locali PASS; qualifica nativa PENDING**. Checkpoint iniziale `bc528908310e8dceff00bdd5661c5391169a58be`; stessa OCI33/coorte. Decimo laboratorio; nove regressioni conservate.

## Protocollo

Il decimo caso ripete cleanup dell'upload incompleto, primo crash congiunto, recupero baseline e controlli rete. Poi aggiunge un witness nativo1048593byte SHAKE256 deterministico nel volume esatto dell'orfano: ID riservato `(1<<48)+33`, cookie33aabbcc. Lo snapshot bounded di tutti gli indici deve escludere collisioni vive e tombstoned; GET404 precede il solo POST. Il POST passa dall'API HTTP del volume tramite la tupla S3→volume18080 già ammessa, con Content-MD5 e risposta201/size esatta. Nessun retry mutativo o assegnazione master, nessun editing dei file DAT/IDX. L'ID è riservato solo in questa fixture senza scritture concorrenti, non un meccanismo di allocazione per produzione.

Prima del vacuum, header DAT e record IDX devono collegare esattamente ID/cookie/hash/dimensione del witness; posizione uguale alla lunghezza precedente del DAT e oltre il payload orfano. Prefissi completi DAT e IDX invariati, una sola entry positiva aggiunta, needle preesistenti e volumi non selezionati immutati. GET diretto200 del witness e baseline S3 conservata.

Un solo vacuum locked sul volume/collection esatti. Richiesti recupero di almeno4MiB di blocchi allocati, rimozione payload/tombstone orfano e conservazione dei needle validi. L'offset del witness deve diminuire almeno4194304byte ed esattamente quanto si riduce il DAT; ID/cookie/size/hash identici, nuovo header e nuova entry IDX concordi. GET diretto200 dopo compattazione.

Segue secondo SIGKILL congiunto e ricreazione dei quattro servizi con stessi storage/IP/config, nuovi namespace/gate e firewall prima di exec; client invariato. Snapshot DAT/IDX/allocazione conservato in stato gated/recuperato/finale. Dopo recupero e probe, witness osservato allo stesso nuovo offset, stessi hash e GET200. S3 baseline8388865byte e metadati identici, orfano diretto404 e S3 assente.11 link/36 dinieghi ripetuti, cinque arresti finali puliti. Totale atteso85 container distinti,50 arresti puliti,35 SIGKILL intenzionali, dieci reti rimosse.

## Test e confini

Dodici nuove regressioni: snapshot nativi sintetici con spostamento reale e blocchi, collisioni su ogni volume, binding volume/collection, prefissi DAT/IDX, mancato o errato spostamento, corruzione identità/payload/indice, symlink, singolo POST dopo404, esistenza che vieta scrittura,503 senza retry e modi CLI incompatibili.134 test locali PASS; YAML/shell/sintassi PASS. Nei test snapshot locali solo la scansione proc/fd è simulata; il runner legge realmente DAT/IDX/proc. Direct API e formati verificati sul codice upstream esatto153ab668c99731a6d29492bf6c61d0b4fa701101: [write handler](https://github.com/seaweedfs/seaweedfs/blob/153ab668c99731a6d29492bf6c61d0b4fa701101/weed/server/volume_server_handlers_write.go), [upload parser](https://github.com/seaweedfs/seaweedfs/blob/153ab668c99731a6d29492bf6c61d0b4fa701101/weed/storage/needle/needle_parse_upload.go).

Witness nativo **non collegato al filer**, non nuovo oggetto S3, non autorizzazione di metodi interni. La baseline S3 rimane la prova dell'oggetto già confermato. Una scrittura diretta della fixture è dichiarata separatamente dai PUT S3 e non è un replay di mutazioni. Prova di rilocazione e perdita processi dopo vacuum, non crash DURANTE commit/rename, power loss, reboot host, disco pieno/perdita disco, repliche, secure erase o RPO/RTO. I PID non definiscono identità; confronto container/namespace separato. Archivio pubblico solo riepiloghi, nessun corpo DAT/IDX/DB o chiave privata.

MiniPET invariato18,3/46=39,78%, circa40% ±10;0/8 gate,0/21 AT,0/120 oggetti reali. Nessun VPS/merge/deploy/replay/reset/grant; MinIO, scope17/52 Engine GET, Teatri/M1 e Farmacie preservati.
