# OUF — generazione33: compattazione del volume con chunk orfano

Stato: **114 test locali PASS; nuova qualifica nativa PENDING**. Checkpoint precedente `ae01a2757d8f49f03c06cace6e1d5e0e0e3cacae`. Stessa immagine/coorte33 e otto laboratori distinti; sette regressioni conservate.

## Prima esecuzione conservata e marker atomico

Run [41836677592](https://github.com/GioNob/ouf-deploy/actions/runs/41836677592), source `c942fdfcbb24ae7348e6ca9541624ceac3bf7bde`:112 test PASS, primo scenario FAILED prima del seed; compattazione non eseguita. Launcher volume exit65/non-OOM e log vuoto; cleanup segnala l'arresto non pulito. Il codice65 corrisponde a marker non valido; i byte del marker non furono esportati, quindi non si dichiara osservata una specifica scrittura parziale.

La pubblicazione diretta con write_text poteva rendere visibile il file prima che fosse completo. Correzione: file temporaneo creato in esclusiva, scrittura/chiusura e rename atomico; validazione di tutte le directory/marker prima del rilascio. Applicata all'avvio iniziale e ai sostituti, mantenendo READY esatto e rifiuto symlink/preaperture. Due regressioni aggiunte: marker completo prima della visibilità e ultimo gate con temporaneo stale che blocca tutti. Totale114 test locali PASS.

Artifact fallito13327355919:39052byte, SHA256 `9f5b733e33d157973a23e6c12eac8d29a006246bb0a63c1b2e11c9fddad3c51f`,37 membri/36 checksum/28 sorgenti del producer verificati. [Originale fallito](../evidence/artifacts/storage-compaction33-failed-41836677592.zip), [readback](../evidence/storage-compaction33-failed-readback-20261104.json). Il run resta FAILED.

## Protocollo

L'ottavo caso ripete integralmente cleanup, crash congiunto, recupero baseline e controlli di rete del settimo caso. La compattazione viene eseguita **dopo** quei controlli, a servizi vivi: non si trasferisce la prova di restart precedente alla compattazione successiva.

1. Snapshot bounded dei sette .dat e relativi .idx: dimensione, blocchi allocati (`st_blocks*512`), SHA256, mappa degli ultimi record e hash/cookie/dimensione di ogni needle valido. Il payload orfano completo deve ancora comparire solo nel volume identificato; tombstone presente. Nessun file temporaneo di compattazione né handle aperto su file fixture già unlinkato.
2. Un solo `weed shell` della stessa OCI33, eseguito come uid65532 nel master già isolato. Script esatto: lock, volume.vacuum con collection=ouf-identity-fixture e un solo volumeId derivato dal chunk, garbageThreshold0.01, unlock. Timeout90s/connectTimeout10s, nessun reinvio mutativo. Usa i link già qualificati, senza aggiungere porte. L'endpoint HTTP vacuum non viene usato: il codice upstream non applica un filtro volumeId a quel percorso.
3. Non basta exit0: richiedere riduzione di almeno4194304byte sia della lunghezza totale .dat sia dei blocchi allocati, scomparsa del payload orfano dai .dat e del suo record dall'indice. Stesso insieme di volumi; dati validi identici per needle e volumi non selezionati esattamente invariati.
4. GET diretto404 sul chunk, GET404/NoSuchKey e HEAD404 via S3, LIST completo baseline-only. Baseline8388865byte identica in GET/HEAD/LIST e metadati filer completi invariati. Snapshot dopo letture identico allo snapshot dopo compattazione; nessun servizio riavviato durante questa fase.
5. Assenza di residui .cpd/.cpx/.cpc/.cpldb e di file fixture unlinkati ancora aperti nel processo volume. Arresti puliti e rete rimossa; originali pubblici conservati con hash/sorgenti e senza corpi .dat/.idx/DB.

Riferimenti del codice upstream esatto: [volume.vacuum](https://github.com/seaweedfs/seaweedfs/blob/153ab668c99731a6d29492bf6c61d0b4fa701101/weed/shell/command_volume_vacuum.go), [shell e propagazione errori](https://github.com/seaweedfs/seaweedfs/blob/153ab668c99731a6d29492bf6c61d0b4fa701101/weed/shell/shell_liner.go), [volume compaction](https://github.com/seaweedfs/seaweedfs/blob/153ab668c99731a6d29492bf6c61d0b4fa701101/weed/storage/volume_vacuum.go).

Dodici test nuovi: comando con lock e volume/collection esatti; rifiuto injection/scope multiplo; snapshot con needle vivi e cancellati; integrità; riduzione reale dei blocchi; volumi non selezionati; residui/handle; processo invariato; indici troncati/symlink; scansione handle scoped/bounded; modi CLI incompatibili. Con le due regressioni sui marker atomici, totale114. `/proc` è simulato nei test locali e letto realmente nel runner nativo. YAML/shell PASS.

## Limiti

Si qualifica una compattazione completata, senza scritture concorrenti, di un volume locale nella fixture. Riduzione dei blocchi allocati ai file .dat, non cancellazione sicura dei settori o misura dello spazio libero dell'intero host. Nessuna prova post-compaction restart, crash durante rename/commit, power loss, disco pieno, tier remoto/EC, repliche multiple o RPO/RTO. La presenza di needle validi nel volume selezionato dipende dall'allocazione nativa; l'integrità della baseline è sempre verificata su tutti i volumi.

MiniPET invariato18,3/46=39,78%, circa40% ±10;0/8 gate,0/21 AT,0/120 oggetti reali. Nessun VPS/merge/deploy/replay/reset/grant. MinIO, scope17/52 Engine GET, Teatri/M1 e Farmacie preservati.
