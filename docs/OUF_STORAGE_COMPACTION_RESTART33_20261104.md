# OUF — generazione33: restart completo dopo compattazione

Stato: **122 test locali PASS; qualifica nativa PENDING**. Checkpoint iniziale `bd1dec94747cb13058c740672701f2213c5d01a1`; stessa OCI33, nessuna modifica al candidato. Il nono scenario conserva gli otto precedenti e aggiunge un secondo crash congiunto dopo la compattazione conclusa.

## Protocollo

1. Ripetere integralmente cleanup, primo crash/recupero, controlli rete e compattazione del singolo volume identificato. Conservare snapshot completo DAT/IDX/blocchi e baseline/metadati/topologia prima del secondo crash.
2. Trattenere i quattro namespace correnti con bind pin verificati. Un batch SIGKILL e quattro exit137/non-OOM osservati prima di qualsiasi sostituto. Conservare log e inventari master/LevelDB/DAT a processi fermi; rimuovere soltanto i container della fixture.
3. Quattro nuovi container/namespace con stesse directory/config/IP/immagine, uid65532/read-only/cap-drop ALL, gate nuovi e regole prima di exec. Client invariato. Otto listener chiusi verificati; pin rilasciati prima di exec. Inventari fermi/gated identici e snapshot DAT/IDX/allocazione già identico al post-compaction anche a gate chiuso.
4. Rilasciare marker atomici. Attendere listener/topologia/registrazioni con budget finiti; verificare metadati completi identici e contatori reali del nuovo filer. GET/HEAD/LIST completo della baseline con contatore del nuovo volume incrementato almeno8388865byte; nessun PUT di recupero, DELETE, replay o secondo vacuum.
5. Chunk diretto404 e S3 GET/HEAD404/LIST baseline-only. Snapshot DAT/IDX e blocchi identico a quello dopo vacuum, escluso PID: non si inferisce identità container da PID, che il kernel può riusare. Identità e namespace nuovi verificati separatamente.
6. Ripetere11 link ammessi e36 dinieghi con contatori firewall; ripetere baseline/assenza/snapshot dopo probe. Cinque arresti finali puliti, rete rimossa. Nel nono caso13 container distinti e8 SIGKILL intenzionali; totale atteso72 container,45 arresti puliti,27 SIGKILL e nove reti rimosse.

## Validazione e limiti

Otto nuove regressioni coprono snapshot identico con nuovo PID o PID riusato, corruzione/rimozione DAT/IDX, ricrescita lunghezza/allocazione, ritorno payload/tombstone/needle/residui/handle, PID invalido e modi CLI incompatibili. Totale122 test; YAML/shell e sintassi Python PASS. Snapshot legge davvero i file nel runner; nessuna scrittura storage del controller.

Budget fixture: listener60 tentativi per porta, topologia10 tentativi/120s con backoff+jitter e Retry-After, recupero lettura massimo6 tentativi solo per500/502/503/504 e budget residuo condiviso. Nessun retry mutativo. Gli otto scenari precedenti conservano i propri profili. Errori e cleanup fallita restano FAILED con evidenze.

Qualifica perdita dei processi **dopo** vacuum completato; page cache e host restano vivi. Non crash durante commit/rename, power loss, reboot host, perdita disco, RPO/RTO, secure erase, spazio libero host o accettazione produzione. La compattazione di un volume con needle vivi dipende dall'allocazione nativa e deve essere dichiarata solo se osservata. Prove pre/post compaction distinte; vecchi prefissi/tombstone precedono il vacuum.

MiniPET invariato18,3/46=39,78%, circa40% ±10;0/8 gate,0/21 AT,0/120 oggetti reali. Nessun VPS/merge/deploy/replay/reset/grant; MinIO, scope17/52 Engine GET, Teatri/M1 e Farmacie preservati.
