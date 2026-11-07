# OUF — generazione33: restart completo dopo compattazione

Stato: **122 test locali/hosted e nove scenari nativi PASS**. Checkpoint iniziale `bd1dec94747cb13058c740672701f2213c5d01a1`; stessa OCI33, nessuna modifica al candidato. Il nono scenario conserva gli otto precedenti e aggiunge un secondo crash congiunto dopo la compattazione conclusa.

## Risultato nativo e readback verificato

Run [41840445331](https://github.com/GioNob/ouf-deploy/actions/runs/41840445331), job126614148697, producer `6aa6d73b3096a4b2de8c7f2300751a0f8019118c`: **122 test e nove scenari nativi PASS**.72 container distinti,45 arresti finali puliti,27 SIGKILL intenzionali e nove reti rimosse. Prima esecuzione41840244896 anch'essa PASS; il risultato ufficiale qui è sul commit con i residui TLS sintetici rimossi.

Nel nono caso un solo vacuum sul volume2/chunk `2,048c099d33` recupera4194304byte allocati. Poi quattro servizi137/non-OOM prima di qualsiasi nuovo container, quattro nuovi namespace verificati con pin, client invariato e tutti i firewall prima di exec. Nessun PUT di recupero o secondo vacuum.

| Misura | Prima della compattazione | Dopo compattazione | Dopo secondo crash/recupero |
| --- | ---: | ---: | ---: |
| Lunghezza totale DAT | 12583448 | 8389064 | 8389064 |
| Blocchi DAT allocati (byte) | 12611584 | 8417280 | 8417280 |
| Byte indice selezionato | 48 | 16 | 16 |

Tutti i DAT/IDX mantengono hash, lunghezza, mappe needle e allocazione nei tre snapshot gated/recuperato/finale. Payload/tombstone orfano assenti, nessun temporaneo/handle unlinkato nel processo volume. Chunk diretto404 e S3 GET/HEAD404/LIST baseline-only. Baseline8388865byte integra al tentativo1; metadati completi identici. Nuovo filer0→1954byte, nuovo volume0→8398110byte; topologia/registrazioni recuperate al tentativo1. Ripetuti11 link ammessi e36 dinieghi dopo il secondo riavvio.

Nel volume2 selezionato era presente **un needle valido da4194304byte (id3)** insieme all’orfano tombstoned (id4). Il needle valido conserva hash/cookie/dimensione dopo vacuum e restart; indice48→16byte. Il payload orfano iniziava dopo il record valido (offset4194360): non si dichiara provata la rilocazione di un record valido posto oltre un buco. I dati validi degli altri volumi restano identici. Non si trasferisce al nuovo caso una qualifica di crash DURANTE compattazione.

Artifact13328848598:802573byte, SHA256 `7241c26b7552bff51cc959d4730d84f993b0810552bd398806dd94aaf784a70c`. Verificati810 membri/809 checksum/29 sorgenti del producer, assenza chiavi private e tutti i percorsi semantici. [Originale](../evidence/artifacts/storage-compaction-restart33-41840445331.zip), [readback](../evidence/storage-compaction-restart33-readback-20261104.json). Readback di riepiloghi nativi vincolati al codice, non seconda esecuzione Docker locale o esportazione DAT/IDX/DB. Firma del publisher non riverificata localmente; la CI verifica l'attestazione della coorte in ingresso.

Prossimo singolo passo: fixture con un record tombstoned prima di un needle valido nello stesso volume; verificare esplicitamente cambio offset, integrità e persistenza del needle rilocato.

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

Nota di pubblicazione: il primo commit4189dbec includeva accidentalmente due file temporanei TLS sintetici (CA della fixture locale). Rimossi subito dal ramo nel commit successivo, con pubblicazione da lista esplicita e controllo anti-chiavi. Nessuna chiave del target è stata usata; i file restano nella storia Git del primo commit e non sono inclusi nelle evidenze native.
