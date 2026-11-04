# OUF — generazione33: SIGKILL filer e recupero metadati

Stato: **52 test locali/hosted e tre percorsi nativi PASS**. Run [41816733896](https://github.com/GioNob/ouf-deploy/actions/runs/41816733896), job126529247006, producer `3ec6473670168b524ac06ca7015aca2416b837ae`. Estensione della fixture isolata già qualificata per il volume in run41814532710. Stessa OCI33, lock/coorte/binario e confini di rete; nessuna modifica alla candidata SeaweedFS o al target.

## Esito nativo e readback originale

- Filer SIGKILL exit137/non-OOM. Vecchio container `d6a31a477ff9d0308930760d9dc22ece6fa1f14e101cc9388a0f22d1ebec2e93`, nuovo `d396c084baa5b8e35d873f2275aeeee252477787071c0bb42fede5e8f4a384cd`. Namespace nuovo/non host, stessa radice/IP, altro gate; listener18888/28888 entrambi chiusi dopo installazione regole e prima dell'exec. Quattro altri ruoli invariati anche dopo la lettura di recupero.
- **40 file LevelDB2 /5272 byte**, inventari e hash esattamente identici tra processo fermo e sostituto ancora bloccato. Entrambi i log identificano lo store leveldb2. Nessuna deduzione di uguaglianza dei file dopo apertura/compattazione.
- GET diretto `?metadata=true` dopo ripresa restituisce **l'intero JSON identico**: path, size, MIME, timestamp, inode, MD5, owner/ACL/ETag/write-id e tre chunk da4194304+4194304+257 byte con gli stessi file ID/offset/hash. Il contatore TCP HTTP del filer ripristinato passa **0→1951 byte** durante tale richiesta, separata dal gateway.
- GET/HEAD/LIST S3 coerenti al **primo tentativo**, nessun nuovo PUT e nessuna lettura del corpo pre-crash. SHA256 oggetto `25809f4ef8ae5e9ab82c2688effb8da2ae66bb0b320befd55350dcb2cda9569d`,8388865 byte. Contatore risposta HTTP del volume **12515→8409733**, incremento8397218 byte. Questi sono byte TCP con overhead, non dimensione esatta del corpo né metrica prestazionale/RTO.
- Normale, crash volume e crash filer:10 link ammessi e37 dinieghi per percorso, contatori dedicati in aumento e other_denied zero. Parità S3 dopo i probe; **17 container distinti**,15 arresti finali puliti e2 SIGKILL intenzionali/non-OOM, tre reti rimosse. La regressione volume conserva i prefissi dei sette .dat/8389064 byte e legge al primo tentativo.
- Archivio GitHub originale artifact13315805136: **169069 byte**, SHA256 `ac19df973977f8a9d81a0bb201b1176d8e3bf5bc0b224fb2c578cb15a0ab48ca`; **158 membri,157 checksum,20 hash sorgenti esatti**. Rilettura locale indipendente di checksum, binding, inspect, namespace, regole/contatori, metadati, inventari, risposte TLS e cleanup PASS. Nessuna chiave privata presente. Verifica firma publisher della coorte eseguita hosted; nessuna verifica crittografica locale aggiuntiva dichiarata.

Originale conservato: [ZIP](../evidence/artifacts/storage-filer-crash33-41816733896.zip). Esito verificatore: [readback JSON](../evidence/storage-filer-crash33-readback-20261104.json). Nessuna seconda esecuzione nativa locale o esportazione dei database/payload viene dichiarata.

Prossimo singolo passo: SIGKILL del master nel laboratorio isolato, verificando ri-registrazione/topologia e lettura dell'oggetto già confermato, altri ruoli conservati, nessun reseed e firewall prima dell'exec. Non equivale a HA o failover produttivo.

## Protocollo eseguito

1. Un solo PUT dell'oggetto deterministico da8 MiB+257 byte, chiave fixture `staging/volume-crash.bin`, con HTTP200. Nessun GET del corpo prima del crash. La chiave è condivisa con il caso volume per mantenere il confronto; le radici dei tre laboratori sono separate.
2. GET read-only diretto `?metadata=true` dal namespace S3 al filer, su collegamento già consentito. Registrazione dell'intero JSON: percorso, dimensione, MIME, timestamp, attributi estesi e riferimenti chunk. Non passa attraverso cache del gateway e non legge il corpo.
3. SIGKILL del solo filer, exit137/non-OOM; log e inspect originali. Hash del tree LevelDB2 fermo, bounded a512 voci/32MiB, file regolari senza symlink, CURRENT/MANIFEST/dati obbligatori. Nessuna apertura del database con client, checkpoint, sync forzato o copia di recupero.
4. Nuovo container/namespace/gate, stessa radice filer e IP; master/volume/S3/client conservano ID, StartedAt e RestartCount. Hash LevelDB identici mentre il nuovo filer è ancora bloccato; firewall installato e due listener chiusi prima dell'exec.
5. Il nuovo filer deve restituire direttamente lo stesso JSON completo. Contatore HTTP in aumento sul nuovo namespace per attestare la risposta; GET/HEAD/LIST S3 firmati/TLS devono ritrovare lo stesso oggetto. Contatore HTTP del volume misura almeno la dimensione del payload durante la lettura, senza PUT di recupero.
6. Matrice completa invariata:10 link ammessi,22 dinieghi tra ruoli,15 DNS/host gateway con contatori. Parità oggetto dopo i probe, cinque arresti puliti e rete rimossa per laboratorio. Normale e crash volume restano regressioni native separate.

## Verifiche e limiti

Dieci test nuovi coprono sostituzione del solo filer, SIGKILL non-OOM, esclusione crash simultanei, mount/gate, inventario e corruzione/file mancanti/symlink/budget, metadati/chunk, GET diretto bounded e contatore. Totale52 con le42 regressioni volume/rete/credential/TLS; YAML e shell validati localmente.

La politica resilienza resta quella OUF: nessun retry mutativo, integrità/identità/permessi o errori sconosciuti bloccano. La lettura diretta metadati ha un solo tentativo dopo readiness; la rilettura S3 usa il profilo fixture già esistente, massimo6 tentativi e backoff1/2/4/8/15s solo su HTTP500/502/503/504, non una certificazione del retry runtime. Nessun aggiramento del firewall per riuscire.

È recupero del processo LevelDB2 sullo stesso host con page cache intatta, non power loss, reboot host, perdita disco, HA, replica o RPO/RTO. I file LevelDB possono cambiare legittimamente all'apertura/compattazione: l'identità byte è richiesta solo durante il fermo e prima dell'exec; dopo si verifica l'identità logica completa dei metadati. File DB e contenuti payload non sono esportati, solo inventari/hash e risultati hosted. L'HTTP interno resta fidato/plaintext; non si prova autorizzazione metodi, mTLS interno, IPv6 o isolamento da host compromesso.

MiniPET invariato18,3/46 =39,78%, circa40% ±10;0/8 gate,0/21 AT,0/120 oggetti reali. Nessuna operazione VPS/merge/deploy/replay/reset/grant. MinIO, scope17/52 Engine GET, Teatri/M1 e Farmacie preservati.
