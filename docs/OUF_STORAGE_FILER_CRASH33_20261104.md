# OUF — generazione33: SIGKILL filer e recupero metadati

Stato iniziale: **52 test locali PASS; qualifica nativa PENDING**. Estensione della fixture isolata già qualificata per il volume in run41814532710. Stessa OCI33, lock/coorte/binario e confini di rete; nessuna modifica alla candidata SeaweedFS o al target.

## Prova richiesta

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
