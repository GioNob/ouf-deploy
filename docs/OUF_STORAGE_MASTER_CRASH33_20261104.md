# OUF — generazione33: SIGKILL master e recupero topologia

Stato iniziale: **64 test locali PASS; qualifica nativa PENDING**. Estensione della fixture a cinque namespace, stessa OCI33 e coorte del checkpoint filer `4bc315fc25d2edb5b87105806fc1216bbdd061d1`. Nessuna modifica al binario candidato o al target.

## Protocollo

1. PUT singolo dell'oggetto deterministico8388865 byte e HTTP200, nessuna lettura del corpo prima del guasto. GET diretto dei metadati dal filer per ottenere i volume ID dei chunk; chiave condivisa `staging/volume-crash.bin`, radice di laboratorio separata.
2. Probe read-only loopback nel namespace master: `/readyz`, `/dir/status`, `/dir/lookup?volumeId=...` per ciascun volume referenziato. Si conserva TopologyId e risposta completa delle localizzazioni; niente fileId/JWT, assign, grow o mutazioni. Questi probe non passano dalle cache dei peer e non allargano il firewall.
3. SIGKILL del solo master: stesso ID, exit137/non-OOM, log/inspect conservati. Inventario della radice master a processo fermo, massimo128 voci/32MiB, file regolari senza symlink e contenuto non vuoto.
4. Stesso disco/IP ma nuovo container/namespace/gate, altri quattro ruoli senza restart. Regole nft installate e listener19333/29333 chiusi prima dell'exec; inventario identico mentre il sostituto è bloccato. Nessun sync, checkpoint o ripristino artificiale.
5. Il nuovo master deve restituire lo stesso TopologyId e le stesse localizzazioni dei chunk sul volume originale. Il log del solo nuovo container deve mostrare nuove registrazioni filer e S3. Attese di discovery limitate a10 probe/120s, backoff1/2/4/8/15s con jitter0–20%, Retry-After rispettato senza accorciarlo; risposta503 di readiness o404/503 dei soli volume ID noti significa registrazione pendente. Errori IAM, identità/localizzazioni errate, altri status e classi sconosciute bloccano.
6. Metadati filer completi invariati, GET/HEAD/LIST S3 firmati/TLS con stesso corpo/hash/MIME, contatore risposta HTTP volume aumenta almeno della dimensione payload. Nessun PUT di recupero. Matrice completa10 link ammessi/37 dinieghi e parità dopo i probe; cleanup verificato.

## Validazione e limiti

Dodici test nuovi su sostituzione del solo master, esclusione crash simultanei, query read-only, input volume ID, readiness/discovery pendenti, rifiuti permanenti e localizzazioni sbagliate, TopologyId, retry/jitter/Retry-After/budget, registrazioni, inventario e HTTP bounded. Totale64 con52 regressioni. YAML/shell verificati. Workflow nativo in quattro radici separate: normale, crash volume, crash filer, crash master.

Recupero di un singolo master sullo stesso host con disco/page cache conservati: non HA, failover multi-master, perdita quorum, power loss, reboot host, perdita disco o RPO/RTO. I probe verificano le localizzazioni dei chunk dell'oggetto e le registrazioni peer, non ogni attributo dinamico o servizio di una topologia produttiva. Lo store master può cambiare legittimamente dopo l'apertura: uguaglianza fisica solo durante fermo/gate; uguaglianza logica dopo ripresa.

I probe loopback sono diagnostici del laboratorio, non un'apertura alle API amministrative dai ruoli applicativi. API interne restano fidate/plaintext, autorizzazione metodi e mTLS non qualificati. Nessuna copia dei dati DB/payload esportata, soltanto inventari/hash/risposte/log bounded. Il budget di discovery appartiene alla fixture monouso e non certifica persistenza o resilienza dei retry runtime.

MiniPET invariato18,3/46=39,78%, circa40% ±10;0/8 gate,0/21 AT,0/120 oggetti reali. Nessun VPS/merge/deploy/replay/reset/grant. MinIO, scope17/52 Engine GET, Teatri/M1 e Farmacie preservati.
