# OUF — generazione33: SIGKILL master e recupero topologia

Stato: **64 test locali/hosted e quattro percorsi nativi PASS**. Run [41818110341](https://github.com/GioNob/ouf-deploy/actions/runs/41818110341), job126534003917, producer `85f2d40e35e4ba2db1a5aa47b616b45bc99e5e0e`. Estensione della fixture a cinque namespace, stessa OCI33 e coorte del checkpoint filer `4bc315fc25d2edb5b87105806fc1216bbdd061d1`. Nessuna modifica al binario candidato o al target.

## Esito nativo e originale verificato

- Solo master SIGKILL137/non-OOM. Container precedente `68b82676cda7676339bb3e862e71a09f25e7f3500fd1bdc5dbb7f100d575bb62`, sostituto `2e643db2d3622c04d84c8c7daf3c66665ae2e2b7aefba1171a3d8c5280cdedb0`. Nuovo namespace/gate, stesso IP/disco e altri quattro ruoli con ID/StartedAt/RestartCount invariati anche dopo il recupero. Regole prima dell'exec,19333/29333 chiusi prima del rilascio.
- **4 file master /1335 byte**: conf, log, max_volume_id e snapshot. Hash identici tra master fermo e sostituto ancora bloccato. Log del nuovo processo: `Recovered TopologyId` con lo stesso ID `6d6429a4-f3ba-40e0-9ee7-c7fd560beb77`, nuove registrazioni filer/S3 e volume server originale.
- Primo probe di lookup volume3 risponde **HTTP503 warming up, Retry-After14**. Il controller registra e attende **14 secondi**, senza accorciare l'attesa. Secondo probe PASS: readiness200, stesso TopologyId, lookup dei volumi3/5/6 identici sul nodo172.30.233.11:18080/gRPC28080. La vista conservata mostra di nuovo i sette volumi1–7; l'ordine dei writable cambia e non è assunto significativo. Non si dichiara uguaglianza byte di tutta la topologia dinamica.
- Metadati filer completi invariati. **Primo GET/HEAD/LIST S3 di recupero PASS**, nessun PUT aggiuntivo, nessun body GET prima del crash. Oggetto8388865 byte, SHA256 `25809f4ef8ae5e9ab82c2688effb8da2ae66bb0b320befd55350dcb2cda9569d`. Contatore HTTP volume13035→8411665, incremento8398630 byte TCP con overhead, non dimensione payload né RTO.
- Normale e tre crash separati:10 link ammessi/37 dinieghi ciascuno, other_denied zero, parità oggetto dopo i probe. **23 container distinti,20 arresti puliti,3 SIGKILL intenzionali**, quattro reti rimosse. Regressioni volume e filer conservano le rispettive prove.
- Artifact13315542510 originale: **235445 byte**, SHA256 `3c7b645e17bcab529a85f7092d3f89884d136a7931f24072905ed7b868d193e1`; **221 membri,220 checksum,21 hash sorgenti esatti**. Readback locale di archive/source binding, stati SIGKILL, root/gate/namespace, inventari, topologia/lookup/Retry-After/log, S3/TLS e rete PASS. Nessuna chiave privata esportata. Firma publisher della coorte verificata hosted, nessuna verifica crittografica locale aggiuntiva dichiarata.

[Archivio originale](../evidence/artifacts/storage-master-crash33-41818110341.zip) e [receipt di readback](../evidence/storage-master-crash33-readback-20261104.json). Nessuna seconda esecuzione nativa locale.

Prossimo singolo passo: arresto forzato dell'intero insieme master/volume/filer/S3 nella fixture e riavvio dalle stesse radici, con nuovi processi e regole prima dell'exec, senza reseed. È una prova di perdita congiunta dei processi/cache applicative; non viene chiamata power loss o reboot host.

## Protocollo eseguito

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
