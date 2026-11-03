# SeaweedFS 4.52 — prova isolata di cold recovery storage

Stato preparazione: `HOSTED_EXECUTION_REQUIRED`. Questo documento non dichiara un
risultato live. La workflow produce `SYNTHETIC_STORAGE_COLD_RESTORE_PASS_NOT_ACCEPTANCE`
soltanto dopo l'intera esecuzione riuscita.

La prova scarica l'esatto artifact OCI `13224053625` (SHA256
`bca4d0a493717812d464f9dc6c7478d918c5dd7f56cd7b5d21f0d4fbcccaeed9`), verifica
il lock a 15 patch, checksum interni e ricostruzione OCI. Docker deve caricare
l'esatto config digest `sha256:add1988121001fe6339a31635d5f61bc560b3c9a540da8027e376a4ebdf0df35`.
Non ricompila il server, non introduce immagini ausiliarie né cambia il candidato.

## Prova prevista

Quattro container separati eseguono master, volume, filer e S3 come UID 65532,
root filesystem read-only, nessuna capability, no-new-privileges, limiti di CPU,
RAM, processi e log. Il master usa rete Docker `none`; gli altri condividono
soltanto quel namespace, senza porte pubblicate. Il client standard-library
Python entra nel namespace con `nsenter -n`: mantiene il filesystem host del
runner, non entra nel mount namespace dei servizi. Gli inspect e le route
effettive sono conservati e verificati. Non si tratta di qualifica delle
NetworkPolicy, nft/DNS o dell'isolamento laterale di un ambiente target.

Il client effettua richieste SigV4 con una sola esecuzione di ogni mutazione.
La sola readiness, read-only, ha massimo 60 probe e deadline di 90 secondi.
Le fixture comprendono corpo vuoto, Unicode/escaping, 8 MiB, overwrite e delete;
LIST paginato, GET, HEAD, byte e metadato `ouf-content-hash` sono confrontati.

Dopo il ritorno del solo writer, tutti i servizi devono terminare pulitamente.
Il codice crea una copia fredda verificata SHA256, rimuove i vecchi container,
sposta gli originali fuori dai percorsi di mount e ripristina in una radice
nuova. Nuovi container montano solo quella radice e la configurazione copiata;
il confronto completo dei quattro oggetti conservati e dell'oggetto eliminato
deve riuscire. Gli originali e il backup non vengono distrutti durante la prova.

## Limiti espliciti

È un sottoinsieme storage della fondazione G3: **non soddisfa l'intero contratto
di backup** che richiede PostgreSQL. Non esegue PostgreSQL, PITR, riconciliazione
DB–oggetti, TLS/rotazione, interruzione elettrica, perdita host, versioning,
retention, multipart, workload rappresentativo o prove di latenza/capacità.
La durata osservata riguarda soltanto il piccolo drill sintetico e non prova
RPO/RTO. I valori iniziali del PET UDP §81 (DB RPO ≤15 minuti, core RTO ≤4 ore)
restano requisiti da confermare con infrastruttura ed esercitazione adeguate.

Il profilo dichiarativo della fondazione non viene materializzato letteralmente:
questa prova usa radici effimere del runner mappate a `/data` in ogni container,
con configurazione distinta read-only. La ricevuta registra
`foundationProfileMaterializedVerbatim=false`, oltre al contratto completo non
soddisfatto. Un fallimento conserva una ricevuta negativa e i log disponibili;
non viene attestato un manifest di successo.

La configurazione S3 usa credenziali pubbliche fixture e HTTP esclusivamente nel
namespace privo di egress. Nessuna identità o autorità target deriva dal test.
Restano 0/8 gate, 0/21 AT, 0/120 oggetti reali; MinIO attivo, Scope17/52,
Teatri/M1 e Farmacie invariati. Release, redistribuzione e custodia durevole
non vengono ammesse. L'artifact CI è temporaneo, con retention di 90 giorni.

## Primo run e correzione del bootstrap

La CI `41687967286`, sul commit `70cd2671b41b0f775889826b2617811451a5e2ba`,
ha superato unit test, download/identità OCI, avvio dei quattro container,
controlli di isolamento e LIST di readiness. Il client seed è fallito prima
del backup. Il suo stderr non era conservato; non si attribuisce un codice
HTTP o un timeout osservato direttamente. I log mostrano però che la prima
allocazione volume ha atteso 5,75 secondi e che il filer ha applicato il lock
ring solo dopo l'avvio delle scritture, oltre il timeout HTTP di 5 secondi.
Tutti i quattro servizi sono poi terminati con ExitCode 0. Nessun restore PASS.

L'artifact negativo `13255691039` (12.262 byte), SHA256
`995bcdc53ea256709135c8fe6bf1a840c7fb1c14b16a0a1bb3e933a579516da7`, è stato
scaricato e riletto indipendentemente. La correzione attende l'evento applicato
del lock ring del filer esatto con soli controlli read-only, massimo 60 poll e
90 secondi. Ogni richiesta operativa ha timeout 30 secondi, senza retry mutativi;
il client seed/verify ha budget totale 180 secondi; la readiness HTTP ha un
cap totale separato di 90 secondi, imposto anche al processo figlio. I 24 slot volume coprono i due gruppi
di crescita iniziale da sette volumi (bucket e metadati filer), senza preallocare
lo spazio. Il nuovo test riparte da fixture vuote in un runner distinto; non
ritenta la mutazione ambigua del run precedente. Lo stderr figlio è ora
conservato anche per scadenza dei 180 secondi, normalizzando output bytes/testo
e limitandolo a 32 KiB UTF-8. Ogni inspect, lettura log e attesa della readiness
è limitato dal budget residuo dei 90 secondi. La [ricevuta negativa](../evidence/seaweedfs-452-cold-recovery-failed-20261103.json)
separa fatti osservati e ipotesi causale. Undici test locali PASS includono
clock simulato per richieste e attese limitate dal tempo residuo, rifiuto di
risposta positiva tardiva e verifica del cap complessivo del processo readiness.
I fallimenti permanenti continuano a fermarsi dopo un solo tentativo. Resta
necessaria una nuova qualifica hosted.
