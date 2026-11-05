# Piano delta finale: contratto offline e limiti

Il modulo `tools/storage_planning/delta_manifest.py` estende la pianificazione esistente senza cambiare il core Go di copia o gli adapter applicativi. Serve SW-WP4/SW-AT14–16: rende esplicite le differenze fra la baseline sorgente e la raccolta finale prima di scegliere gli effetti da eseguire.

## Input e risultato

`compile_delta(baseline, current, baseline_bodies, current_bodies, *, source_profile_sha256, destination_profile_sha256)` restituisce piano privato e riepilogo pubblico. I due inventari seguono `ouf.storage-private-inventory.v1`; restano raccolte metadata con `objectBodiesRead=0`. Le due mappe separate dei corpi contengono `entryId → bytes`, dove entryId è quello del compilatore inventario. Non è stato definito un nuovo collector target.

Tutti i byte sono ricalcolati con SHA256. Un hash `ouf-content-hash` dichiarato è solo confronto aggiuntivo; se manca, si calcola comunque l'hash; se diverge, STOP. Dimensione o ETag uguali non nascondono un corpo differente. Nessun claim `sha256` precompilato viene accettato come lettura verificata. Il modulo dimostra consistenza degli input locali, **non la provenienza autentica dei byte o uno snapshot temporale dello storage**.

| Classificazione | Significato del candidato |
|---|---|
| ADD | Chiave assente dalla baseline e presente nella raccolta finale; destinazione attesa assente ma non osservata |
| REPLACE_BODY | Stessa chiave, hash del corpo differente |
| REPLACE_METADATA | Corpo uguale, metadati/header/tag da conservare differenti |
| REMOVE | Chiave della baseline assente dalla raccolta finale completa; richiede nuova prova di assenza sotto fence prima di qualsiasi effetto |
| SOURCE_OBSERVATION_CHANGED | Corpo e rappresentazione uguali, osservazioni sorgente cambiate (es. ETag/Last-Modified/ordine tag); richiede riconciliazione, non riscrittura automatica |
| UNCHANGED | Uguali tutti gli input confrontati; non prova la parità corrente della destinazione |

L'intento include digest dei due inventari, corpi locali, profili e azioni; ogni variazione cambia il fingerprint. I digest dei profili sono input forniti dal chiamante, non attestazioni di identità. La precedente sorgente non è una prova della proprietà della destinazione. Ogni azione conserva la rappresentazione sorgente originale; Last-Modified non diventa implicitamente la nuova base di retention.

## Limiti e comportamento di blocco

- Per snapshot: 256 oggetti, 16MiB per oggetto, 64MiB complessivi; inventario JSON canonico massimo 4MiB. Due snapshot in memoria; nessun streaming o CLI operativo.
- Insieme bucket e feature deve restare identico. Raccolta incompleta, set dei corpi mancante/estraneo, hash o dimensioni divergenti bloccano; un inventario vuoto dichiarato completo produce soltanto candidati REMOVE senza autorizzazione.
- Namespace pericolosi/collisioni, versioning anche sospeso, versioni/marker, multipart pendenti, cifratura/hold/retention, lifecycle/replication/notification configurati richiedono un altro profilo. Nessuna degradazione silenziosa. Header ignoti e tag duplicati sono respinti.
- `publicAccessBlock=UNSUPPORTED` conservato aggiunge un requisito irrisolto; non equivale a funzione assente o accettazione policy.
- Output privato senza payload raw; riepilogo pubblico solo conteggi/byte/classificazioni, senza chiavi, profili, hash di oggetti o metadati. Il chiamante resta responsabile della custodia di input e piano privato.
- Sempre `executionEnabled=false`, `authority=null`, `automaticReplayAllowed=false`. Un nuovo fingerprint richiede reprocessing governato, non rinnova budget o scope. Nessuna rete, filesystem, credenziale, retry, PUT, DELETE o mutazione DB nel modulo.

Il successivo executor deve provare ownership e rilettura completa della destinazione, precondizioni correnti della sorgente, fence unico, journal durevole, budget owner, esiti ambigui, backup e riferimenti DB. In assenza di queste prove il piano resta non eseguibile. Non passarlo a `itemsFromPrivatePlan`: quel wire è copy-new e ha schema diverso.

## Verifica

22 test in `tests/test_storage_delta_manifest.py`: tutte le classificazioni, hash calcolati anche senza hint, overwrite stesso ETag/dimensione, input incompleti, set errati, bucket/feature drift, versioni/sospensione/marker, multipart, attributi protetti, namespace e Unicode, ordine tag, redazione, immutabilità input e fingerprint. Fixture di 120 oggetti/203743 byte con 10 hint mancanti, interamente generata. Nessun dato reale o riuso del vecchio scope17.

Comando locale/CI: `python3 -I -B -S -m unittest discover -s tests -p 'test_storage_delta_manifest.py' -v`. Il workflow dedicato conserva log, commit e hash dei quattro file sorgente/contratto CI. L'esito di test non è una ricevuta di migrazione o firma di provenienza degli inventari.

Accettazione invariata: 0 gate, 0 AT, 0 oggetti reali. Rehearsal MinIO→OCI33 e nuovo collector/executor non realizzati da questo blocco.
