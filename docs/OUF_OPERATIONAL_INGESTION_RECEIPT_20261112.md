# Ricevuta delle due route ingestion — 12 novembre 2026

Il controller `scripts/apply-operational-ingestion-receipt-20261112.py` propone
e applica due UPDATE: `execute-ouf.ingestion.operations.summary` e
`execute-ouf.ingestion.operations.incidents`. Sostituisce soltanto
`plugins.serverless-post-function.functions`; N resta N, tutte le altre N−2
route sono identiche. Il numero è osservato, non fissato a 90.

Importa il controller 20261111 solo dopo verifica SHA-256 dei byte LF
`4e06c241dd2c6607a683dfb770605a4e3813252bb1e6a2c5c24ea0e4d03c54c3`.
Riusa manifest gateway, renderer, helper con hash, transport Admin nsenter,
guard APISIX, binding, journal esclusivo e primitive private/fsync. Il publisher
20261111 impone sei modifiche e N+3: il nuovo script specializza soltanto il
ciclo journal/PUT/readback per due UPDATE e N→N, con un controllo aggiuntivo
del solo campo funzione. Nessun file 20261111 è modificato.

Il sorgente gateway è `8383cfe7946199badc5fcbb1bb3ac25160567541`. La resa usa
lo stesso renderer con riferimenti per entrambi gli owner `{gateway: G,
ingestion: NAME}`: per ingestion aggiunge `RECEIPT_KEY_ENV` dopo
`REQUIRED_SCOPE` e firma `X-OUF-Operational-Receipt`.

## Baseline privata obbligatoria

`--applied-plan` indica il `plan.private.json` dell'apply 20261111 già riuscito.
`--applied-plan-sha256` è il suo digest canonico atteso, calcolato con `digest()`
20261111 (JSON ordinato compatto, newline finale). È distinto dall'hash dei
byte di `--runtime-plan-sha256`. Nessuno dei due è fissato nel codice.

Il piano applicato deve stare sotto `--evidence-root`, in una directory
`apply-<applied-plan-sha256>` root 0700; il file deve essere regolare, root
0600, di nome `plan.private.json`. La radice è root 0700, così come eventuali
directory intermedie. Traversal e symlink sono rifiutati; la traversata usa
directory descriptor con `O_NOFOLLOW`. La lettura usa il `read()` originale,
limitato a 16 MiB, con identità stabile, più verifica di proprietà e permessi
prima/dopo. Occorre Linux con `/proc/self/fd`.

Prima di qualunque PUT:

1. Il digest canonico deve coincidere con il parametro CLI.
2. Il piano deve essere esattamente riproducibile dal compilatore 20261111,
   senza differenze sospese. Le sei desired sono quindi verificate per intero.
3. La mappa attesa è `before` con tutte le `change.desired` applicate. L'intera
   mappa corrente deve coincidere, comprese le route estranee. Solo
   `create_time` e `update_time` sono esclusi, come nel controller originario.
4. Le sei funzioni devono avere le costanti IAM comuni e coincidere con la resa
   corrente; le due gateway devono avere lo stesso G. Le ingestion devono
   essere senza `RECEIPT_KEY_ENV`. Una ingestion già firmata dà
   `HELD / ALREADY_APPLIED_OR_DIVERGENT`; qualunque altra differenza della
   mappa dà `CURRENT_MAP_DIFFERS_FROM_APPLIED_PLAN`.

Le due desired partono dalle route della mappa attesa: nessun plugin, schema,
URI o upstream viene ricostruito o sostituito fuori dal campo autorizzato.
Il piano pubblico contiene `appliedPlanSha256` e
`currentMapMatchesAppliedPlan`, mai campi privati del piano applicato.

## Parametri e approvazione

Esecuzione Linux root con Python isolato, stessi percorsi relativi del
repository e byte LF del controller, degli asset e degli helper fissati.
Tutti i segnaposto seguenti sono dati dell'installazione, senza default:

```sh
sudo python3 -I -B scripts/apply-operational-ingestion-receipt-20261112.py \
  --plan \
  --applied-plan '<evidence-root>/apply-<digest-applicato>/plan.private.json' \
  --applied-plan-sha256 '<digest-canonico-piano-applicato>' \
  --ingestion-receipt-key-env '<nome-env-installato>' \
  --runtime-plan '<piano-runtime-privato>' \
  --runtime-plan-sha256 '<sha256-byte-piano-runtime>' \
  --evidence-root '<evidence-root>' \
  --admin-key-file '<file-admin-esistente>' \
  --docker-bin '<binario-docker-assoluto>' \
  --docker-socket '<socket-docker-assoluto>' \
  --apisix-config-target '<config-montata-apisix>' \
  --service-binding 'ouf-mcp-server=<host-mcp>' \
  --service-binding 'ouf-ingestion-runtime=<host-ingestion>' \
  --service-binding 'ouf-gateway-control-plane=<host-gateway>'
```

`NAME` deve rispettare `[A-Z][A-Z0-9_]{0,127}` ed essere diverso dal riferimento
di delega e da G. Deve comparire tra i nomi di `Config.Env` di APISIX running,
letti dal Docker inspect API 1.44 già usato dal transport. L'assenza dà
`INGESTION_RECEIPT_KEY_NOT_EXPOSED_TO_APISIX`. Nessun valore ENV viene
stampato o persistito, neppure nel journal privato: si conservano il digest del
nome richiesto, il digest della lista ordinata dei nomi e il booleano
`exposedToApisix`. La presenza del nome non prova il caricamento della chiave
in Lua né la verifica applicativa della firma da parte del produttore.

La modalità plan effettua solo letture runtime e scrive evidenza locale privata;
termina con `HUMAN_HASH_APPROVAL_REQUIRED`. Il JSON pubblico espone per ogni
route `beforeSha256`, `afterSha256`, `producerReceiptBefore: false` e
`producerReceiptAfter: true`. Riferimenti, credenziali, IAM e binding privati
compaiono soltanto come digest. Il nome della chiave non è pubblicato.

Dopo review umana del JSON e del `planSha256`, usare gli stessi parametri,
sostituendo soltanto `--plan` con:

```sh
--apply --plan-sha256 '<planSha256-approvato>'
```

L'apply ricompila il piano da letture fresche e confronta l'hash prima della
prima PUT. Crea esclusivamente `apply-<planSha256>` root 0700, con file 0600:
un tentativo già presente blocca ogni replay, anche se aveva fallito prima
della prima PUT. Non cancellarlo per riprovare. Il binding guard è conservato:
DNS da APISIX, unico peer running su rete condivisa e osservazione immutata.
Il transport continua a verificare Config/NetworkSettings/MAC e configurazione
Admin senza nuove esclusioni o normalizzazioni. La presenza ENV è ricontrollata
prima di ciascuna PUT.

Ogni PUT è preceduta da guard, rilettura dell'intera mappa e intento fsync;
seguono ACK privato, nuova rilettura integrale ed evidenza verificata. Il
successo riporta `routeWritesVerified: 2`, `unchangedRoutesVerified: N-2` e
`finalRouteCount: N`. Se una scrittura è incerta, `runtimeChanged` resta `null`.
Non ci sono retry o rollback. APISIX non offre CAS globale: occorre una finestra
operativa esclusiva; il controllo prima/dopo rileva le divergenze osservabili,
non elimina la corsa fra GET e PUT.

## Qualificazione e limiti

Il nuovo workflow si attiva sulle PR per i cinque nuovi file e sui push al
branch del task. Non esegue deploy. Il checkout gateway è fissato al commit
completo e il test confronta i sei asset byte per byte, poi invoca il vero
materializzatore con la mappa `{gateway, ingestion}`. Confronta tutte le sei
funzioni, oltre a schema, path e upstream, senza mock del gateway.

La suite Linux root copre baseline completa, divergenze anche estranee, piano
e file applicato, permessi/proprietà, symlink, hash, nomi ENV, journal,
interferenze e risultati incerti. Il workflow richiede zero skip. La qualifica
nativa crea APISIX/etcd reali e tre peer effimeri come il test 20261111, espone
un nome ENV sintetico, prepara 90 route, esegue plan e due PUT, verifica 88 route
invariate e il readback completo, hash errato, replay e seconda plan già firmata.
Le PUT di preparazione della fixture sono distinte dalle due PUT del controller.

```sh
sudo env OUF_OPERATIONAL_GATEWAY_SOURCE='<checkout-gateway-fissato>' \
  python3 -I -B -m unittest discover -s tests \
  -p test_operational_ingestion_receipt_20261112.py -v
sudo python3 -I -B tests/qualify_operational_ingestion_receipt_native_20261112.py -v
```

Sulla postazione Windows i test puri usano flag di lettura sintetici e fsync
directory simulato; i quattro test filesystem Linux restano esclusi. Questo
non qualifica sicurezza POSIX o transport. L'equivalenza reale è stata eseguita
anche localmente su un export temporaneo LF del commit gateway già presente,
letto senza modificare quel repository. Il checkout Windows CRLF non può
soddisfare il confronto byte per byte; l'export usa `core.autocrlf=false`, senza
normalizzare i byte durante il test. Docker locale non è disponibile e WSL
nega l'accesso: esiti Linux root, nativo e CI restano da acquisire. Nessun accesso
VPS, segreti o reti esterne è stato effettuato. La qualifica nativa non prova
IAM applicativa, verifica della ricevuta nel produttore o E2E.
