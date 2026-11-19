# Sei route operative — proposta e applicazione

Controller fuori sprint, sorgente gateway
`8383cfe7946199badc5fcbb1bb3ac25160567541`. Aggiorna sul posto le tre
summary e clona ciascuna per incidents: N → N+3 route, N−3 invariate, con N
osservato dalla lista Admin e vincolato all'hash del piano (sul VPS il
2026-11-12: 87 → 90, 84 invariate; etcd `--keys-only` conta anche la chiave
cartella `/apisix/routes/`). Nessuna
prova locale o CI equivale a un'installazione sul VPS. Nessun deploy nel workflow.

Claude fissa `__PIN_COMMIT__` e `__PIN_SHA256__` dopo la review D-001. Il secondo
è SHA-256 dei byte del controller; manifest e tre helper sono già vincolati dal
controller. Consegnare gli stessi percorsi relativi `scripts/` e `releases/` del
commit approvato. I tre helper esistenti devono avere i byte Git LF, verificati
prima di importarli. Non copiare `.env` o configurazioni del gateway sorgente.

Il comando usa Python Linux, root e modalità isolata. Tutti i valori fra `<...>`
sono parametri dell'installazione: non sono default. `runtime-plan` è il piano
privato già custodito con `roles.apisix.containerId` e `nativeImage`; il relativo
hash è SHA-256 dei byte del file, distinto dal digest canonico `planSha256`.
La chiave Admin viene selezionata dal bind read-only della configurazione come
nel modello; `admin-key-file` è letto soltanto se la lista `admin_key` è vuota.
Nessuna chiave di delega viene letta o generata.

Le intestazioni installate ammesse sono soltanto due, dopo la riga esatta
`return function(conf, ctx)`, con assegnazioni `local NOME = <stringa JSON>`:

- `current`: `DELEGATION_KEY_ENV`, `ISSUER`, `AUDIENCE`, `MCP_WORKLOAD`,
  `CAPABILITY`, `OWNER`, `REQUIRED_SCOPE`, in questo ordine. Gli ultimi tre
  valori devono coincidere con la capability della route e il profilo fissato;
  resta il blocco `INSTALLED_OPERATIONAL_CONSTANTS_DIVERGE`.
- `legacy-execute-summary`: `DELEGATION_KEY_ENV`, `ISSUER`, `AUDIENCE`,
  `MCP_WORKLOAD`, `INGESTION_RECEIPT_KEY_ENV`, `GATEWAY_RECEIPT_KEY_ENV`, in
  questo ordine. È il formato condiviso di settembre, che sceglie il produttore
  da `CapabilityID`: l'identità della summary è verificata tramite id e uri.

Intestazioni ibride, riordinate, incomplete o con costanti aggiuntive sono
`HELD` / `KNOWN_OWNER_CONSTANTS_REQUIRED`; valori diversi da stringhe JSON
chiuse sono `CLOSED_OWNER_CONSTANT_REQUIRED`. I riferimenti alle chiavi devono
rispettare `[A-Z][A-Z0-9_]{0,127}` ed essere distinti. Le tre summary devono
avere lo stesso formato, le stesse costanti IAM e gli stessi riferimenti alle
chiavi ricevuta; ogni divergenza blocca il piano prima delle PUT.

Solo le due route desired con owner `gateway` ricevono `owner_key_env`, ricavato
da `GATEWAY_RECEIPT_KEY_ENV` installato: il Lua reso contiene `RECEIPT_KEY_ENV`
e firma `X-OUF-Operational-Receipt`. Nessun nome di chiave è fissato nel
controller e nessun parametro CLI può sostituirlo. Il formato `current` è
riconosciuto, ma non fornisce questo riferimento: il piano termina `HELD` /
`INSTALLED_GATEWAY_RECEIPT_KEY_REFERENCE_REQUIRED`, senza default.
`INGESTION_RECEIPT_KEY_ENV` viene validato e confrontato, ma non usato per la
resa: il produttore ingestion in esecuzione non richiede la ricevuta. Le route
MCP e ingestion sono rese senza ricevuta.

```sh
git rev-parse HEAD  # deve essere __PIN_COMMIT__
printf '%s  %s\n' '__PIN_SHA256__' scripts/apply-operational-execute-routes-20261111.py | sha256sum --check
# Preparare una directory root 0700; file del piano e journal saranno 0600.
sudo install -d -m 0700 '<evidence-root>'

sudo python3 -I -B scripts/apply-operational-execute-routes-20261111.py \
  --plan \
  --runtime-plan '<retained-runtime-plan>' \
  --runtime-plan-sha256 '<sha256-byte-runtime-plan>' \
  --evidence-root '<evidence-root>' \
  --admin-key-file '<existing-admin-key-file>' \
  --docker-bin '<absolute-docker-binary>' \
  --docker-socket '<absolute-docker-socket>' \
  --apisix-config-target '<mounted-apisix-config-path>' \
  --service-binding 'ouf-mcp-server=<mcp-runtime-host>' \
  --service-binding 'ouf-ingestion-runtime=<ingestion-runtime-host>' \
  --service-binding 'ouf-gateway-control-plane=<gateway-runtime-host>'
```

Sul VPS i binding comunicati sono `ouf-mcp-server=ouf-mcp-server`,
`ouf-ingestion-runtime=ouf-ingestion` e
`ouf-gateway-control-plane=ouf-gateway-control-plane`. Verificarli tramite il
piano: non sono assunti dal codice. Ogni host deve risolversi dal container
APISIX in un solo indirizzo e corrispondere a un solo endpoint di un container
running su una rete condivisa. Docker è osservato con API 1.44; Config/MAC e
frame APISIX sono confrontati integralmente dal guard esistente, con il solo
ordinamento dei record mount già qualificato nel modello. Nessun lifecycle.

Dopo il sì umano sul JSON pubblico e sul suo `planSha256`, ripetere lo stesso
comando sostituendo **soltanto** `--plan` con:

```sh
--apply --plan-sha256 '<planSha256-approvato>'
```

L'apply ricompila il piano da GET freschi e dalle osservazioni dei binding. Se
cambiano route, IAM o generazione/installazione, l'hash cambia e non parte
alcuna PUT. Ogni PUT è preceduta dalla verifica dell'intera mappa e da intento
fsync, seguita da ACK privato e rilettura esatta. Sono al massimo sei PUT senza
retry. L'Admin API non offre una transazione o CAS globale: una modifica
concorrente fra controllo e PUT resta un rischio da gestire con finestra
operativa esclusiva, e viene rilevata alla rilettura quando osservabile.

Scope: il gateway applica `REQUIRED_SCOPE` nel Lua post (`operations.status.read`
oppure `operations.incident.read`). La pre-function deve coincidere con quella
del profilo sorgente; OIDC non deve avere `required_scopes`. In caso contrario
`unsupportedDifferences` elenca campi e digest e l'esito è `HELD` /
`SUMMARY_PLUGIN_REVIEW_REQUIRED`: sottoporre il delta al reviewer prima di
estendere il perimetro. Anche scope trovati in altri campi conservati dei plugin
richiedono questa review. Il JSON include la relativa domanda esplicita.
Nessuna sostituzione testuale di scope in codice ignoto.
Gli ID/label installati e gli altri plugin vengono conservati intenzionalmente;
l'equivalenza CI riguarda schema, Lua, path e upstream, come richiesto.

Il JSON pubblico contiene solo digest dei valori privati, incluso il nome della
chiave ricevuta gateway. Espone `installedFormat` (`current` oppure
`legacy-execute-summary`) e `producerReceipt: true` sulle sole route gateway;
un'installazione `current` senza riferimento ricevuta resta comunque `HELD`
prima di produrre un piano. La proposta completa,
le immagini prima, gli intenti e gli ACK possono contenere segreti: restano nella
directory privata, non allegarli al report. La modalità plan scrive soltanto
evidenze locali, senza PUT. `runtimeChanged=null` significa che una PUT è stata
tentata ma il suo risultato non è dimostrato: riconciliare manualmente prima di
qualsiasi ulteriore azione. Una directory `apply-<hash>` preesistente impedisce
ogni replay, anche dopo un preflight fermato. Non cancellarla per riprovare e non
fare rollback automatico; usare le immagini prima per una review di ripristino
manuale distinta. Non riavviare container, né leggere SQL, chiedere token o
attivare provider.

Qualifica prevista sul runner GitHub `ubuntu-24.04`:

```sh
OUF_OPERATIONAL_GATEWAY_SOURCE='<checkout-8383cfe7946199badc5fcbb1bb3ac25160567541>' python3 -I -B -m unittest discover -s tests -p test_operational_execute_routes.py -v
sudo python3 -I -B tests/qualify_operational_execute_routes_native.py -v
```

Il primo verifica i sei membri del manifest byte per byte contro il checkout e
invoca il vero `materialize` operativo completo, sia senza parametro ricevuta
sia con `producer_receipt_key_envs={'gateway': <nome sintetico>}`. Confronta le
funzioni del controller byte per byte in entrambi i casi, oltre a schema, path
e upstream, con un runtime interamente sintetico e senza mock delle funzioni
gateway. Il caso senza ricevuta qualifica solo la compatibilità del renderer:
non autorizza un piano privo del riferimento installato.
Il secondo crea APISIX/etcd e tre peer effimeri, prepara 88 route sintetiche
con le tre summary nel formato condiviso di settembre, esegue la CLI
plan/apply, verifica sei PUT, 91 route e le 85 estranee invariate. Non prova
autenticazione applicativa, la verifica della firma da parte del produttore o
l'E2E operativo. Python non è disponibile nel PATH della
postazione locale di implementazione: esecuzioni e risultati CI restano da
acquisire prima dell'uso operativo.
