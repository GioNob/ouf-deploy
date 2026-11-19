# Preparazione A2 — successor correnti dopo D-022

Task sprint-01/task-21, decisioni D-011 punto 4 e D-022. Solo codice e prove
locali: questo documento non attesta esecuzione sul VPS o una nuova ricevuta A.

## Motivazione e confine

La preparazione A dell'11 novembre lega il peer Semantic successivo al cutover D
e i due successor allora creati e mai avviati. D-022/task-20 ha ricreato il
southbound il 13 novembre senza `noswap`: il vecchio
`34adce783cba238c1954eb33e39c37a641ea4f0db212531951a2fd2b86290c52`
è stato rimosso; il nuovo è
`622a150067244ae8dbb4ac0f1889bc9e4b9823ed761820495f5c0849738dbc0d`,
transazione `864a28dbbd5ccc402f9406e500359123`.

L'adapter resta
`85b5302f6dbc3e9a24ace904b8d8a2d43bc5185e340c1bfe5474c723a6b640ef`,
transazione `7ff12b95c3f70c5eaebb1d0a12ab931d`. La ricevuta A originale non
rappresenta quindi la coppia corrente. A2 pubblica una nuova ricevuta, senza
riscrivere A o la storia di creazione e senza nuove CREATE, avvii, ammissioni,
sonde applicative o modifiche a runtime, reti, route o credenziali.

## Osservazioni e discendenza

`scripts/prepare-semantic-provider-a2-20261113.py` eredita da A la logica e i codici
di `read_cutover`, profilo Engine, generazione del cutover D, `verify_new`,
`backend_network`, binding read-only delle route, certificato configurato e hash
della foglia, `observe_peer` con `/proc`, veth reciproci e rilettura finale di
stabilità. Il confronto Docker usa API 1.44 come A e conserva integralmente
`Config.MacAddress` e gli endpoint, senza normalizzazioni o esclusioni MAC.
Non viene provato TLS live del southbound.

Sono caricati per SHA-256 gli stessi moduli invariati:

| Modulo | SHA-256 |
| --- | --- |
| `cutover-semantic-provider-20261111.py` | `ec69f0d86d337596ad562078eee18f87189310bb08f44a4f2b3550122b0366d9` |
| `upgrade-semantic-application-20261108.py` | `2e7e7e42367b3329f6ebd441bba665f974ea43871049d863415524610138efb1` |

A2 non cambia né usa i selettori storici `cutover.SUCCESSORS`,
`cutover.SOUTHBOUND_SUCCESSOR` o `cutover.SUCCESSOR_TRANSACTION`: CID e transazione
di ciascun ruolo sono argomenti obbligatori. Il ruolo è riconosciuto come in P:
l'alias `ouf-semantic-southbound-v2` identifica il southbound. Ogni successor deve
essere `created`, PID 0, mai avviato, RestartCount 0, restart `no`, runtime
`ouf-semantic-admitted-v2`, senza endpoint attivo e con label di creazione uguale
alla transazione CLI del proprio ruolo.

La lettura della precedente A applica gli stessi vincoli di `P.receipt_a`:
stato STAGED, piano atteso uguale in result e manifest, manifest identico,
`replayAllowed: false`, schema e root, pin e contenuti dei due artefatti.
`successors.json` è anche vincolato al suo hash CLI. L'adapter deve avere lo stesso
frame di A e la stessa transazione; il secondo CID di A deve essere l'`oldCid`
della ricevuta D-022.

La ricevuta D-022 richiede custodia root:root 0600, file regolare a link unico,
antenati root non scrivibili da gruppo/altri, hash esatto, schema
`ouf.semantic-southbound-successor-recreation.v1`, stato
`SOUTHBOUND_RECREATED_STOPPED`, CID nuovo e transazione CLI, `noswapRemoved: true`
e `containerStarts: 0`. Il digest della ricreazione replica esattamente i campi
`Id`, `Image`, `Config`, `HostConfig`, `Mounts`, `Path`, `Args`, `NetworkSettings`,
`State`, `RestartCount`, `Name`, usando `.get()` come il produttore. Un test lo
confronta direttamente con `frame_digest` dello script di ricreazione.
Il Tmpfs corrente deve uguagliare `plan.newSouthboundRequest.HostConfig.Tmpfs`.
Si verificano anche il digest canonico del piano D-022 e il digest della richiesta
con la nuova label, come prodotti da task-20.

Le letture della discendenza sono ripetute alla fine. I loro hash, inclusi quelli
di manifest/result precedenti, entrano nel calcolo del piano con la formula di A:
SHA-256 del JSON canonico di `{manifest, cutoverInputHashes}`. Il nome storico
`cutoverInputHashes` include ora anche questi input. Cambiare un input della
discendenza cambia il piano; un apply con digest precedente si ferma prima di
qualsiasi scrittura di output.

I rifiuti producono `HELD` con codici, tra cui
`A2_ADAPTER_LINEAGE_MISMATCH`, `A2_RECREATION_LINEAGE_MISMATCH`,
`A2_RECREATION_FRAME_MISMATCH`, `A2_RECREATION_TMPFS_MISMATCH`,
`A2_SUCCESSOR_TRANSACTION_MISMATCH`, `A2_SUCCESSOR_ROLE_MISMATCH` e
`A2_LINEAGE_CHANGED_DURING_READ`; custodia, hash, forma e ricevute hanno codici
dedicati. I controlli ereditati mantengono i codici di A.

## Formato e compatibilità con P

La nuova directory contiene gli stessi quattro file di A: `manifest.json`,
`result.json`, `semantic-peer.json`, `successors.json`. Il manifest conserva
`ouf.semantic-provider-preparation-a.manifest.v1` e il result conserva
`SEMANTIC_PROVIDER_PREPARATION_A_STAGED`: sono il contratto già consumato da P.
`semanticPeer`, pin `filesCreated`, percorso directory e frame dei container
mantengono la forma di A. P non impone un insieme chiuso di chiavi ai successor.

`successors.containers[]` aggiunge `transaction` per riga; `transactions` mappa
CID a transazione e sostituisce il vecchio singolo `transaction`.
`southboundCertificate` resta invariato. `lineage.previousA` contiene `root`,
`planSha256`, `successorsSha256`; `lineage.recreation` contiene `path`, `sha256`,
`planSha256`, `oldCid`, `newCid`.

La pubblicazione segue `stage` di A: root esistente e con custodia verificata,
nuova directory esclusiva 0700, file root:root 0600 con `O_EXCL`/`O_NOFOLLOW`,
fsync dei file e delle directory. Un output esistente viene rifiutato; un output
parziale non viene eliminato o sovrascritto. Il controller richiede root, `-I -B`
e imposta umask 077. `--plan` osserva senza creare output.

## Sequenza umana plan/apply

Il launcher è preparato per una consegna futura. Claude deve sostituire
`__PIN_COMMIT__` e `__PIN_CONTROLLER_SHA256__` dopo review e commit D-001.
Scarica controller, cutover e rollout dallo stesso commit fissato, li verifica
per SHA-256 in una directory temporanea root 0700 e usa
`sudo /usr/bin/python3.13 -I -B`. I due hash storici non cambiano.
La directory di consegna è conservata e stampata su stderr. Non è stata eseguita
in questo task. I pin incompleti causano uscita prima di download o sudo.

Comandi Bash per l'umano sul VPS, con launcher già consegnato e revisionato:

```bash
set -euo pipefail
umask 077
ouf_a2_recreation=/etc/ouf/deploy-snapshots/southbound-recreate-20261113-d022-v1/result.json
ouf_a2_recreation_sha=$(sudo sha256sum -- "$ouf_a2_recreation")
ouf_a2_recreation_sha=${ouf_a2_recreation_sha%% *}
[[ "$ouf_a2_recreation_sha" =~ ^[0-9a-f]{64}$ ]]

ouf_a2_args=(
  --adapter-id 85b5302f6dbc3e9a24ace904b8d8a2d43bc5185e340c1bfe5474c723a6b640ef
  --adapter-transaction 7ff12b95c3f70c5eaebb1d0a12ab931d
  --southbound-id 622a150067244ae8dbb4ac0f1889bc9e4b9823ed761820495f5c0849738dbc0d
  --southbound-transaction 864a28dbbd5ccc402f9406e500359123
  --previous-a-root /var/lib/ouf-storage-migration/semantic-provider-preparation-a-20261111
  --previous-a-plan-sha256 17de05e7d9b9610e58919a5b22697f28865ea0b076327d0b477fbae03d22daa8
  --previous-a-successors-sha256 5d9a1d3522edf79c7354bb905d7ca0b6cf56335f9893627cfcb330638c861567
  --recreation-receipt "$ouf_a2_recreation"
  --recreation-receipt-sha256 "$ouf_a2_recreation_sha"
  --output-root /var/lib/ouf-storage-migration
  --output-name semantic-provider-preparation-a2-20261113
)
bash scripts/deliver-semantic-provider-a2-20261113.sh --plan "${ouf_a2_args[@]}"
```

Esaminare il JSON `PLAN_READY`: peer, successor, transazioni e discendenza.
In caso di `HELD` riconciliare il codice senza riscrivere le ricevute. Solo dopo
la review del piano copiare il suo `planSha256` quando richiesto:

```bash
read -r -p 'planSha256 A2 revisionato: ' ouf_a2_plan_sha
[[ "$ouf_a2_plan_sha" =~ ^[0-9a-f]{64}$ ]]
bash scripts/deliver-semantic-provider-a2-20261113.sh --apply \
  --plan-sha256 "$ouf_a2_plan_sha" "${ouf_a2_args[@]}"
```

L'apply ricalcola tutte le osservazioni: se il digest cambia, resta senza output.
Per P si useranno la nuova root A2 e il nuovo piano A2 riportato nella ricevuta,
senza modificare P. Non riutilizzare il piano A dell'11 novembre come piano A2.

## Effetti a valle e verifiche

D-011 punto 4 resta il vincolo: A documenta la creazione dei successor osservati.
L'acceptance futura dovrà rappresentare **due transazioni** nella `creation`;
questa modifica appartiene a un task successivo. A2 non aggiorna quel consumatore.
Le prove rootfs del nuovo southbound devono riferirsi al nuovo CID e alla sua
generazione; i sigilli del rimosso non si trasferiscono automaticamente.
Le ricette dovranno mantenere il Tmpfs senza `noswap` di D-022 e riconciliare i
nuovi riferimenti, conservando gli originali. A2 non prova ammissione, avvio,
provider pronto, discovery o E2E e non abilita alcuno di questi passi.

La suite `tests/test_semantic_provider_a2.py` simula Docker e `/proc`, verifica
discendenza positiva e negativa, hash e custodia richiesti, transazioni per ruolo,
stato mai avviato, output esclusivo, plan senza scritture e apply con digest
cambiato senza scritture. Importa P originale e ne esegue `receipt_a` e
`read_roles` sulla ricevuta pubblicata da A2 con Docker simulato. I moduli storici
sono caricati con i pin originali e una modifica ai byte viene rifiutata.

```bash
sudo /usr/bin/python3.13 -I -B -m unittest discover -s tests -p test_semantic_provider_a2.py -v
bash -n scripts/deliver-semantic-provider-a2-20261113.sh
```

Il workflow PR esegue la suite su Ubuntu/Python 3.13 come root per verificare
anche lo staging POSIX 0700/0600. L'esecuzione locale Windows usa Python 3.12 e
adatta solo le primitive POSIX assenti; non attesta la custodia POSIX reale.
Le copie temporanee LF usate per i test dei pin corrispondono ai blob Git:
i moduli nel checkout Windows CRLF non vengono modificati. Nessuna esecuzione
CI o osservazione VPS è attestata dalla sola presenza di questo workflow.

Verifica locale del 13 novembre: **20 test passati, zero skip** con Python
3.12.12 (`C:/Program Files/QGIS 3.40.14/apps/Python312/python.exe -I -B`);
`bash -n` passato. Controllo AST: funzioni di osservazione, caricatore dei moduli
e `write` identici ad A. I blob Git dei due moduli corrispondono ai pin storici.
Il PASS Linux/Python 3.13 del workflow resta da acquisire dopo la pubblicazione
a cura di Claude; non sono stati eseguiti add, commit, push o accessi esterni.
