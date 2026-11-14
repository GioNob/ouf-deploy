# B1: ricette dei successor correnti — task-22, r2

Il controller `scripts/prepare-semantic-provider-b1-recipes.py` prepara otto file
privati e `result.json` per i successor correnti. Non avvia container, non firma,
non concede accettazione e non chiama servizi applicativi. Le sole chiamate
Docker ammesse dal controller sono GET API 1.44 sul socket locale esplicito.
Questo documento descrive codice e prove sintetiche; non attesta esecuzione VPS.

## Origine delle quattro parti

| Parte | Origine indipendente |
| --- | --- |
| `launch` adapter | `build_request(historical_ids, ADAPTER, True)` del modulo di ricreazione autenticato per hash, senza eseguire `main`. Digest canonico uguale a `plan.reconstructedRequestDigests[ADAPTER]` della ricevuta D-022. |
| `launch` southbound | `plan.newSouthboundRequest` della ricevuta D-022 root:root 0600, autenticata con hash CLI. Include entrypoint `/bin/sh -c` e tmpfs senza `noswap`. |
| `template` adapter | Baseline containerd-overlayfs adapter e builder storico, entrambi fissati per hash; `approvedUser` e `mountOrdering` provengono dalla baseline. |
| `template` southbound | Baseline tmpfs qualificata dal task-19 e builder tmpfs fissato per hash, con lo stesso `mountOrdering`. La dichiarazione `manifest.tmpfs` deve coincidere esattamente con quella della baseline. |
| `context` | CID CLI e sei parametri di layout espliciti; `networkNamespaceName: null`, `rootfsPath = rootfs-parent/CID`. Il compilatore verifica `docker_context`. |
| `policy` | `compile_policy(template, launch, context)` del compilatore fissato, senza argomento OCI osservata. |

Gli inspect correnti verificano richiesta, transazione, runtime e stato
`created`, mai avviato. Riutilizzano integralmente `inspect_created`, inclusa
l'unica normalizzazione qualificata: `OomKillDisable: null` nella richiesta
diventa `false` nell'inspect. Nessuna esclusione di `Config.MacAddress`: resta
il controllo del modulo di ricreazione sul profilo legacy e sugli endpoint.
Il digest del frame corrente deve coincidere anche con il frame trattenuto in A2.

La ricevuta A2 applica il contratto di `P.receipt_a`: status STAGED,
`planSha256` atteso uguale in result e manifest, manifest identici, replay falso,
schema/root, pin e contenuti di `semantic-peer.json` e `successors.json`.
Si verifica anche l'hash CLI di successors, l'insieme esatto di due CID e
transazioni, e il binding della ricreazione nella lineage A2.

La correzione r2 è applicata esattamente: per verificare `newRequestSha256`
si calcola `sha(canonical(plan.newSouthboundRequest | {"Labels":
{OWNER_LABEL: southbound_transaction}}))` con la canonicalizzazione del modulo
di ricreazione e si controlla `newTransaction`. Per il launch si usa invece
la richiesta senza label. Le label non entrano nell'OCI. Il digest originale
`reconstructedRequestsSha256` è conservato come lineage, non ricalcolato
ricreando il southbound storico.

## Launch dalla richiesta

`creation_launch.py` usa `Entrypoint + Cmd`, `WorkingDir`, `User` numerico
nonroot, `HostConfig` e bind ordinati della richiesta. Usare l'OCI da verificare
per costruire l'aspettativa renderebbe il confronto circolare. Anche il vecchio
`launch_from_spec` non basta per il southbound: usa l'entrypoint dell'immagine,
mentre questa creazione lo sovrascrive.

Per l'adapter il test di parità ricostruisce spec e configurazione immagine
coerenti con la stessa richiesta e confronta l'intero launch con
`launch_from_spec`. L'ambiente segue Docker: PATH predefinito, HOSTNAME con slot
`$OUF_HOSTNAME`, poi Env della richiesta. Un PATH dell'immagine sostituisce il
valore nella posizione originaria, senza spostarlo. Duplicati e override di
HOSTNAME vengono rifiutati. Non si applicano sostituzioni generiche alle stringhe.

La memoria deve essere positiva e uguale a MemorySwap, pids positivo, bind tutti
RO, nessun Binds alternativo. Le sorgenti riportano esattamente le otto chiavi
del compilatore, con `maxBytes: 1048576`.

## Custodia e D-021

Ogni sorgente è aperta con descriptor relativo a una catena di directory
root, senza symlink e senza scrittura di gruppo/altri. Si richiedono file
regolare, nlink 1, massimo 1 MiB, modo 0600 o 0644. Il profilo di ownership
riusa quello di `create-provider-v2-stopped.py`: input del ruolo appartenenti
a uid/gid del ruolo; il solo `trust-bundle.pem` pubblico appartiene a root:root
ed è 0644. `provider-receipt.key` richiede sempre 0600. Metadati, identità e
dimensione vengono ricontrollati dopo la lettura.

La chiave southbound nel bind esatto di D-022 viene solamente hashata: FileIO
`readinto(bytearray)` alimenta SHA-256 attraverso memoryview. Il buffer è
azzerato dopo ogni lettura e nel finally; non viene decodificato né restituito.
Python e la libreria di hash non offrono una garanzia di cancellazione di ogni
copia interna: il codice evita copie immutabili esplicite dei byte della chiave.
Nessun contenuto viene scritto, copiato o loggato. Solo il digest entra in launch
e policy privati. I test cercano una sentinella sintetica in stdout, piano e
tutti i file pubblicati, usando anche il lettore effettivo della chiave.
`secretBytesHashed: 1` indica l'unica sorgente HMAC southbound prevista dal task;
anche gli altri bind vengono hashati senza esportarne il contenuto.

I controlli `protected_file` e `verify_routes` di D-022 vengono riusati per la
chiave e per la configurazione southbound; non leggono il contenuto HMAC.
Gli errori pubblicano soltanto codici costanti, senza testo libero delle eccezioni.

## Chiusura software fissata

| File riusato | SHA-256 dei byte di delivery |
| --- | --- |
| `scripts/recreate-southbound-successor-20261113.py` | `13fe99b68e6e81af7976cf3b8a4c2e3b1d3ccfc0cb3896be0fd8665cf6390bcb` |
| `tools/semantic_frame_compiler/compile_creation_frame_policy.py` | `36ee627e524415002a98fede8d7e61ad22ae95b6fec6b6686c1e01d878be570d` |
| `tools/semantic_frame_compiler/build_role_frame_template.py` | `64f71f1c1414a87fda7e98a4402bef2b12ff8c5a917766810412825cca54f00c` |
| `tools/semantic_frame_compiler/containerd-overlayfs-adapter.json` | `6dc554812c9298baffeb1ef7314eb2f43d7d4e5e41aea791f506a723f527b41e` |
| `tools/semantic_successor_recipes/build_role_frame_template_tmpfs.py` | `63a04a56ac483b36e304db6694723dd5114372dc85011da5e1a5ae6b1aae3a15` |
| `tools/semantic_successor_recipes/containerd-overlayfs-southbound-tmpfs.json` | `326d0b88276db8dde1729dfe0fabed9ca9d8ff9e8f6b87e6fcba7fa8f1741080` |

Le baseline hanno costanti nel controller, senza nuove opzioni CLI. Anche il
generatore nuovo ha un pin esplicito nel controller. Tutta la chiusura è letta
sotto custodia root:root 0600/0644 e autenticata prima degli import; viene
ricontrollata prima della pubblicazione. I byte CRLF di un checkout Windows non
sono accettati dal controller al posto dei byte LF fissati.

Il launcher mantiene la struttura `scripts/`, `tools/semantic_frame_compiler/`
e `tools/semantic_successor_recipes/`, in una nuova directory 0700 sotto
`/etc/ouf/deploy-snapshots`, con antenati protetti (non sotto `/var/tmp`).
Ogni download ha un SHA-256 verificato.
Dopo review e commit, Claude deve sostituire `__PIN_COMMIT__`,
`__PIN_CONTROLLER_SHA256__`, `__PIN_LAUNCH_SHA256__` con i tre valori distinti
del commit e dei due file nuovi. Fino ad allora il launcher si ferma.
Il pin di creation_launch nel controller deve restare coerente con il file
revisionato. Nessun commit, push o download è parte dell'implementazione locale.
Prima dell'esecuzione si verifica nuovamente l'hash di `/usr/bin/python3.13`
`889c603f0d17cb54060951bcf4c4f9b8c9ebd9e52b392c70209bbb9755d797d9`,
poi si esegue `sudo /usr/bin/python3.13 -I -B`. Root:root e umask 077 obbligatori.

## Sequenza umana plan/apply

Nessun valore operativo è un default nel controller. Il piano A2 non è fornito
come digest nella consegna del task: l'umano inserisce quello della ricevuta A2
già revisionata, senza inventarlo o usare il vecchio piano A. Il digest dei
successors e quello della ricevuta D-022 sono invece quelli forniti nel task.
Non rieseguire A2 o D-022. I parent context sono quelli del preparatore storico
`prepare_provider_v2_frame_policies.py`.

```bash
read -r -p 'planSha256 della preparazione A2 già revisionata: ' ouf_b1_a2_plan_sha
[[ "$ouf_b1_a2_plan_sha" =~ ^[0-9a-f]{64}$ ]]
ouf_b1_args=(
  --a2-root /var/lib/ouf-storage-migration/semantic-provider-preparation-a2-20261113
  --a2-plan-sha256 "$ouf_b1_a2_plan_sha"
  --a2-successors-sha256 394562b4162e8d1b615a6b61897446c8316b37e7a438fa99b389dbb5f119dfdb
  --recreation-receipt /etc/ouf/deploy-snapshots/southbound-recreate-20261113-d022-v1/result.json
  --recreation-receipt-sha256 56528cb24df9ce1d48f18ee67ac8105d308db8ee1602dd604a9573b08b22b79c
  --historical-adapter-id f3d59af93fc90162681cee3a7562bdff3bf2af8c05cbdb7e270d1508fff18f67
  --historical-southbound-id 1fc5ae6a0db4600e0124bb1f9d2998780d533fd2b4de7cb086d8675b6afb5916
  --adapter-id 85b5302f6dbc3e9a24ace904b8d8a2d43bc5185e340c1bfe5474c723a6b640ef
  --southbound-id 622a150067244ae8dbb4ac0f1889bc9e4b9823ed761820495f5c0849738dbc0d
  --adapter-transaction 7ff12b95c3f70c5eaebb1d0a12ab931d
  --southbound-transaction 864a28dbbd5ccc402f9406e500359123
  --expected-runtime ouf-semantic-admitted-v2
  --docker-socket /var/run/docker.sock
  --bundle-parent /run/docker/containerd/daemon/io.containerd.runtime.v2.task/moby
  --metadata-parent /var/lib/docker/containers
  --network-namespace-parent /run/docker/netns
  --cgroup-driver systemd
  --storage-parent /var/lib/docker
  --rootfs-parent /var/lib/docker/rootfs/overlayfs
  --output-root /etc/ouf/deploy-snapshots
  --output-name semantic-provider-b1-recipes-20261113-v1
)
bash scripts/deliver-semantic-provider-b1-recipes.sh --plan "${ouf_b1_args[@]}"
```

Il plan non scrive file: stampa hash di template/launch/context/policy per
ruolo, baseline, chiusura software e input, con `planSha256`. Non stampa i
documenti launch o policy né il contenuto delle richieste. L'output di delivery
del launcher è distinto: conserva soltanto i sorgenti verificati, non le ricette.
Il piano è SHA-256 del JSON canonico senza LF; i binding degli artefatti sono
SHA-256 dei byte effettivamente scritti, cioè JSON canonico con LF finale.

Dopo aver revisionato il piano, mantenendo quiescenti i writer della coppia:

```bash
read -r -p 'planSha256 B1 ricette appena revisionato: ' ouf_b1_plan_sha
[[ "$ouf_b1_plan_sha" =~ ^[0-9a-f]{64}$ ]]
bash scripts/deliver-semantic-provider-b1-recipes.sh --apply \
  --plan-sha256 "$ouf_b1_plan_sha" "${ouf_b1_args[@]}"
```

Apply riosserva gli input e gli inspect e ricompila. In ogni invocazione si
esegue l'intera osservazione/compilazione due volte, confrontando tutti i byte
canonici; ogni differenza ferma il lavoro. Un digest diverso dal piano approvato
produce HELD prima di scrivere. La root di output deve già esistere sotto
custodia root; il nome finale deve essere nuovo.

La directory viene riservata esclusivamente con `mkdir` 0700: per le directory
questa è la primitiva equivalente alla creazione esclusiva; `O_EXCL` si usa per
i file. Le due sottodirectory sono 0700; gli otto file e `result.json` sono
root:root 0600 con `O_EXCL`, no-follow, fsync e rilettura/hash. Si sincronizzano
anche le directory. Un errore dopo l'inizio della pubblicazione conserva
l'output parziale e non autorizza replay o sovrascrittura.

`result.json` usa `ouf.semantic-provider-b1-recipes.v1` e stato
`SEMANTIC_PROVIDER_B1_RECIPES_PREPARED`, con `planSha256`, CID/transazioni,
quattro binding `{path, sha256}` in `roles.<role>.recipe`, binding completi A2
e ricreazione, `secretValuesPrinted: false`, `startAuthorized: false`,
`acceptanceGranted: false`. La forma di recipe è validata nel manifest task-15
con dati sintetici. Questa ricevuta non è un manifest di accettazione firmato.

## Verifica e limiti

Comando CI Linux, Python 3.13, root per i controlli POSIX effettivi:

```bash
sudo python3 -I -B -m unittest discover -s tests -p test_semantic_provider_b1_recipes.py -v
bash -n scripts/deliver-semantic-provider-b1-recipes.sh
```

In locale è disponibile Python 3.12.12 di QGIS:
`C:/Program Files/QGIS 3.40.14/apps/Python312/python.exe`. La suite viene
eseguita con `-I -B` su Windows; gli adattamenti dei test per descriptor e
metadati Windows non sostituiscono la qualifica POSIX della CI. Solo le fixture
dei test convertono CRLF in LF per simulare la delivery; il controller non lo fa.
Non è stato avviato alcun workflow remoto in questo task: il verde CI deve
essere verificato dal reviewer dopo la pubblicazione autorizzata.

Le baseline reali vengono compilate integralmente nei test, con entrambi i
builder reali. Si verificano parità adapter, shell/tmpfs southbound, ordine Env,
digest con label r2, mismatch di richieste/inspect/A2, custodia, determinismo,
assenza di scritture in plan e apply obsoleto, hash dei file e forma task-15.

Qui si prova la compatibilità di forma delle ricette attraverso i contratti
qualificati in CI. La policy si dimostra soltanto al primo `create` del task OCI
in B2. Non sono provati confronto OCI target, enforcement kernel, accettazione
HUMAN, admission, switch, readiness, discovery o E2E. Non sono modificati A/A2,
P, compilatori, baseline, dati reali, budget, STATE, releases o evidence.
