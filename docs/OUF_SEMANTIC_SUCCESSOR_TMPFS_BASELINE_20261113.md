# B1 ricette, parte 1: baseline CI southbound con tmpfs

Task `sprint-01/task-19`, decisioni D-020 e D-021. Implementazione confinata a
`ouf-deploy`, branch `sprint-01/task-19-southbound-tmpfs-baseline`.
Questa consegna prepara il workflow; non attesta un esito CI o un nuovo stato VPS.
La baseline JSON è intenzionalmente **assente**, fino alla prima run verde.

## Perché una baseline distinta

Il southbound `34adce78…` del 2026-11-11 usa UID/GID `636:636`, rootfs
scrivibile, memoria 536870912 byte, swap limit uguale alla memoria e pids 128.
Rispetto alla ricetta storica aggiunge il tmpfs
`/run/ouf-southbound-runtime`, avvia `/bin/sh -c <script>` e monta un ulteriore
file RO per la chiave HMAC. La richiesta è costruita da
[`build_request`](../scripts/create-discovery-stopped-candidates-20261111.py).
Le opzioni richieste, mantenute letteralmente, sono:

```text
rw,noexec,nosuid,nodev,uid=636,gid=636,mode=0700,size=1m,noswap
```

La baseline storica southbound non contiene questo tmpfs. Quella adapter resta
il riferimento per l'adapter `85b5302f…`; questo task non la sostituisce.
Le ricette rimangono separate dalla ricostruzione del rootfs (D-020).

## Fixture e prova attesa

Il nuovo [fixture nativo](../tools/semantic_successor_recipes/test_southbound_tmpfs_baseline_native.py)
mantiene l'impianto del fixture storico senza modificarlo: Docker 29.8.1,
dockerd isolato, snapshotter containerd/overlayfs, rete bridge privata e
runtime di cattura. Il runtime salva il `config.json` OCI al `create` e termina
con 77 prima di chiamare runc; rifiuta anche `start` con 78. Entrambi i candidati
restano con PID 0 e `StartedAt` nullo. Nessuno script del candidato viene eseguito.

Prima della cattura si prova il mount con tutte le opzioni richieste in un
namespace mount privato. Il fixture controlla anche `noswap` in
`/proc/self/mounts`. Un kernel incompatibile o una probe fallita produce
`TMPFS_NOSWAP_KERNEL_REQUIRED`, senza skip o rimozione dell'opzione.

Il candidato 1 è creato con due bind RO, uno per configurazione sintetica e uno
per HMAC sintetico, `--entrypoint /bin/sh` e comando `-c <script breve>`.
Le destinazioni esercitano profondità diverse e l'intercalazione del tmpfs con
i bind metadata Docker. UID, rootfs, risorse, capability drop e
no-new-privileges sono quelli richiesti dal task.

Solo una copia dell'OCI1 riceve le sette sentinelle chiuse del compilatore e la
sentinella HOSTNAME nell'ambiente. L'OCI catturata rimane immutata: niente
risoluzione dei path rootfs o `/var/run`, ordinamento o riscrittura delle
opzioni. Anche il record tmpfs della copia resta integralmente quello prodotto
da Docker. Una differenza nei path grezzi fa fallire il confronto.

Il launch del candidato 2 nasce dalla configurazione dell'immagine e dai file
sorgente sintetici verificati, con path, contenuti e script diversi dal primo.
Il context usa CID2 e i parent del daemon già qualificati con il candidato 1;
non legge OCI2. Dopo `docker create` e prima di `docker start`, la policy viene
compilata, serializzata e fissata su file privato con fsync. OCI2 non esiste
ancora. Il fixture confronta poi **l'intera** `policy.expectedOci` con OCI2 e
controlla che i byte della policy fissata siano invariati.

Questo prova la compatibilità della forma sintetica e la compilazione prima
della generazione dell'OCI del secondo candidato. Non prova approvazione del
template target, autenticazione degli input/context, applicazione kernel dei
vincoli del candidato, contenuto rootfs, TLS/IAM, accettazione, E2E o avvio VPS.
Il mount di probe prova il supporto kernel di `noswap`, non l'enforcement di un
candidato che il runtime ha deliberatamente rifiutato.

## Builder e qualificazione

Il [builder nuovo](../tools/semantic_successor_recipes/build_role_frame_template_tmpfs.py)
riusa `build_role_template` e `compile_policy` storici, entrambi invariati.
La differenza è circoscritta alla posizione del tmpfs di ruolo: il builder
storico colloca tutti i mount non-bind fra i default prima dei bind; quello
nuovo colloca il solo tmpfs dichiarato insieme ai bind ordinati per profondità
e destinazione (`mountOrdering: depth-path`). I tmpfs di sistema, compresi
`/dev` e `/dev/shm`, rimangono nei default, con ordine e campi invariati.
Nessuna opzione OCI viene ricostruita dalla stringa della richiesta.

La necessità del nuovo modulo è una **condizione della run nativa**, ancora da
eseguire: sul candidato 1 si provano entrambi gli ordinamenti storici
`depth-path` e `depth-stable-user-first`. Devono differire dal template solo
nell'ordine dei mount; il builder nuovo deve riprodurre esattamente il template.
Se uno dei due storici basta, la run fallisce con `HISTORICAL_BUILDER_SUFFICES`:
il reviewer deve allora eliminare l'estensione e usare quello storico, prima
di qualificare la baseline. Nessuna scelta viene adattata osservando OCI2.

`launch.manifest.tmpfs` dichiara la stessa mappa della baseline. Una differenza
di destinazione o stringa di opzioni, compresa la rimozione di `noswap`, viene
rifiutata con `TMPFS_LAUNCH_DRIFT`. Una dichiarazione baseline mancante viene
rifiutata con `TMPFS_BASELINE_DECLARATION_REQUIRED`; un record OCI baseline
assente, duplicato o di tipo/sorgente diverso con `TMPFS_BASELINE_MOUNT_REQUIRED`.
La baseline è un input da autenticare e approvare separatamente: questo modulo
non certifica la corrispondenza fra una dichiarazione arbitraria e un template
arbitrario. Nella fixture tale corrispondenza proviene dalla richiesta Docker
nota e dalla cattura CI, non da una conversione inventata delle opzioni.

I [9 test unitari](../tests/test_semantic_successor_recipes.py) verificano ordine,
immutabilità degli input, conservazione integrale del tmpfs/default, compilazione
con più bind, rifiuto delle differenze e mantenimento dei guard storici su
rootfs, utente e bind RO. Le modifiche sintetiche dei test puri non sono una
baseline esportabile.

## Workflow e acquisizione della baseline

Il [workflow](../.github/workflows/semantic-successor-recipes.yml) risponde a
`pull_request` sui nuovi file e a `workflow_dispatch`. Ha job distinti `unit` e
`native`. Usa lo stesso download statico Docker 29.8.1 e il medesimo SHA-256
dell'archivio del workflow storico:
`d8db66739d2e28d4933786d73e918d9be643a67fbd835db1bf740d650a259e70`.
Non richiede il checkout del repository Semantic Registry: il confronto esatto
usa soltanto i due moduli puri già presenti in questo repository.

Il workflow storico usa tag `actions/checkout@v4` e
`actions/upload-artifact@v4`, non SHA delle azioni. Il nuovo usa le stesse
azioni v4, fissate agli SHA già presenti nei workflow di questo repository:
checkout `11bd71901bbe5b1630ceea73d27597364c9af683`, upload-artifact
`ea165f8d65b6e75b540449e92b4886f43607fa02`. Nessuna consultazione esterna è stata
eseguita per risolvere i tag.

Claude deve acquisire la baseline soltanto dopo review e prima run verde di
**entrambi** i job, associata al commit revisionato:

1. Leggere nel log nativo `SOUTHBOUND_TMPFS_NATIVE=PASS`, la scelta del builder
   e `CI_FRAME_BASELINE_EXPORT={"file": ..., "sha256": ...}`. Conservare run ID,
   commit della run e digest esatto. Nessun digest viene anticipato qui.
2. Scaricare l'artifact `frame-baseline-containerd-overlayfs-southbound-tmpfs`
   della stessa run; retention 30 giorni. Il file interno è
   `containerd-overlayfs-southbound-tmpfs.json`.
3. Calcolare SHA-256 sui byte del file scaricato e confrontarlo con il campo
   `sha256` stampato da `CI_FRAME_BASELINE_EXPORT=`. Controllare schema
   `ouf.semantic-ci-engine-frame-baseline.v1`, ruolo southbound, versione Engine,
   `mountOrdering`, mappa `tmpfs` e flag `syntheticFixture: true`,
   `targetTemplateApproved: false`, `acceptanceGranted: false`,
   `startAuthorized: false`.
4. Copiare gli stessi byte in
   `tools/semantic_successor_recipes/containerd-overlayfs-southbound-tmpfs.json`.
   Non fare pretty-print, conversioni EOL o aggiunta di newline. Ricontrollare
   il digest sulla copia, poi Claude committa il file nel perimetro D-001.
   L'implementatore di questo task non esegue download, staging o commit.
5. La run successiva copia anche il JSON committato nel fixture isolato e lo
   confronta byte per byte con l'export appena generato. Un solo byte diverso
   produce `COMMITTED_BASELINE_BYTE_DRIFT`. Controllare il marker
   `CI_COMMITTED_BASELINE_BYTE_MATCH=true` prima di dichiarare riproducibilità
   fra run.

L'export usa `OUF_FRAME_COMPILER_EXPORT_DIRECTORY`; il nome non dipende dal
runner. I path delle sorgenti sintetiche sono fissi sotto
`/root/ouf-southbound-tmpfs-native`, creato esclusivamente se assente. CID,
hostname e path dinamici sono sostituiti solo negli slot del template; i dati
Engine restanti rimangono grezzi. Un cambio reale di immagine, kernel o Engine
che cambi il documento deve fallire, non aggiornare automaticamente il JSON.

## Stato di verifica e task successivo

Controllati localmente branch, HEAD, working tree e sorgenti storici. I sei
file nuovi superano il controllo whitespace; gli script shell del workflow
superano `bash -n` e tutte le azioni sono fissate a SHA. `git diff --exit-code`
conferma l'assenza di modifiche ai file tracciati. Il builder storico conserva
il digest Git/LF `64f71f1c1414a87fda7e98a4402bef2b12ff8c5a917766810412825cca54f00c`;
il compilatore conserva
`36ee627e524415002a98fede8d7e61ad22ae95b6fec6b6686c1e01d878be570d`.
I byte CRLF della working tree Windows sono anch'essi invariati.
Python
non è disponibile nel PATH Windows e WSL è inaccessibile: i test Python non
sono stati eseguiti qui. CI non avviata, nessun accesso VPS, servizi esterni o
segreti. Nessun file preesistente viene modificato, compresi STATE e registro
funzionale, secondo il perimetro esplicito di task-19. La qualifica nativa e il
commit della baseline rimangono affidati a Claude come sopra.

Il task successivo costruirà il controller ricette sul VPS: ricostruzione
della richiesta di creazione e verifica contro il piano `52cfc4fb…`, launch
con hash delle sorgenti **inclusa la chiave HMAC** (D-021), context dei nuovi
CID e compilazione della policy. Dovrà autenticare input e baseline, mantenere
distinti ricetta e [lavoro B1 sul rootfs](OUF_SEMANTIC_PROVIDER_B1_ROOTFS_20261113.md),
e non ricavare la policy dall'OCI target da controllare. Questa baseline
sintetica non conferisce alcun consenso o autorizzazione di avvio.
