# B1: nuove evidenze rootfs, 13 novembre 2026

Task sprint-01/task-18; D-011 punti 2 e 4, D-014, D-020. Questo documento
descrive codice da qualificare in CI e successivamente eseguire dall'operatore.
Non è una ricevuta VPS e non concede acceptance, lease o avvio.

## Contratto

`scripts/prepare-semantic-provider-b1-rootfs.py` richiede root:root,
`python3 -I -B`, umask 077 e tutti i path/hash dalla CLI, senza default.
Il launcher richiede Linux, sudo, curl e `/usr/bin/python3.13` con hash fissato.
Prima della pubblicazione Claude sostituisce `__PIN_COMMIT__` e
`__PIN_CONTROLLER_SHA256__`: il launcher non funziona con segnaposto residui.
Il commit deve contenere il controller e le quattro librerie; non è il commit
del launcher stesso, per evitare una dipendenza circolare del pin.

Il plan verifica i cinque eseguibili con `program`, la closure con
`load_sealer`, gli archivi root:root 0600/nlink 1 (massimo 512 MiB ciascuno),
il file A root:root 0600, l'Engine e i due candidati. Non esegue export,
unpack, mount, mkdir, spooling o scritture. Le letture Docker usano pipe
limitate e un path config ancora assente sotto l'output futuro, senza usare
la configurazione dell'operatore. Anche l'output deve essere ancora assente;
il padre deve esistere, essere root:root e non scrivibile da gruppo/altri.
Si rifiutano symlink e antenati non custoditi secondo le primitive storiche.

Il writer A produce `containers` nell'ordine `cutover.SUCCESSORS`, ossia
adapter, southbound. Il controller verifica esattamente questa coppia
ordinata di CID e immagini, senza ricavare un nuovo ruolo dai dati osservati.
CID uguali sono un errore CLI. Una divergenza da A produce
`A_SUCCESSOR_BINDING_MISMATCH`; un candidato diverso da Id/Image esatti,
created, PID 0, Running false e StartedAt zero produce
`NEVER_STARTED_EXACT_CANDIDATE_REQUIRED`.

Il piano pubblico contiene tutti i binding, la destinazione, le scritture,
gli hash delle configurazioni dei candidati e dell'inventario lifecycle.
Non espone Env, credenziali o contenuti dei mount. `planSha256` è SHA-256
del payload `plan` serializzato con `canonical`, senza timestamp generati.
L'apply ripete il preflight; un digest diverso produce
`PLAN_DIGEST_CHANGED` prima di qualsiasi scrittura. Una directory già
presente viene rifiutata anche se appartiene a un tentativo precedente.

La libreria `apply_docker_init` ammette soltanto il commit Engine completo
`464cd50c3d9e92877d56940ea160de6fca7bea23`. Non viene modificata: il
controller verifica questa compatibilità già nel plan. Versione e commit
rimangono argomenti CLI obbligatori; il prefisso di sette caratteri del commit
deve coincidere con il GitCommit server. Driver richiesto: overlayfs;
DockerRootDir deve coincidere con il path CLI. Tutti i confronti inspect
usano la stessa CLI e lo stesso ambiente, senza esclusioni MAC.

## Evidenze nuove e confronto

Gli archivi OCI storici rappresentano le stesse immagini dei nuovi CID e
sono input validi. I vecchi receipt, confronti e seal dei vecchi CID non sono
evidenze dei successori. Per D-020 si ricostruiscono da zero entrambi gli
offline, senza copiare ricevute né trasformare un seal storico in aspettativa.
La closure storica è codice verificato, riusato tramite `load_sealer`.

L'apply crea esclusivamente una nuova directory 0700 e, per ogni ruolo,
`<ruolo>/offline` 0700 inizialmente vuota. `prepare` verifica l'archivio,
ricostruisce il layout e spacchetta con umoci; `apply_docker_init` applica
il tool Engine alla copia offline. I receipt hanno permessi 0600 e vengono
scritti con `write_once`, come i confronti e `result.json`.

Per ruolo si costruisce una vista overlay temporanea indipendente con
`expected_overlay`. Durante **un solo** `stopped_export_view` si ottengono
il seal effettivo e gli entry completi dal path
`<docker-root>/rootfs/overlayfs/<nuovo-cid>`. Docker gestisce il mount durante
l'export: il controller tiene aperta la pipe, osserva direttamente i metadata
del filesystem montato e infine drena/scarta il tar. Non estrae quel tar come
aspettativa indipendente. L'export non avvia il container, non esegue il suo
entrypoint e non include i contenuti dei bind/volume esterni come rootfs.
Il contesto storico attende il rilascio del mount, anche sui percorsi di errore.

I medesimi entry effettivi vengono confrontati sia con la vista strict sia
con l'immagine offline e la policy di root derivata con `expected_root_mode`.
`compare_image_entries` è invariato: tratta i contatori di link delle directory
e il modo root secondo la policy storica, conserva i seal v1 e continua a
confrontare i link dei file. `strictSealsMatch` viene registrato, ma il criterio
di successo è `imageEquivalence.equivalent is true` per entrambi i ruoli.
`classify` registra le differenze nel confronto; un fallimento conserva quel
record e produce `TARGET_ROOTFS_DIFFERS_FROM_INDEPENDENT_EXPECTATION`, senza
`result.json` di successo.

Prima e dopo **ciascun export** si confrontano le configurazioni complete di
entrambi i candidati, senza normalizzare Config.MacAddress o gli endpoint.
Prima e dopo l'apply si confrontano gli stati lifecycle di tutti i container;
come nel codice storico sono esclusi soltanto i tick dei probe Health, che
non sono cambiamenti lifecycle. Le verifiche finali avvengono anche quando
una fase fallisce. Cambiamenti producono
`STOPPED_CANDIDATE_CONFIGURATION_CHANGED` oppure
`EXISTING_CONTAINER_STATES_CHANGED`. Sono osservazioni ai confini delle
operazioni: non impediscono modifiche concorrenti da un altro operatore.
È necessario mantenere la coppia quiescente durante l'esecuzione.

Output principale:

```text
<output>/docker-config/
<output>/adapter/offline/{layout/,bundle/,expected-rootfs.json,
                         docker-init-claim.json,expected-docker-rootfs.json}
<output>/southbound/offline/{layout/,bundle/,expected-rootfs.json,
                            docker-init-claim.json,expected-docker-rootfs.json}
<output>/{adapter,southbound}/strict/{view,upper,work}/
<output>/adapter-comparison.json
<output>/southbound-comparison.json
<output>/result.json
```

`result.json`, schema `ouf.semantic-provider-b1-rootfs-evidence.v1`, lega il
plan, A, closure ed Engine. Ogni `roles.<r>` contiene CID, immagine, i binding
assoluti `{path,sha256}` dei tre receipt/confronti e `effectiveSeal`, identico
ad `actualSeal`, inclusi schema `ouf.semantic-rootfs-seal.v1`, sha256, entries,
bytes. Il futuro controller B1 copia questi quattro campi in
`manifest.roles.<r>.rootfs`; CID e immagine rimangono nel ruolo del manifest.
Non copia l'intera riga result nel manifest, che ha un contratto chiuso diverso.

Lo stato finale è `SEMANTIC_PROVIDER_B1_ROOTFS_EVIDENCE_PREPARED`.
I contatori dichiarano 2 export, 0 lifecycle, 0 start, 0 letture di chiavi
private e 0 firme. `acceptanceGranted` e `startAuthorized` rimangono false.
Questo non firma B1, non valida la ricetta applicativa, non autorizza avvii,
non attiva provider e non prova discovery/E2E.

## Sequenza operatore

Esempio per i valori comunicati del VPS, da eseguire solo dopo review e CI.
Non eseguito durante questo task. `A_SUCCESSORS_SHA256` non è stato fornito
nei metadati: deve provenire dalla ricevuta A verificata, non essere inventato
né ricalcolato silenziosamente come propria aspettativa. `PLAN_SHA256` è
copiato dall'output del plan letto e approvato dall'umano. L'output name sotto
è una nuova destinazione proposta: la sua assenza è verificata dal plan.

Il launcher scarica codice e crea una directory privata di **consegna** anche
quando inoltra `--plan`. La garanzia di nessuna scrittura riguarda il controller
`--plan`, non il download. Il launcher stampa il path di consegna e lo conserva;
l'operatore può riusare quel controller verificato per entrambe le invocazioni.

```bash
# Dopo aver predisposto il launcher con entrambi i pin sostituiti:
# impostare l'hash indipendente dalla ricevuta A, senza un default.
: "${A_SUCCESSORS_SHA256:?impostare SHA-256 verificato del successors.json di A}"
archive_root=/etc/ouf/deploy-snapshots/semantic-provider-v2-stopped-create-a2kbzv6l/images
offline_code=/etc/ouf/deploy-snapshots/semantic-provider-v2-offline-rootfs-s3BU0nDX
args=(
  --a-successors /var/lib/ouf-storage-migration/semantic-provider-preparation-a-20261111/successors.json
  --a-successors-sha256 "$A_SUCCESSORS_SHA256"
  --adapter-container-id 85b5302f6dbc3e9a24ace904b8d8a2d43bc5185e340c1bfe5474c723a6b640ef
  --adapter-image-id sha256:277dcefd4744c244f4f6f23f8969f3d0acd64369e2ff1bd67594955c4ca7fbbc
  --adapter-archive "$archive_root/adapter.image.tar.gz"
  --adapter-archive-sha256 8301649b854a01d0306fabb14a5f93dd08eb4b1df98c2af356c0c84773821207
  --adapter-config-digest sha256:62e066bd021f386291f5de21ce0e1f9e67904a74b4146326070c7784493ad320
  --southbound-container-id 34adce783cba238c1954eb33e39c37a641ea4f0db212531951a2fd2b86290c52
  --southbound-image-id sha256:c15541037a08276e36715a3c3798c2d07fe6faabf5547d3885a66cd10575e366
  --southbound-archive "$archive_root/southbound.image.tar.gz"
  --southbound-archive-sha256 1588c2391f9da45f300d16dd191cfe483dff83f81ed9424baec40201e64d7641
  --southbound-config-digest sha256:d4c47bbeca75d94e2231e17ca14552885b7b339a5f33dbace411e275c79ded04
  --umoci "$offline_code/umoci"
  --umoci-sha256 b21ac9b656fa76035db6ac4793facfd26982165d96f730bae9606d6f0929932e
  --docker-init-tool "$offline_code/docker-initlayer"
  --docker-init-sha256 be8b8804a0d63990d02cc4b44008c22397778b4fecf16077397103fe8a64cb22
  --docker /usr/bin/docker
  --docker-sha256 7f5b38163f9c5367f4b42d905c0505877eafa4c20abe49430c85a770aefacf40
  --mount /usr/bin/mount
  --mount-sha256 2f36342bd2fef42343c4fa4a2a396a7f56c7c8f4ddcbd31c43205c62e152e6d4
  --umount /usr/bin/umount
  --umount-sha256 3f3046ef1cdc5134eb0b7ac586c6fea3bcea22aa6614830a14e274f3905b6cd5
  --source "$offline_code/source"
  --source-manifest-sha256 fb797f12eb838bfdc5eae7cd28617f6d7d17531968d710735df248354496e250
  --engine-version 29.8.1
  --engine-commit 464cd50c3d9e92877d56940ea160de6fca7bea23
  --docker-socket unix:///var/run/docker.sock
  --docker-root /var/lib/docker
  --output-root /var/lib/ouf-storage-migration
  --output-name semantic-provider-b1-rootfs-20261113
)
bash scripts/deliver-semantic-provider-b1-rootfs.sh --plan "${args[@]}"

# Leggere piano e planSha256. Impostare il digest esatto prima dell'apply:
: "${PLAN_SHA256:?impostare planSha256 del piano verificato}"
bash scripts/deliver-semantic-provider-b1-rootfs.sh \
  --apply --plan-sha256 "$PLAN_SHA256" "${args[@]}"
```

In alternativa, dopo la consegna, le due chiamate al solo controller sono:

```bash
: "${DELIVERY_DIRECTORY:?path root privato stampato dal launcher}"
sudo /usr/bin/python3.13 -I -B "$DELIVERY_DIRECTORY/prepare-semantic-provider-b1-rootfs.py" \
  --plan "${args[@]}"
sudo /usr/bin/python3.13 -I -B "$DELIVERY_DIRECTORY/prepare-semantic-provider-b1-rootfs.py" \
  --apply --plan-sha256 "$PLAN_SHA256" "${args[@]}"
```

## Spazio e recupero

Gli archivi già presenti occupano 224.665.042 byte (circa 214,3 MiB) complessivi;
non vengono duplicati come archivi compressi. Lo spazio nuovo comprende layout
OCI, rootfs spacchettati, init layer e directory overlay. La dimensione effettiva
spacchettata non è disponibile nei fatti comunicati: non si deduce dai MiB
compressi e non viene dichiarata misurata. Come pianificazione conservativa,
considerare fino a circa 48 GiB più overhead per due layout e due rootfs,
usando i budget storici di lettura da 16 GiB e seal da 8 GiB per ruolo.
Non è una misura del VPS, una quota riservata o un limite atomico di spazio
durante unpack. Verificare lo spazio disponibile prima dell'apply; l'export
viene drenato senza salvare il tar.

Nessun rollback o retry automatico. Un errore stampa `HELD`, motivo pubblico,
fase, directory, receipt già scritti e alberi parziali conservati. Un apply
interrotto non si rilancia sullo stesso output. Conservare e riesaminare
l'evidenza prima di proporre un output diverso. I contesti storici tentano il
rilascio dei mount; un fallimento di unmount rimane un errore, non un successo.

Il ripristino consiste nella **rimozione manuale della sola directory nuova**
dopo averne verificato il path assoluto e l'assenza di mount residui, conservando
prima i receipt necessari alla review. Non cancellare input A, archivi OCI,
closure storica, container o rootfs Docker. Anche la directory temporanea di
consegna è conservata e si rimuove manualmente dopo review. Nessun comando
di cancellazione viene eseguito da questi controller.

## Test e limiti

Comando previsto nel nuovo workflow `semantic-provider-b1-rootfs.yml`:

```bash
bash -n scripts/deliver-semantic-provider-b1-rootfs.sh
sudo -n env OUF_B1_ROOTFS_NATIVE=1 /usr/bin/python3 -I -B -m unittest discover \
  -s tests -p test_semantic_provider_b1_rootfs.py -v
```

La modalità native richiede Linux root:root e `-I -B`; se mancano fallisce
senza trasformare la qualifica in uno skip. Il fake Docker è un eseguibile
locale root 0700 verificato per hash, che ammette soltanto letture e usa
fixture sintetiche. Si verificano parsing, hash/custodia, engine, binding A,
candidati mai avviati, output assente, plan stabile e privo di scritture,
digest cambiato senza scritture e conservazione degli errori.

Per l'apply si iniettano unpack, Docker-init, mount ed export. Restano reali
closure/sealer, cattura entry, `classify`, `compare_image_entries`, lettura
della root policy da un layer sintetico, write-once, controlli e costruzione
risultato. Il test positivo costruisce un manifest con i binding prodotti e
lo passa a `build_acceptance` e `decode_manifest` del task-15; esercita strict
false/equivalent true. Le negative coprono differenze rootfs, mutazioni MAC e
stati container cambiati, senza risultato di successo. Nessun Docker reale
è richiesto e nessuna prova CI sostituisce un apply reale sul motore fissato.

Nell'ambiente Windows di implementazione Python non è disponibile nel PATH
e l'enumerazione WSL è negata. La suite non è stata eseguita localmente e la
CI non è stata avviata da questo task, che vieta push e servizi esterni.
Il verde CI e l'export reale dei nuovi CID rimangono da attestare separatamente.
