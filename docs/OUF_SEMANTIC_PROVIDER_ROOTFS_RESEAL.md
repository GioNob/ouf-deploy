# D-040 — Risigillatura B1 dopo il create

Lo strumento `scripts/prepare-semantic-provider-b1-rootfs-v2.py` produce nuova
evidenza per i due successori già creati, ancora mai avviati secondo Docker.
Non esegue `create`, `start`, `stop`, `rm`, importazioni o firme. Non modifica
snapshot, ricette, accettazioni o librerie storiche. Le osservazioni VPS del
15 novembre fornite nel task motivano il controllo; non sono nuove osservazioni
eseguite durante questo sviluppo.

## Metodo e identità della vista

Si riutilizzano `checked_export`/`stopped_export_view` del v1, invariati. Un
`docker export` trattenuto mantiene montata la vista effettiva containerd,
inclusi lower e upper del container. Il tar non viene estratto o usato come
rootfs: viene drenato e scartato, con i limiti storici. Il container rimane
fermo. Questo evita di ricostruire la vista con `lowerdir=upper:lower`, che
potrebbe alterare i contatori di link delle directory rispetto al mount Docker.

Per ogni ruolo sono richiesti due documenti vincolati per percorso/hash:
`framePolicy` con `expectedOci` (la policy usata da R3) e la copia conservata
del `config.json` OCI prodotto da Docker. Devono coincidere integralmente.
Il profilo ammesso richiede esplicitamente:

```text
expectedOci.root.path = <dockerRoot>/rootfs/overlayfs/<containerId>
```

`NodeObservation.observe` storico legge precisamente `oci.root.path`: usa il
percorso assoluto direttamente, oppure lo risolve rispetto al bundle se relativo.
Questo strumento supporta soltanto il primo profilo Docker/containerd. Percorsi
relativi, `/proc/<pid>/root`, driver differenti, versioni diverse da Docker
29.8.1 o OCI divergenti producono un diniego, senza scegliere una vista alternativa.

Il v2 controlla `/proc/self/mountinfo`: il percorso OCI deve essere un unico
mount overlay senza submount. Registra lower ordinati, upper, work e opzioni
effettive, con i percorsi sotto lo snapshotter containerd del Docker root
vincolato. Non accetta un percorso upper fornito separatamente dall'operatore.

La lettura avviene su un bind del percorso OCI, rimontato `ro` e verificato
tramite mountinfo. Il bind conserva le stesse entry e lo stesso `st_nlink` del
mount originale. Il medesimo `rootfs_seal`, caricato con `load_sealer` dal closure
storico vincolato per hash, viene eseguito anche sul percorso OCI originale.
Entrambe le mappe complete di entry e i sigilli devono coincidere esattamente
(`NODE_ROOTFS_VIEW_MISMATCH` altrimenti). Nessun campo viene escluso dal sigillo
effettivo. L'assenza di submount impedisce di includere i contenuti privati dei
bind o dei tmpfs del namespace del container.

La vista indipendente dell'immagine è un overlay **in sola lettura**, con il
solo `offline/bundle/rootfs` già preparato dal v1 come lower. Comprende
l'applicazione offline del Docker init già attestata dal v1, senza il nuovo
upper del container. Non si rilanciano unpack o Docker init. Come nel v1,
`expected_root_mode` ricava il mode della radice dagli header dell'immagine:
il mode del wrapper del bundle umoci non è automaticamente il mode della
radice dello snapshot. Il report conserva il sigillo grezzo della vista
immagine e la policy indipendente del mode; non li riscrive con valori osservati.
Poiché il layout è conservato da un'esecuzione precedente, il v2 verifica
nuovamente SHA256 e custodia dei blob degli strati prima di interpretarne gli
header e dopo il confronto; i relativi path/hash sono nel report.

## Differenze ammesse e dinieghi

Il confronto usa le entry complete catturate dallo stesso codice storico che
le serializza per il sigillo. Non applica un filtro globale di directory o link.

- Ogni destinazione OCI assente nell'immagine deve comparire: file vuoto,
  SHA256 del vuoto, un solo link, root:root e 0600 se la sorgente bind è un
  file; directory root:root 0700 per bind di directory o tmpfs.
- Gli antenati assenti sono directory root:root 0700, contenenti soltanto gli
  altri punti/antenati dichiarati. Nessun xattr sulle nuove entry.
- Gli antenati già presenti possono essere copiati nell'upper conservando
  tipo, mode, uid, gid e xattr dell'immagine. Il numero di link della directory
  fisica deve essere `2 + sottodirectory immediate`. Nella vista overlay un
  antenato unito può avere `st_nlink=1`; altrimenti deve avere il numero fisico
  coerente con le sottodirectory. Questa regola vale solo per gli antenati
  individuati dalle destinazioni firmate. Il sigillo continua a includere il
  valore esatto osservato. mtime/ctime non sono campi del sigillo storico.
- Tutte le altre entry dell'immagine devono essere identiche.

Si legge anche l'upper fisico: un file d'immagine copiato nell'upper, anche se
identico, o un percorso nascosto dalla vista unita non viene accettato.
Whiteout e file speciali sono rifiutati dal sealer storico; symlink nuovi,
hardlink, xattr aggiunti, contenuti non vuoti e tipi/permessi/owner divergenti
sono rifiutati dal confronto. Le sorgenti bind sono osservate con `lstat`,
senza leggerne i contenuti e senza seguire symlink.

I principali codici sono `POST_CREATE_NONEMPTY_FILE`,
`POST_CREATE_OWNER_DENIED`, `POST_CREATE_MODE_DENIED`,
`POST_CREATE_UNDECLARED_PATH`, `POST_CREATE_COPYUP_METADATA_DRIFT`,
`POST_CREATE_IMAGE_METADATA_OR_CONTENT_DRIFT`, `POST_CREATE_XATTR_DENIED`,
`POST_CREATE_ENTRY_TYPE_DENIED`, `POST_CREATE_UPPER_UNDECLARED_PATH` e
`ROOTFS_SPECIAL_ENTRY_UNSUPPORTED`. Una mutazione durante le letture produce
un diniego; non si normalizza la differenza né si pubblica un risultato PREPARED.

## Input e uso

Prerequisiti: Linux root:root, Python isolato con bytecode disabilitato,
closure storico e risultato v1 conservati, binari Docker/mount/umount vincolati
per SHA256, socket Docker locale, nessuno scrittore concorrente. Il v2 non
autentica nuovamente una firma della frame policy: richiede gli hash espliciti
dei documenti della catena approvata, come input alla futura emissione.

Predisporre **prima** quattro directory vuote root:root 0700, distinte e fuori
dai percorsi source, risultato v1, Docker root e nuovo output. Il controller
non crea mountpoint durante il plan. Eseguire in un mount namespace privato
predisposto dall'operatore. I soli mount temporanei creati dal controller sono
l'overlay immagine `ro` e il bind reso `ro`; `mount -n` evita scritture in mtab.
L'export storico monta temporaneamente il rootfs tramite il daemon e lo
rilascia dopo l'osservazione: è una lettura con lifecycle di mount, non una
promessa di assenza di mount/letture nel daemon. Non viene reso read-only il
mount originale di Docker e non vengono toccati upper/work per ricostruirlo.

Distribuire lo script accanto al v1 e alle medesime librerie storiche, oppure
usarlo nel layout del repository. `--help` elenca tutti i binding obbligatori.
Forma dei comandi (i segnaposto devono essere sostituiti con input verificati):

```bash
python3 -I -B scripts/prepare-semantic-provider-b1-rootfs-v2.py --plan \
  --date 20261115 \
  --previous-result /percorso/v1/result.json --previous-result-sha256 HASH_V1 \
  --a-successors /percorso/a2/successors.json --a-successors-sha256 HASH_A2 \
  --source /percorso/cohort-source --source-manifest-sha256 HASH_SOURCE \
  --docker /binario/docker --docker-sha256 HASH_DOCKER \
  --mount /binario/mount --mount-sha256 HASH_MOUNT \
  --umount /binario/umount --umount-sha256 HASH_UMOUNT \
  --adapter-frame-policy /percorso/adapter-policy.json --adapter-frame-policy-sha256 HASH_AP \
  --adapter-oci-config /percorso/adapter-oci.json --adapter-oci-config-sha256 HASH_AO \
  --adapter-image-view /var/lib/reseal-views/adapter-image \
  --adapter-container-view /var/lib/reseal-views/adapter-container \
  --southbound-frame-policy /percorso/southbound-policy.json --southbound-frame-policy-sha256 HASH_SP \
  --southbound-oci-config /percorso/southbound-oci.json --southbound-oci-config-sha256 HASH_SO \
  --southbound-image-view /var/lib/reseal-views/southbound-image \
  --southbound-container-view /var/lib/reseal-views/southbound-container
```

Il plan non crea output, file temporanei, directory o configurazioni Docker.
Restituisce vecchio/nuovo sigillo per ruolo, differenze esaustive, binding dei
documenti, snapshot e binari, e hash di Config completo e stati dei container.
MacAddress e gli endpoint rimangono nel confronto esatto del v1.

L'apply usa gli stessi argomenti con `--apply --plan-sha256 HASH_PLAN` al posto
di `--plan`. Ricalcola il plan, crea esclusivamente:

```text
/var/lib/ouf-storage-migration/semantic-provider-b1-rootfs-<YYYYMMDD>-post-create/
    adapter-comparison.json
    southbound-comparison.json
    result.json
```

L'apply riesegue l'osservazione prima di scrivere le ricevute: due export nel
plan, quattro nell'apply, zero operazioni di lifecycle container in entrambi.
Directory 0700 e file 0600, creazione esclusiva senza overwrite. I parziali
rimangono; lo strumento non li cancella. Ogni esito indica
`doNotRerunApply: true`. Un errore dopo la creazione dell'output richiede la
riconciliazione dei parziali, non un rilancio o una data diversa per aggirarlo.

## Catena accettazione gen 4 e R3 v5

Il risultato conserva schema `ouf.semantic-provider-b1-rootfs-evidence.v1`
e stato `SEMANTIC_PROVIDER_B1_ROOTFS_EVIDENCE_PREPARED`.
`offlineImageReceipt` e `offlineDockerReceipt` conservano esattamente i binding
v1. `comparison` punta al nuovo report esaustivo; `effectiveSeal` è quello
effettivo post-create. `previousResult` mantiene il legame al predecessore.

Non servono modifiche a `issue-semantic-provider-acceptance-v51.py`: il test
portabile usa il vero `observe` dell'emettitore, le fixture A2/ricette/autorità
esistenti e il risultato del v2 con `generation=4`. Custodia nativa del ledger
e OpenSSL sono sostituiti solo nella fixture portabile; non si emette una firma.

La composizione R3 invariata accetta `version=5`, `sequence=5` e un
`supersedes` esplicito. Il test usa il nuovo risultato e un'accettazione gen 4
coerente; verifica il documento rootfs prodotto e il rifiuto di un sigillo
divergente nell'accettazione. Il generatore/runbook operativo resta fuori da
questo task: occorre passarvi i nuovi hash, senza riutilizzare l'accettazione
precedente né dichiarare readiness.

## Prove e limiti

Test portabili:

```bash
python3 -I -B -m unittest discover -s tests -p test_prepare_semantic_provider_b1_rootfs_v2.py -v
```

La fixture nativa è protetta da `OUF_B1_ROOTFS_V2_NATIVE=1`; se il gate è
attivo e mancano Linux root, isolamento o binari, fallisce anziché saltare.
Il processo figlio usa un mount namespace privato, directory temporanea in
`/var/lib`, daemon Docker dedicato con containerd overlayfs e Docker 29.8.1.
Importa un'immagine locale con sleep/librerie host e crea un container con
bind file e tmpfs verso destinazioni assenti. Il wrapper esegue davvero
`runc create`, poi il vero `NodeObservation.observe` sul bundle Docker e
infine elimina soltanto il task della fixture senza eseguire `runc start`.
I controlli transport/live-profile estranei al sigillo sono sintetici; rootfs,
generazione del PID, percorso OCI e namespace di rete sono osservati davvero.

Dopo la rimozione del task, l'export trattenuto rimonta il medesimo snapshot;
il confronto usa lower senza upper, upper fisico e bind read-only. Richiede
che il sigillo sia identico a quello restituito prima da `NodeObservation`.
Il marker di successo è `NODE_OBSERVE_POST_CREATE_EQUAL`. Le operazioni di
lifecycle di questa fixture non appartengono allo strumento consegnato.
Questa prova del kernel non sostituisce la verifica dei binding v1, esercitata
dal controller e dalla fixture portabile completa.

Il workflow B1 aggiunge questa qualifica con l'archivio Docker già fissato
dalla coorte R3, più regressioni B1/accettazione/R3. Il workflow non è stato
eseguito in questa sessione. Sul checkout Windows i test portabili del v2
passano; il test decisivo nativo resta da eseguire in CI. La suite v5.1 locale
ha inoltre un fallimento preesistente dei pin dovuto a CRLF: il blob Git e il
file normalizzato LF coincidono con il pin dell'emettitore. Nessun pin o
runbook è stato cambiato per aggirare questo controllo.
