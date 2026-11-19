# Frame observer v2: tmpfs dichiarati nella policy firmata

Task sprint-01/task-50; D-022 acquisita, D-041 proposta per review.

## Motivazione e autorità

Il primo start v5 descritto dall'owner si ferma in `prepare` con
`CREATED_FRAME_OBSERVER_DENIED`: il reviewer v1 considera dichiarati solo i
bind di `manifest.mounts`. Il tmpfs southbound approvato è invece presente sia
in `manifest.tmpfs` sia nell'OCI completo firmato, prima del confronto rootfs.
Questo documento descrive il codice candidato; non attesta nuove prove VPS.

Il v2 estende solo `configured_profile` del modulo incorporato
`review_semantic_oci_policy`. Il confronto canonico esatto dell'intero bundle
con `expectedOci` resta il primo vincolo, prima delle verifiche semantiche.
Una dichiarazione tmpfs non consente di cambiare il bundle: destinazione,
tipo, sorgente e opzioni sono già fissati nell'OCI autenticato. Nessuna
enumerazione di mount osservati viene trasformata in autorità.

`frame-observer.py` v1, `CreatedFrameObserver`, schema, wrapper, protocollo di
invocazione, verifiche di custodia, generazione e output restano invariati.
Il modulo `observe_semantic_mount_view` è identico byte per byte: il tmpfs è
già incluso in `mandatory` e `allowed` attraverso i mount del bundle.

## Regola esatta

`manifest.tmpfs`, se presente, deve essere un dizionario destinazione → stringa
di opzioni Docker. Un dizionario vuoto o la sua assenza conserva il percorso
v1 dell'adapter. Per ogni voce il v2 richiede:

- una destinazione POSIX assoluta canonica, senza sovrapposizione, uguaglianza,
  antenati o discendenti rispetto ai bind dichiarati e al set `kernel` del v1;
- esattamente un mount nella destinazione, `type == source == 'tmpfs'`, senza
  campi `uidMappings` o `gidMappings`, nemmeno vuoti;
- opzioni come lista ordinata esattamente uguale a
  `['rprivate'] + dichiarazione.split(',')`, senza duplicati;
- `noexec`, `nosuid`, `nodev` obbligatori; `exec`, `suid`, `dev`, `shared`,
  `rshared`, `slave`, `rslave` vietati;
- una sola opzione per ciascuno di `size`, `uid`, `gid`, `mode`: UID/GID
  numerici positivi minori di 2³², mode ottale fino a `0777` senza bit `0077`;
- size intera positiva in byte oppure con suffisso binario `k`, `m`, `g`
  (anche maiuscolo), fino a 64 MiB inclusi; percentuali e frazioni sono negate.

Le regole di hardening si applicano sia alle opzioni dichiarate sia a quelle
del mount. Una destinazione in conflitto produce
`OCI_DECLARED_TMPFS_OVERLAP`; assenza, duplicazione, tipo/sorgente/mapping o
opzioni difformi producono `OCI_DECLARED_TMPFS_DRIFT`; un hardening insufficiente
produce `OCI_DECLARED_TMPFS_HARDENING_REQUIRED`. Dopo aver escluso drift di
forma/conteggio e overlap, l'hardening precede il confronto delle opzioni:
per esempio un `exec` aggiunto o una size oltre 64 MiB sono HARDENING anche
se divergono dalla dichiarazione. Un tmpfs aggiuntivo non dichiarato resta
`OCI_UNDECLARED_MOUNT_DENIED`. I codici appartengono al reviewer incorporato;
il processo conserva il solo diniego pubblico redatto del v1.

## Ordine Docker 29 e generazione ripetibile

La fonte locale verificata è il fixture
`tools/semantic_successor_recipes/containerd-overlayfs-southbound-tmpfs.json`,
Engine 29.8.1. Contiene la dichiarazione
`rw,noexec,nosuid,nodev,uid=636,gid=636,mode=0700,size=1m`
e il mount OCI:

```json
{"destination":"/run/ouf-southbound-runtime","type":"tmpfs","source":"tmpfs","options":["rprivate","rw","noexec","nosuid","nodev","uid=636","gid=636","mode=0700","size=1m"]}
```

Si mantiene quindi l'ordine esatto di questo profilo, senza normalizzazione a
insiemi. L'uguaglianza ordinata è verificata anche sul Docker reale nel job
`cohort-docker-29`. Non si deduce una garanzia universale per altri Engine:
un ordine diverso viene negato, non ammesso automaticamente.

Nel repository non è presente un generatore del v1: il workflow storico lo
confronta con il blob dell'owner. `build_frame_observer_v2.py` legge quel v1,
verifica hash dei moduli e schema, sostituisce solo il blocco della review
mount, ricalcola il relativo `SOURCE_HASHES` e produce il nuovo file sigillato.
Il comando `--check` verifica la riproducibilità senza scritture. L'output è LF
anche su checkout CRLF; i testi incorporati non modificati sono identici.

## Composizione e compatibilità

`SOURCE_MAP` e `SOURCE_INPUTS` conservano la chiusura storica; le nuove
`SOURCE_MAP_V6` e `SOURCE_INPUTS_V6` sostituiscono il solo blob observer. Da R3
v6 si accetta esclusivamente la nuova chiusura e si lega `frame-observer-v2.py`;
R3 1–5 mantengono la precedente. Il set `sourceHashes` del broker resta quello
originario: il suo validatore già autentica separatamente il binding observer,
quindi non richiede modifiche.

I lettori dell'issuer e dell'upgrade accettano esattamente una delle due
chiusure, prima delle letture dei blob. `compose` impone successivamente la
chiusura corretta per la versione; l'unione e i sorgenti estranei sono negati.
Il lettore dell'installazione iniziale v1 resta invariato. Nessun runbook VPS
o file di distribuzione storico è stato cambiato.

I fixture hash v1–3 presenti nel repository restano invariati e passano.
Un confronto locale con il composer originale a HEAD `ee65da685bf2532ae8d1694550af6fcc7990ed7e`
ha inoltre verificato l'identità dell'intero risultato per R3 1–5, usando gli
stessi input correnti. Non erano presenti fixture hash v4/v5 da aggiornare.

## Fixture nativo e verifiche

La coorte usa la composizione v6 come scheletro e copia il blob v2 reale nella
chiusura installata. Non rimane uno stub `FRAME`. Il Docker privato importa
solo un rootfs sintetico locale e crea entrambi i ruoli con utente `636:636`,
capabilities rimosse, no-new-privileges, rootfs readonly, memoria/swap 256 MiB,
pids 128, hostname e PATH espliciti. Entrambi hanno un bind readonly di file
su `/run/role.json`; solo southbound ha il tmpfs dichiarato.

Il fixture prepara sorgenti root:root `0644`, nlink 1, con hash e limite byte;
la custodia della policy root:root `0600` e parent `0700` è asserita. Startup,
manifest e sorgenti vengono costruiti dagli input del fixture, non ricopiati
dall'OCI. Il runtime di cattura rifiuta la prima create prima di runc: l'OCI
completo e gli hook catturati sono poi vincolati prima delle firme sintetiche.
Il reviewer reale controlla anche questa policy prima della firma.

I mountpoint sono già presenti nell'archivio rootfs sintetico, così la create
non richiede di correggere un sigillo dopo averlo osservato. Il percorso
runtime v5.2 → broker `prepare` → `CreatedFrameObserver` → evidenza vincolata
comprende il processo reale `runc create`, la vista `/proc` e il confronto del
sigillo rootfs. Il fixture richiede evidence e frame hash, identità del blob
observer e uguaglianza del sigillo autenticato nell'epoch STARTED.

`tests/test_frame_observer_v2.py` esegue il reviewer incorporato senza
inquinare `sys.modules`, copre i casi positivi/negativi, hash, schema, identità
degli altri moduli e wrapper, e lancia i processi v1/v2 per il diniego redatto.
Il successo del processo con root e `/proc` reali è nel gate
`OUF_R3_COHORT_NATIVE=1`, con Linux root:root obbligatorio e nessuno skip se il
gate è abilitato. I workflow R3 eseguono anche i nuovi test portabili.

Le prove native non sono state eseguite nella worktree Windows: attendono CI.
Non è attestata una nuova installazione, uno start VPS o un'accettazione E2E.
