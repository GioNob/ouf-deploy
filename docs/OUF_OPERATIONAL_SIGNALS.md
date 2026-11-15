# Produttori dei segnali operativi — R-008, R-009

Decisione D-039: i segnali approvati dall'umano vengono proiettati nei due
contratti del collector gateway (task-47). Questi programmi producono file;
non avviano servizi R3, non rinnovano fiducia e non generano autorizzazioni.
Questo task non attesta alcuna installazione o osservazione sul VPS.

## Custodia e pubblicazione

I percorsi predefiniti sono `/var/lib/ouf-semantic-provider-health/status.json`
e `/var/lib/ouf-trust-windows/status.json`. Il collector legge rispettivamente
`ouf.semantic-provider-r3-health.v1` e `ouf.trust-window-status.v1`.
La serializzazione è JSON ASCII canonico: chiavi ordinate, separatori compatti,
nessun newline né valore non finito, massimo 16 KiB.

Entrambi usano la stessa pubblicazione atomica: temporaneo nella directory
di destinazione, custodia root:root 0600 verificata sul descrittore, scrittura,
flush/fsync del file, rename con sostituzione, fsync della directory. In caso
di errore il temporaneo viene rimosso; dopo un rename riuscito ma fsync fallito
il nuovo file può già essere visibile, ma la persistenza non è attestata.
La directory deve già esistere con antenati fidati, senza symlink; le unità
la creano con `StateDirectory`, modalità 0700. Non vengono create directory
dei sistemi osservati, né modificati permessi o file di ingresso.
L'esecuzione installata richiede Linux e root:root; gli entrypoint impediscono
la scrittura di bytecode. Non utilizzare credenziali o chiavi private.

## Salute R3

Entrypoint: `scripts/semantic-provider-r3-health.py`, da eseguire con Python
`-I -B`. Accetta gli stessi binding di `operate --plan`:

```text
--plan
--install-root PATH --wrapper PATH --wrapper-sha256 HEX64
--docker PATH --docker-sha256 HEX64 --docker-socket unix:///PATH
--systemctl PATH --systemctl-sha256 HEX64
--nft PATH --nft-sha256 HEX64
--timeout-seconds 180
--status-path /var/lib/ouf-semantic-provider-health/status.json
```

`--plan` è facoltativo e serve solo alla compatibilità degli argomenti.
`--action`, `--role`, `--apply`, `--plan-sha256` e `--output-directory`
non sono accettati. I binding nft vengono validati sintatticamente per
compatibilità con il piano; nft non viene letto, caricato né eseguito.
Il produttore usa solo Docker `inspect` e systemctl `show`, con gli stessi
path/hash/socket e l'ambiente chiuso di `operate`.
La destinazione deve essere esterna alla root R3 e diversa dagli eseguibili.

Il lettore riprende la selezione del runtime di `operate.observe`: wrapper
vincolato per hash, root/versione selezionata dal wrapper, runtime installato
verificato contro il sorgente consegnato, configurazione e closure verificate
dai loader installati. Riusa `terminal_binding`, `broker_denials`,
`docker_fields` e `service_active` senza cambiare R3/v2. I comandi mantengono
gli stessi controlli di hash prima/dopo, ambiente e binding di `operate`,
ma catturano stdout in memoria anziché nel suo file temporaneo.
Non invoca direttamente `observe`, che comprende una lettura nft e il
controllo della directory di output.

La testa viene autenticata con `auth.head` e il modulo mandates installati e
vincolati per hash. `runtime.authorization_head` non è adatto: rifiuta STOP
anche quando autenticato. Il produttore riporta OPERATE o STOP dalla catena
autenticata; se non riesce, riporta UNPROVEN/sequence null e un `readError`.
Il validatore di firma installato usa normalmente file temporanei per
OpenSSL. Un sottotipo locale ne sostituisce esclusivamente il trasporto:
versione/hash/budget e verifica Ed25519 con lo stesso OpenSSL restano
obbligatori; chiave pubblica DER, firma e frame passano tramite memfd anonimi
sigillati e `/proc/self/fd`, senza file temporanei sul filesystem. Il modulo
installato non viene modificato e non esiste fallback su disco. Il kernel
deve supportare memfd e sealing; altrimenti la lettura resta non provata.
Con STOP, l'eventuale epoca ancora viva conserva il riferimento alla precedente
autorizzazione OPERATE autenticata nella stessa catena. I legami storici delle
epoche terminali restano quelli del lettore originale.

Puntatori, journal, supervisore e coordinatore vengono letti senza lock e
ricontrollati per contenuto e identità, incluse sostituzioni con byte uguali.
Si ricontrollano anche epoche e testa alla fine della lettura. Un'instabilità
riconosciuta ripete l'intera lettura una sola volta: se persiste, si pubblica
uno stato vuoto con `readError` pubblico, senza mescolare letture incompatibili.
Un altro errore conserva solo i campi già verificati in quel tentativo.
Il programma non acquisisce né lock comune né `operation.lock`.

L'output seleziona esclusivamente i campi dello schema A: nessun CID, IP, MAC,
PID, boot ID, hash di configurazione, path o blocco `cohort`. Dei dinieghi
validati conserva solo mode/reason/at dell'epoca corrente: massimo quattro,
i più recenti in ordine cronologico (ordinamento deterministico a parità di
istante). I diagnostici invalidi e le epoche precedenti non diventano dinieghi
correnti. `unitActive` richiede ActiveState=active e SubState=running; il valore
false con un errore di lettura non costituisce prova di arresto. `updatedAt`
è il timestamp del file del supervisore, distinto da `checkedAt`.

Exit 0 quando lo stato è scritto, anche con `readError`; exit 1 quando non è
possibile pubblicarlo in modo autorizzato e durevole. Stdout contiene solo
`R3_HEALTH_STATUS_WRITTEN` o `R3_HEALTH_STATUS_WRITE_FAILED`; nessun traceback.

## Finestre di fiducia

Entrypoint: `scripts/trust-window-status.py`, Python `-I -B`:

```text
--inventory /etc/ouf/operational-signals/trust-inventory.json
--inventory-sha256 HEX64
--status-path /var/lib/ouf-trust-windows/status.json
```

L'inventario deve avere esattamente schema `ouf.trust-window-inventory.v1`
e `windows`. Ogni elemento ha esattamente ref, policyPath, policySha256 e
liveConsumers. Esempio strutturale (sostituire l'hash prima dell'uso):

```json
{"schema":"ouf.trust-window-inventory.v1","windows":[{"ref":"b1b2","policyPath":"/etc/ouf/trust/b1b2.json","policySha256":"HEX64","liveConsumers":[]}]}
```

Inventario e policy sono letti con `semantic_authority_mandates.mandates.private_bytes`:
file root:root 0600, singolo hard link, nessun symlink, antenati fidati,
dimensione massima 64 KiB, identità stabile durante la lettura e hash SHA-256
esatto. Slug `[a-z0-9-]{1,64}`; massimo 16 finestre con ref distinti e 16
consumatori distinti per finestra. Le liste vuote sono ammesse e conservate.
Finestre e consumatori sono ordinati per rendere stabile l'output.

La policy viene passata integralmente a **`mandates.anchor`**, che riconosce
le ancore `ouf.semantic-deployment-trust-policy.v1` e
`ouf.semantic-provider-b1b2-trust-policy.v1` e ne valida esattamente i campi,
le identità, i ruoli e le finestre. Il campo usato è **`keys[].expiresAt`**:
la scadenza pubblicata è il minimo di tutti i mandati dei ruoli dichiarati
nella policy, anche se scaduti o revocati. Non vengono eliminati i mandati
scaduti per spostare artificialmente la scadenza. Non sono supportati alias
arbitrari `notAfter` o policy sconosciute.

L'inventario non ha un binding al ledger dei rinnovi: rappresenta le finestre
della policy vincolata (generazione zero nella terminologia mandates), non
una vista del mandato rinnovato esternamente. Per una diversa policy occorre
aggiornare esplicitamente policySha256 e hash dell'inventario; nessuna ricerca
automatica di ledger, autorità o policy alternativa. I consumatori sono quelli
dichiarati dall'inventario approvato, non una discovery live di processi.

Un hash diverso, un file illeggibile o una policy non valida interrompono la
produzione prima della scrittura: exit 1 e solo un codice pubblico su stdout
(ad esempio `TRUST_WINDOW_HASH_MISMATCH`, oppure il codice del validatore).
Il file esistente resta intatto; il produttore non cancella lo stato per
simulare `silent`. Il collector può rilevare assenza o anzianità dello stato.
Successo: exit 0 e `TRUST_WINDOW_STATUS_WRITTEN`.

## Unità e qualificazione

Le unità consegnate in `ops/systemd/` sono template di installazione, non
installate da questo task. Usano `/opt/ouf-deploy` come root del codice e
gli EnvironmentFile root-custoditi sotto `/etc/ouf/operational-signals/`:

- `r3-health.env`: R3_INSTALL_ROOT, R3_WRAPPER, R3_WRAPPER_SHA256, R3_DOCKER,
  R3_DOCKER_SHA256, R3_DOCKER_SOCKET, R3_SYSTEMCTL, R3_SYSTEMCTL_SHA256,
  R3_NFT, R3_NFT_SHA256, tutti binding pubblici espliciti.
- `trust-windows.env`: TRUST_INVENTORY e TRUST_INVENTORY_SHA256.

Adeguare la root del codice nelle unità se la consegna usa un percorso diverso.
`ProtectSystem=strict` mantiene in sola lettura anche installazioni R3 fuori
da `/etc/ouf`; `ReadOnlyPaths` esplicita il codice, `/etc/ouf` e il socket
Docker standard `/run/docker.sock` (un altro socket richiede il binding
corrispondente). Il socket permette richieste: è il codice a limitare Docker
a inspect. L'unico `ReadWritePaths` è la directory del proprio stato.
Entrambe sono oneshot root, PrivateTmp/NoNewPrivileges; R3 scatta ogni cinque
minuti, le finestre ogni giorno. Nessuna dipendenza dall'attivazione del
supervisore che impedisca di osservarlo quando è inattivo.

La CI `operational-signals.yml` esegue test portabili, custodia Linux root,
non regressione portabile operate/upgrade e il gate `OUF_R3_HEALTH_NATIVE=1`.
Quest'ultimo riusa il fixture nativo di operate: runtime/wrapper/broker reali,
Engine e supervisore simulati, namespace isolati; verifica lo stato dopo start
e stop, file canonico 0600 e lettura con lock comune e lock delle epoche
mantenuti esclusivi. Non prova un Engine Docker o systemd di produzione.
I test portabili usano fake espliciti dei confini nativi; la policy deriva
dal fixture esistente `tests/test_semantic_b1b2_authority.py:policy`, passando
dal validatore reale. I test nativi non vengono eseguiti in locale Windows.
