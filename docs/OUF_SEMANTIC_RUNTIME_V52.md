# Runtime OCI governato v5.2 — epoche e autorizzazione durevole

Implementazione del task-39, R3 (D-033/D-034), secondo §13.4 del design B2.
Il modulo nuovo è `tools/semantic_runtime_v52/semantic_provider_docker_runtime_v52.py`.
Non installa il wrapper OCI, non modifica Docker, non firma e non legge chiavi private.
Il v5.1 e le librerie fissate per hash restano invariati.

## Configurazione e custodia

Schema chiuso `ouf.semantic-docker-runtime-adapter.v5.2`, JSON canonico ASCII
(chiavi ordinate, separatori `,` e `:`, nessun newline). File root:root 0600,
regolare, senza symlink o hardlink; antenati root non scrivibili da gruppo/altri.
L'invocazione richiede root:root e Python `-I -B`.

| Campi | Contratto |
| --- | --- |
| `schema`, `sourceHash` | Schema e SHA-256 dei byte del runtime stesso |
| `runtimePath`, `runtimeSha256`, `pythonPath`, `pythonSha256` | Eseguibili assoluti, root e verificati per hash |
| `registryRoot`, `runtimeStateRoot` | Registro persistente e parent esclusivo dei root runc ammessi |
| `opensslBinding` | `{path, sha256, version}` |
| `candidates` | Esattamente due CID, ciascuno `{role, bundleParents}`; ruoli distinti `adapter` e `southbound` |
| `admissionPath`, `admissionSha256` | Entrypoint broker v2 |
| `admissionConfigurations` | Esattamente i due CID, ciascuno `{path, sha256}` della configurazione stabile del broker |
| `driverPath`, `driverSha256` | Entrypoint hook v2/v7 |
| `operation` | `{authorizationRoot, anchorBinding, mandateRoot, mandatesModule, installationRef, entityRef, issuerRef}` |
| `authorizationModule`, `epochsModule` | Binding espliciti `{path, sha256}` dei due moduli di lettura |
| `leaseQuiesce` | `{entrypoint: {path, sha256}, configuration: {path, sha256}}` del supervisore |
| `limits` | Esattamente `{"maxEpochsPerHour":6}` |

`anchorBinding` e `mandatesModule` sono binding `{path, sha256}`. Nessun campo
di armatura è ammesso. `verify_files` controlla tutti i binding e gli eseguibili;
gli input vengono ricontrollati attorno alle chiamate alla catena di ammissione.

`authorization`, `epochs` e il modulo dei mandati sono compilati dai byte
verificati. L'import storico `authorization` di `epochs` viene risolto
temporaneamente alla sola copia verificata, senza cambiare `sys.path`.
Per il grant si riusa il bootstrap fissato del broker v2: controlla l'intera
chiusura `sourceHashes` della configurazione stabile prima di eseguirne i byte,
incluso `driver_v7.validate`. I binding espliciti di authorization/epochs e
dell'hook devono coincidere con quella chiusura. Il grant deve avere lo stesso
`sourceRoot`/`sourceHashes` e la stessa configurazione di autorità.

## Create, start e chiusura

L'installatore deve già predisporre `registryRoot` e `<cid>/epochs` 0700,
e `<cid>/operation.lock` 0600. Il runtime non crea candidati né lock mancanti.
Sotto il lock del CID legge `epochs.current` e verifica `authorization.head`:
testa unica `OPERATE`, hash della configurazione runtime esatta, CID/ruolo e
hash della configurazione stabile del broker. Una revoca o una catena invalida
nega l'operazione con il codice pubblico della verifica.

Su `create`, una precedente epoca viva dello stesso boot dà `EPOCH_STILL_OPEN`.
Un'epoca viva di altro boot viene chiusa `ABANDONED` soltanto dopo la prova
di assenza runc prevista dal v5.1, senza rollback. Le terminali sono
`DELETED`, `FAILED`, `ABANDONED`. Il limite conta tutti i journal con
`openedAt > now-3600`; sei aperture danno `EPOCH_RATE_EXCEEDED`.

Prima di ogni apertura viene eseguito esattamente:

```text
<python> -I -B <supervisor> --configuration <cfg> --configuration-sha256 <sha> --quiesce-only
```

I binding sono verificati prima e dopo, anche in caso di errore del figlio.
Serve uscita 0; altrimenti `LEASE_QUIESCENCE_UNPROVEN`, senza nuova epoca.
La testa e il puntatore vengono ricontrollati dopo la revoca.

L'apertura crea esclusivamente `epochs/<e+1>` 0700 e `adapter.json` 0600,
stato `OPENING`, boot/hash/testa/tempo e campi operativi null. Il puntatore
canonico `current` contiene `{epoch,journalSha256}`. Ogni transizione verifica
sia journal sia puntatore attesi, scrive temporanei 0600, fsync, rename e fsync
delle directory. Journal e puntatore sono due file: un'interruzione fra i due
rename lascia una coppia incoerente che i lettori rifiutano. Nessuna riparazione
o ripetizione implicita; anche epoche orfane oltre il puntatore danno diniego.

La sequenza è `OPENING` → broker `authorize-create` → `PREPARING` → bundle
ombra nell'epoca → `CREATING` → runc create → broker `record-created` → `CREATED`.
Restano i controlli del v5.1 su bundle, rootfs, fasi hook, namespace di rete,
runtimeStateRoot e argomenti OCI. Lo stderr ereditato da runc create resta
disponibile al processo del container.

`start` richiede `CREATED` sul boot corrente e ricontrolla la testa esatta
dell'epoca. Esegue `cohort-ready`, acquisisce lo scheduling comune,
passa a `PREPARING`, invoca broker `prepare`, valida il grant con v7 e i
legami a epoca, testa e hash della configurazione **del broker**. L'hash
`configurationHash` del journal runtime resta invece quello della configurazione
**v5.2**. Dopo hook, `ADMITTED`, `STARTING` e start del driver, rilegge runc e
registra `STARTED` con `{pid,startTicks}` da `/proc`.

Tutte le chiamate al broker comprendono `--epoch <e>`. `authorize-create`
riceve su stdin JSON canonico `{id,bundleHash}`; `record-created`, `cohort-ready`
e `prepare` ricevono lo stato OCI. `cleanup` ha stdin chiuso. L'hook riceve
lo stato OCI; driver start e rollback hanno stdin chiuso. Tutti usano `-I -B`
e l'ambiente ridotto del v5.1, senza credenziali.

`delete` esegue `DELETING`, runc delete, `quiesce(config)` tramite lo stesso
supervisore `--quiesce-only` del create, rollback del driver, cleanup del
broker nell'epoca, poi `DELETED`. La revoca precede il rollback anche quando
l'altro ruolo è ancora vivo e il supervisore non ha ancora reagito al delete.
Se la quiescenza fallisce, l'epoca diventa `FAILED` con
`LEASE_QUIESCENCE_UNPROVEN`, senza rollback né cleanup. La verifica della
generazione morta nel driver resta invariata.
`state` e `kill` con epoca viva usano runc; `kill` non quiesce: il lease resta
legato alle epoche vive e il supervisore lo ritira.
Senza epoca o con epoca terminale, `state`/`delete` richiedono l'esatta prova
di assenza del v5.1. Un delete non preparato richiede recupero come nel v5.1.
Gli errori del percorso aperto diventano `FAILED` con codice pubblico,
con CAS best effort: se fallisce, nessun journal concorrente viene sovrascritto.
Non si concede un nuovo tentativo nella stessa epoca. I fallimenti non provocano
rollback automatici di generazioni potenzialmente vive.

## Prove e limiti

`tests/test_runtime_v52_epochs.py` include il gate `OUF_RUNTIME_V52_NATIVE=1`
(Linux root:root obbligatorio): firme effimere di fixture e OpenSSL reali,
processo reale per `startTicks`, runc/broker/hook/quiescenza finti con controllo
esatto di argv, stdin, fasi e ambiente. Copre due cicli sulla stessa autorità,
abbandono, epoca ancora aperta, limite orario, quiescenza fallita, STOP/revoca,
hash e ruoli divergenti, grant legacy o con binding errato, FAILED e CAS fallito.
I test portabili verificano il contratto v7, la redazione dei codici pubblici
e la normalizzazione degli errori di quiescenza con ricontrollo dei binding.
I nativi verificano anche l'ordine delete → quiescenza → rollback → cleanup,
il fallimento della quiescenza senza rollback/cleanup e due revoche per ciclo
(create e delete). Il caso R3 `test_real_wrapper_start_restart_stop` verifica
start, restart del solo adapter (epoca 1 `DELETED`, epoca 2 `STARTED`, tabelle
ricreate senza nuove firme), poi stop con entrambi `DELETED`, lease `QUIESCED`
e tabelle assenti. La sua verifica nativa è affidata alla CI Linux root;
l'esecuzione locale delle suite portabili non la attesta.

Il workflow `semantic-runtime-v52.yml` esegue i nativi e le regressioni v5.1,
authorization/epochs, supervisore e tutto `test_semantic_provider_admission_v2*.py`,
inclusa la fixture reale del task-38b. La nuova integrazione completa runtime →
broker/hook reali è facoltativa e non è attestata: l'ambiente locale è Windows,
WSL è negato (`E_ACCESSDENIED`) e la fixture 38b richiede Linux root e namespace/
mount. Nessuna modifica al pacchetto v2 è stata fatta per aggirare il limite.
Il comportamento reale Docker `unless-stopped`, il boot e l'installazione
restano fuori da questo task. Nessuna prova CI o VPS viene dichiarata eseguita
dal solo workflow.
