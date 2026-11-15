# Ammissione per epoca v2 — task-38a

La testa durevole `authorization.head()` sostituisce i tre documenti temporanei
della v1. Nessuna emissione avviene allo start. Una revoca, una testa STOP o
un hash diverso negano l'ammissione. Il cohort-draft resta invariato: tutti i
moduli v1 sono compilati solo dopo la verifica dei byte privati contro
`sourceHashes`. Anche `mandatesModule` viene compilato dai byte verificati.

```sh
python3 -I -B scripts/semantic-provider-deployment-broker-v2.py \
  --configuration /etc/ouf/admission/adapter.json --container-id <cid> \
  --epoch 1 --bundle /var/lib/ouf/registry/<cid>/epochs/1/bundle \
  --runtime-root /run/ouf/runtime/owned --mode authorize-create
```

La configurazione canonica `ouf.semantic-deployment-broker.v2` è stabile per
ruolo; lo sha256 dei byte esatti deve coincidere con
`admissionConfigurationSha256` della testa. Lo schema chiuso è in
`broker_v2.FIELDS`; `operation` contiene i cinque binding/percorsi della catena
durevole e `authorities` contiene installationRef, entityRef e issuerRef.
`epoch` e `epochRoot` sono esclusi dalla configurazione.
L'invocazione verifica il puntatore corrente con `epochs.current`, boot, hash
dell'autorizzazione e stato: OPENING, CREATING, CREATED, PREPARING, DELETING per
authorize-create, record-created, cohort-ready, prepare, cleanup rispettivamente.
Il runtime root deve coincidere col journal dopo authorize-create.

Nella directory privata dell'epoca, il broker crea `deployment.json` e
`broker-state.json` in STAGED con O_EXCL/0600. Una coppia preesistente viene
accettata solo in STAGED con identico binding; parziali e fasi successive non
sono ripresi. Le transizioni usano il CAS di `PrivateJournal` sotto il lock
comune già esistente. Una nuova esecuzione richiede un'epoca nuova.

I documenti legati sono JSON canonici: la policy contiene `expectedOci`, il
sigillo è `ouf.semantic-rootfs-seal.v1`, il trasporto contiene esattamente
`networkBindings`, `transport`, `tableName`. I loro hash devono coincidere con
la voce del ruolo. `creationFrameObserverBinding.configuration` è lo stesso
binding della policy. Il template stabile v1 viene letto solo come dati:
le dichiarazioni di trasporto devono coincidere col documento legato. La sua
vecchia transactionId non è un'autorità; per `live_profile` si deriva una
correlazione da CID, epoca e hash dell'autorizzazione.

`NodeObservation.observe` riusa generazione, hash OCI, sigillo rootfs, NIC e
osservazioni reciproche dei peer. `CreatedFrameObserver.observe` prova la
conformità del frame alla policy e restituisce l'hash osservato: non esiste un
hash atteso del frame vivo da inventare nella policy. La riautorizzazione
confronta questo hash e la generazione con `evidence.json`, rileggendo la testa
prima e dopo l'osservazione. Non applica finestre temporali della v1.
La dipendenza transitiva dell'osservatore usa soltanto gli helper puri `encoded`
e `program`, secondo la decisione del run 1.

`PreparerPort` è il punto di integrazione del task-38b. `prepare(request, state)`
riceve il contenuto sigillato di `preparer.json`, opera fuori dal lock del
broker, protegge il footprint, valida il proprio grant e scrive `driver.json`
nella stessa directory con O_EXCL/0600. Restituisce esattamente
`{binding, evidenceHash, driverHash}`. Il broker verifica binding, prova, byte
del driver e generazione, poi chiama `seal_driver_locked`. `cleanup(request)`
deve provare la rimozione del footprint prima di restituire. Il task-38a non
definisce il contenuto del grant v7: questa validazione appartiene alla porta.
Nella sola parte A la porta predefinita nega con `PREPARER_V2_UNAVAILABLE`; non esiste un selettore
di plugin in configurazione. Il test inietta una porta sintetica, che non
costituisce un grant utilizzabile dal runtime.

I test portabili si eseguono con unittest; quelli nativi richiedono Linux
root:root e `OUF_ADMISSION_V2_NATIVE=1`. Riutilizzano la fixture crittografica
reale del task-37, epoche reali e comandi runc/rete/osservatore sintetici:
nessun container, rete o servizio viene modificato. Il workflow aggiunge le
non regressioni di operation e lease supervisor sotto sudo. Questa prova non
attesta installazione, readiness applicativa o E2E.

## Parte B — preparer v2, driver v7, hook v2 (task-38b)

La porta predefinita del broker è ora `SubprocessPreparer`; `UnavailablePreparer`
resta disponibile per i test. La porta verifica i byte esatti di `preparer.json`,
invoca l'entrypoint di `sourceRoot` verificato con Python verificato, `-I -B`, stato OCI su
stdin e timeout condiviso, e accetta un solo oggetto canonico seguito da LF.
Per prepare l'esito è esattamente `{binding,evidenceHash,driverHash}`, per
cleanup `{state:"CLEANED"}`. Return code, dimensione, campi o binding diversi
negano l'operazione. Nessun selettore di plugin o nuovo parametro del broker.

Il grant canonico chiuso `ouf.semantic-preexec-driver.v7` mantiene i campi base
v6 e `peerBinding` quando il trasporto contiene peer dichiarati. I nuovi campi
di primo livello sono:

- `operationBinding`: esattamente authorizationSha256, epoch, containerId,
  configurationHash;
- `evidenceBinding`: path e sha256 di `evidence.json` dell'epoca;
- `consumptionJournal`: percorso del `deployment.json` della stessa epoca;
- `operation`: authorizationRoot, anchorBinding, mandateRoot, opensslBinding,
  mandatesModule, installationRef, entityRef, issuerRef. Sono gli input durevoli
  di `authorization.head`; clock e budget sono forniti dal processo;
- `creationFrameObserverBinding`: python, source e configuration vincolati.

`authorityBinding`, `authorityScope`, `consumptionBinding` e
`authenticationBinding` sono rifiutati, anche se gli altri campi sono corretti.
La validazione lega CID/epoca ai percorsi, al profilo v2 e alla transactionId
derivata con la stessa correlazione della parte A. I contratti nft, lease e
profilo restano verificati anche dai rispettivi componenti v1 invariati.

`preparer_v2.Worker` rilegge configurazione e template sigillati e carica i
moduli v1 dai byte privati verificati con `broker_v2.load`. Richiede il template
nativo completo: sei comandi nft/ip/nsenter/unshare/mount/umount con hash,
Python verificato, budget nativo 1–5 secondi e inode intero del namespace host.
Il template sintetico minimale dei test della parte A non è un input nativo.
Il binding runtime del candidato viene completato con il runtimeRoot
dell'epoca. Nessun dato o profilo preesistente viene riscritto per adattarlo.

Prima delle modifiche verifica la lease QUIESCED con set vuoti,
`sealed_authorizer_v2`, documenti della testa e consumo READY con evidenceHash
e generazione corrispondenti. Crea `admission.json` STAGED con O_EXCL/0600;
qualunque parziale o replay resta conservato e negato. Riusa la sequenza v1:
namespace OCI o preparato, journal PREPARING, osservazioni NIC e peer,
`live_profile`, runtime indipendente e template in un nuovo namespace con
`isolated_template`. Scrive `preexec.json` e `driver.json` con O_EXCL/0600,
porta admission a PREPARED, invoca il driver plan/apply/verify e conclude
PROTECTED. Solo il broker, al ritorno della porta, sigilla driverHash nel
consumo dell'epoca.

L'entrypoint hook v2 carica lo stesso insieme ordinato di moduli v1 soltanto
dopo aver verificato tutti gli hash. `Preexec.before_process` conserva lock
comune, lease quiescente, footprint e generazione. `start` usa
`EpochConsumption.consume_locked`, con riautorizzazione prima e dopo STARTING,
e chiama il runtime sotto lo stesso lock. `hook` verifica senza consumare lo
start, come la v1. `rollback` non costruisce né chiama l'autorizzatore.
Cleanup richiede rollback indipendente già concluso, tabelle assenti,
generazione morta e inode del namespace posseduto corrispondente; solo allora
smonta il namespace e porta admission a CLEANED. Non termina processi e non
concede lease.

### Riutilizzo e differenze puntuali dalla v1

`cohort-draft/tools/semantic_provider_preexec.py:34` e
`cohort-draft/tools/semantic_provider_preexec_native.py:33` ricevono profilo e
backend/comandi; nessuna dipendenza diretta dai campi v3–v5 del grant.
`cohort-draft/scripts/semantic_provider_preexec_hook.py:121` invece lega
`verify_peers` a `authorityScope.transportHash`: quella funzione non è
riusabile letteralmente. La copia versionata `driver_v7.verify_peers` confronta
la stessa policy con `transportSha256` del ruolo letto dalla testa durevole;
raccolta, confronto osservazioni e risoluzione dei peer restano gli stessi.
Il loader dello script v1 (`semantic_provider_preexec_hook.py:59`) ammette
soltanto gli schemi precedenti: viene sostituito dal loader v7, senza cambiare
il cohort-draft. Le chiamate authority/Consumption nei due script v1 sono
sostituite dalle funzioni v2, non adattate inventando vecchi binding.
Dal modulo storico producer si riusano soltanto gli helper puri già ammessi
dalla parte A, direttamente `program` e transitivamente dagli osservatori;
nessun producer, firma o chiave viene creato allo start o in preparazione.

### Correzione run 2: chiusura completa dei sorgenti

`sourceHashes` contiene ora esattamente 28 path relativi a `sourceRoot`:
i tre entrypoint v2, i sette file Python del pacchetto
`tools/semantic_provider_admission_v2/` (compreso `__init__.py`),
`tools/semantic_provider_operation/authorization.py` ed `epochs.py`, e i
sedici moduli v1 già elencati in `broker_v2.MODULES`. I moduli v1 conservano
i path di consegna `tools/<nome>.py`; gli altri mantengono i path del repository.
File aggiuntivi, mancanti o hash non validi nella mappa sono negati. Lo stesso
insieme chiuso è richiesto dalla configurazione broker e dal grant v7; il
preparer lo acquisisce dalla configurazione broker legata per path e hash
in `preparer.json`.

Ciascun entrypoint contiene il proprio bootstrap, fissato dall'hash usato dal
runtime. Prima di eseguire codice applicativo controlla JSON canonico,
custodia privata, insieme esatto, `Path(__file__).absolute() == sourceRoot/SELF`,
hash del proprio script e poi hash di ogni altro sorgente. Il preparer verifica
anche il binding della configurazione broker. Dopo aver raccolto tutti i byte,
rilegge le configurazioni per escludere cambiamenti durante la lettura. Solo
allora crea pacchetti sintetici con percorsi di ricerca vuoti e compila i byte
verificati mediante `types.ModuleType` ed `exec(compile(...))`. Non importa
moduli applicativi da filesystem e non modifica i percorsi di ricerca Python.
L'alias storico `authorization` usato da `epochs.py` punta al modulo verificato.
Il bootstrap è duplicato nei tre script perché deve precedere l'esecuzione di
qualunque helper del pacchetto; i test controllano i manifest e il comportamento
di tutti e tre.

`SubprocessPreparer` rilegge la configurazione legata e verifica l'intera
chiusura prima e dopo il sottoprocesso. Invoca
`sourceRoot/scripts/semantic-provider-admission-preparer-v2.py`; il worker usa
lo stesso root per il template isolato e per l'hook. Non deriva questi percorsi
dalla posizione del modulo importato. Broker, worker e driver ricontrollano
gli hash prima delle rispettive operazioni, compreso rollback; l'indipendenza
di rollback dall'autorizzazione d'esercizio resta invariata.

La fixture nativa della parte A copia anche i nuovi sorgenti vincolati e attende
il codice pubblico `BROKER_SOURCE_PACKAGE_DRIFT` per una modifica del pacchetto.
È il solo adeguamento ai suoi test. I test portabili della parte B alterano a
turno ciascuno dei 28 file dopo la lettura della configurazione, per ciascun
entrypoint, e verificano il diniego prima di qualunque esecuzione applicativa.
Coprono inoltre mappe incomplete/eccedenti, percorso dello script errato,
compilazione dello snapshot e ricontrollo successivo al caricamento. I test
nativi aggiunti attraversano i tre entrypoint in processi separati e verificano
con una sentinella su disco che un modulo alterato non venga eseguito.

### Correzione run 3: protocollo template e diagnostica pubblica

Nel run 2 `Worker.prepare` passava l'output del sottoprocesso `template`
direttamente ad `authorization.decode`. Il worker termina la propria unica
riga canonica con LF; `authorization.decode` richiede invece il solo documento
canonico. Questo percorso rifiutava quindi una risposta corretta con
`CANONICAL_OPERATION_JSON_REQUIRED`, poi nascosto da `SubprocessPreparer`.
`Worker.invoke_result` ora richiede il LF e decodifica tutti i byte precedenti:
LF assente, doppio LF, CRLF, oggetti multipli e JSON non canonico sono negati.
Il test portabile attraversa un vero sottoprocesso Python e il confine
stdin/stdout; non richiede namespace o privilegi Linux. È un difetto accertato
del protocollo, non una prova dell'intero esito nativo del run 3.

Preparer e hook, sia nel bootstrap sia nelle main applicative, emettono su
stderr una sola riga `SEMANTIC_ADMISSION_PREPARER=DENIED <CODICE>` oppure
`SEMANTIC_PREEXEC_HOOK=DENIED <CODICE>`. Il codice deve corrispondere a
`[A-Z0-9_]{1,80}`; qualunque altro errore diventa `INTERNAL_ERROR`, senza
messaggi, path o traceback. Il bootstrap resta identico nei tre entrypoint
eccetto SELF/TARGET; il broker conserva il proprio esito pubblico precedente.
La porta di produzione continua a scartare stderr.

Nella suite nativa il primo sottoprocesso del preparer è osservato con cattura
di stderr esclusivamente nel test: un diniego chiama `self.fail(stderr)`.
Non si ritenta una preparazione parziale, che maschererebbe la causa originale
con un diniego di replay. Un ulteriore caso invoca direttamente il preparer
reale su un'epoca indipendente, con gli stessi byte di richiesta/stdin,
interprete, ambiente minimo e timeout della porta. Verifica il risultato
canonico con LF, il broker PROTECTED e il consumo STARTED dopo l'hook.
La fixture controlla esplicitamente custodia root:root 0600/nlink 1 di tutti
i sorgenti, directory sorgenti 0700, hash, SELF, interprete e
configurationBinding. Il controllo statico non ha individuato difetti in
questi binding della fixture; non sono stati allentati controlli nativi.
Revoca, frame modificato e replay richiedono ora i rispettivi codici pubblici.

Verifica locale run 3 su Windows/Python 3.12.12: parte B 11 test superati e
6 nativi saltati; parte A 11 superati e 6 nativi saltati; lease supervisor
16 superati e 5 nativi saltati; operation 11 nativi saltati. Il gate Linux
root resta da eseguire nel workflow già presente. WSL non è utilizzabile
in questa sessione (`Wsl/EnumerateDistros/Service/E_ACCESSDENIED`): nessun
risultato locale attesta che la CI nativa sia diventata verde.

### Prove e limiti

`tests/test_semantic_provider_admission_v2_preparer.py` copre schema chiuso,
binding, protocollo esatto del sottoprocesso, consumo sotto lock, replay,
rollback senza autorità, ricollezione peer e sentinelle contro le vecchie
chiamate. Il gate `OUF_ADMISSION_V2_NATIVE=1` richiede Linux root:root e gli
strumenti mount/umount/unshare, più un'interfaccia host con indice >1 (solo
osservata per nome/indice). Usa il broker e il preparer reali, un processo
disponibile in /proc, il mount del suo namespace, il template isolato e il
runtime sintetico; include start/cleanup, revoca e cambiamento del frame.
Le sole firme della fixture sono quelle iniziali dell'autorizzazione durevole
del task-37; sentinelle nel pacchetto temporaneo vincolato per hash impediscono
producer e vecchio authority anche nei sottoprocessi.

Non è stato trovato un eseguibile nft finto riusabile in
`tools/semantic_transaction_profiles/` o nei test preexec presenti. Il test
include quindi `FAKE_NFT`: storage per inode del namespace, tabelle e set
timeout vuoti, testo delle regole conservato nel readback per verificare
footprint e proprietà. Non esegue nft/ip né dimostra la semantica del kernel.
Il mount e unshare sono reali; le NIC osservate e il runtime sono simulati.
Il workflow esegue separatamente suite portabile e gate nativo, mantenendo le
non regressioni della parte A, operation e lease supervisor.

In questa working tree i test portabili sono eseguiti su Windows; il gate
nativo e le non regressioni native restano da eseguire in CI. Nessuna prova
locale attesta completamento nativo, installazione o effetti sul VPS.
