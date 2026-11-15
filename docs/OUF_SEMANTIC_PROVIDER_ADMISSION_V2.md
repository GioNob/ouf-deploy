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
La porta predefinita nega con `PREPARER_V2_UNAVAILABLE`; non esiste un selettore
di plugin in configurazione. Il test inietta una porta sintetica, che non
costituisce un grant utilizzabile dal runtime.

I test portabili si eseguono con unittest; quelli nativi richiedono Linux
root:root e `OUF_ADMISSION_V2_NATIVE=1`. Riutilizzano la fixture crittografica
reale del task-37, epoche reali e comandi runc/rete/osservatore sintetici:
nessun container, rete o servizio viene modificato. Il workflow aggiunge le
non regressioni di operation e lease supervisor sotto sudo. Questa prova non
attesta installazione, readiness applicativa o E2E.
