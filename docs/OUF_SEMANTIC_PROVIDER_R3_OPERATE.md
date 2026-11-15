# Esercizio governato del provider R3 — task-42

`scripts/operate-semantic-provider-r3.py` esercita esclusivamente i due CID
della configurazione R3 installata. Richiede Linux root:root, Python `-I -B`,
installazione 41b già completata e testa durevole `OPERATE`. Non installa
componenti, non emette firme, non legge chiavi private e non scrive direttamente
authorization, registry, epoche, configurazioni, lease o nft.

## Invocazione e plan

Argomenti obbligatori comuni:

```text
/usr/bin/python3 -I -B scripts/operate-semantic-provider-r3.py
--plan | --apply --plan-sha256 DIGEST
--action start|restart-policy|restart-one|stop
--install-root PATH
--wrapper PATH --wrapper-sha256 SHA
--docker PATH --docker-sha256 SHA --docker-socket unix:///PATH
--systemctl PATH --systemctl-sha256 SHA
--nft PATH --nft-sha256 SHA
--output-directory PATH_NUOVO
[--timeout-seconds 180]
```

`restart-one` richiede anche `--role adapter|southbound`; le altre azioni
rifiutano `--role`. Timeout intero fra 1 e 600 secondi, default 180. Tutti i
binari sono espliciti, con hash verificati prima e dopo ogni chiamata anche
in caso di errore. Stdin chiuso, stderr scartato, output letto con limite;
ambiente minimo PATH/LC_ALL/OPENSSL_CONF come nell'installatore.

Il plan è di sola lettura: nessuna directory o claim viene creato. Osservazione,
argomenti, binding, destinazione e timeout fanno parte del corpo canonico del
plan, escluso `planSha256` (i campi di stato del report CLI sono esterni al
corpo). L'apply ricalcola il plan e lo confronta di nuovo
immediatamente prima della creazione esclusiva della root di output. Un delta
richiede un nuovo plan. Il plan resta uno snapshot, non una prenotazione del
runtime; nessun lock CID/guard viene trattenuto mentre Docker esegue i figli,
che devono acquisire proprio quei lock. Runtime e supervisore mantengono i
rispettivi controlli di concorrenza e autorità.

## Osservazione

Ogni plan, il controllo prima degli effetti e ogni lettura dopo l'azione:

- verificano custodia/hash e destinazione esatta del wrapper; compilano i byte
  del runtime v5.2 installato solo dopo confronto con quelli della consegna;
  eseguono `load_configuration`, `verify_files`, `operation_modules` e
  `authorization_head` della copia installata, inclusi i mandati del registro;
- richiedono la medesima testa `OPERATE` per entrambi i CID e la ricontrollano
  a fine osservazione. Espongono solo decisione, hash e sequenza. Il journal
  v2 contiene `authorizationSha256`, **non** un campo sequence: il confronto
  con l'hash della testa autenticata vincola anche la sua sequenza;
- leggono `epochs.current` dalla copia installata e riportano numero, stato,
  bootId, failure pubblico e generazione viva sì/no. Ogni epoca esistente deve
  appartenere al boot corrente, all'hash della configurazione e della testa.
  Per la ripartenza leggono anche il journal immediatamente precedente con
  il validatore installato, esponendone soltanto numero e stato;
- eseguono `docker inspect` per CID e selezionano Status, Running, Pid,
  StartedAt, RestartCount, Runtime e nome RestartPolicy. Runtime diverso da
  `ouf-semantic-admitted-v2` dà HELD. Non confrontano né normalizzano Config,
  MAC o NetworkSettings e non modificano reti. Il PID Docker running deve
  coincidere con quello della generazione STARTED del journal;
- leggono `systemctl show` (ActiveState, SubState, NRestarts) e il file indicato
  da `supervisor/configuration.json:statusPath` con custodia root:root 0600.
  Espongono solo state, reason pubblico, epochs, activationsLastHour e
  authorizationSequence;
- leggono il journal del coordinatore dal path della medesima configurazione,
  con custodia root, selezionando state e leaseAuthorized;
- eseguono soltanto `nft -j list tables`, riportando presenza delle tabelle
  inet/bridge per i nomi dei due candidati dalla testa autenticata.

I contenuti dei documenti privati e lo stdout/stderr dei processi non vengono
copiati nelle ricevute. PID e boot sono osservazioni pubbliche selezionate.

## Azioni e traguardi

| Azione | Precondizioni | Effetti diretti e readback |
| --- | --- | --- |
| `start` | Due CID created/exited, Running false/PID 0, epoca assente o terminale; servizio attivo WAITING sulla sequenza corrente; lease QUIESCED/non autorizzato | Due `docker start` concorrenti, ciascuno con timeout. Entrambi running, epoche STARTED vive incrementate esattamente di 1 (assente = 0), supervisore ACTIVE sulle stesse epoche, lease LEASE_READY/autorizzato, quattro tabelle presenti. |
| `restart-policy` | Due CID running, epoche STARTED vive | Due `docker update --restart unless-stopped`; running, policy unless-stopped, stessa epoca/PID/StartedAt/RestartCount. |
| `restart-one` | Due CID running, epoche STARTED vive; supervisore ACTIVE sulle stesse epoche e sequenza | `docker restart --time 30 CID` del solo ruolo. Nuova epoca esattamente +1 STARTED viva, precedente DELETED, testa invariata, altro ruolo con stessa epoca/PID; supervisore nuovamente ACTIVE, lease pronto e tabelle presenti. |
| `stop` | Almeno un CID running | `docker stop --time 30 CID` dei soli ruoli running, in parallelo. Entrambi exited/PID 0, epoche terminali, supervisore attivo WAITING, lease QUIESCED/non autorizzato e quattro tabelle assenti. |

Esiti: `SEMANTIC_PROVIDER_R3_STARTED`,
`SEMANTIC_PROVIDER_R3_RESTART_POLICY_SET`,
`SEMANTIC_PROVIDER_R3_RESTARTED_WITHOUT_SIGNATURE`,
`SEMANTIC_PROVIDER_R3_STOPPED`. Gli stati terminali sono DELETED, FAILED,
ABANDONED. Per restart-one è richiesto specificamente DELETED del precedente.

Il timeout limita ciascuna richiesta Docker; dopo le richieste si apre una
finestra di polling della stessa durata. Le chiamate osservative nel polling
ricevono il tempo residuo, fino a 30 secondi ciascuna. Nessun retry delle
richieste Docker. Un errore di richiesta non produce un successo anche se il
readback raggiunge il traguardo. Se il traguardo non arriva, HELD con
`R3_READBACK_TIMEOUT`, errori pubblici delle richieste e `lastObservation`
completa (epoche/failure, Docker, supervisore, lease e tabelle). Errori di
lettura intermedi conservano l'ultima lettura completa e sono distinti in
`observationError`; non diventano assenza di epoca o di tabella.

Non c'è stop automatico dopo un fallimento. Per lo stop compensativo occorre
un nuovo plan `--action stop` e una root distinta. Se un fratello non è mai
partito e resta created, lo stop del ruolo running può riuscire ma il traguardo
complessivo exited/terminale non è provato: l'esito resta HELD, senza avviare il
fratello per far passare il controllo.

## Claim, ricevute ed errori

La root di output è nuova, separata dall'installazione, con antenati in custodia
root. `mkdir` esclusivo 0700, claim e `result.json` O_EXCL/NOFOLLOW 0600 con fsync,
come nel modello dell'installatore. Il claim conserva l'intero plan approvato.
Una root preesistente non viene riusata o sovrascritta.

`doNotRerunApply=true` già alla creazione della root (primo effetto, scelta
conservativa coerente con 41b) e comunque prima di ogni tentativo Docker.
Contatori espliciti dei tentativi: dockerStartRequests, dockerStopRequests,
dockerUpdateRequests, dockerRestartRequests; signaturesIssued e privateKeysRead
sempre zero. Timeout o errore di exec consumano il tentativo contato.
Anche un parziale dopo il claim salva `result.json`. I dinieghi prima del
claim stampano il report HELD senza creare output, come nell'installatore;
non sovrascrivono eventuali ricevute preesistenti. Errori con soli codici
pubblici, errno per OSError e callChain funzione/linea per eccezioni sconosciute.
Un errore nel salvataggio è dichiarato `diagnosisSaved=false` su stdout.

## Verifica e limiti

`tests/test_semantic_provider_r3_operate.py` include contratti portabili per
ogni azione, violazioni, delta di readback, timeout e ultima osservazione,
parallelismo obbligatorio con barriera, contatori e assenza di stop automatico.

`OUF_R3_OPERATE_NATIVE=1` abilita il ciclo Linux root in namespace mount/rete
privati sulla fixture 41b. La factory ereditata crea i file sotto `/var/lib` e
sonda gli eseguibili; non usa `/run` per i programmi della fixture. Il Docker
finto invoca realmente il wrapper v5.2 installato per create/start/delete,
attraversando broker/preparer/hook reali e processi reali con PID/startTicks.
Il ciclo verifica epoca 1 STARTED, policy, restart adapter a epoca 2 con epoca 1
DELETED, stop a DELETED e byte dell'autorizzazione invariati.

Systemctl, pubblicazione ACTIVE/WAITING, quiescenza e stato del lease sono simulatori
espliciti della fixture; non provano il servizio o l'attivazione del lease.
Nft è il modello del 41a, realmente chiamato dal driver; un lock solo della
fixture serializza il suo file di stato durante rollback concorrenti.
Non sono provati Docker Engine reale, politica di reboot o supervisore reale.
Il gate nativo su piattaforma/utente errati fallisce esplicitamente.

Il workflow installazione R3 esegue il nuovo test con gate/root, le regressioni
41a/41b/runtime v5.2 già presenti e py_compile. Su Windows locale i nativi
rimangono da eseguire in CI: `wsl --status` locale restituisce
`Wsl/EnumerateDistros/Service/E_ACCESSDENIED`. La presenza del workflow non è
un PASS attestato.
Nessun accesso VPS, rete, servizio esterno o segreto reale è richiesto.

## Dinieghi registrati

La chiusura R3 v3 include l'osservabilità del broker v2. Dopo la verifica
della directory privata dell'epoca, un'invocazione negata tenta di creare
`registry/<cid>/epochs/<epoca>/broker-denial-<modalità>.json`, schema
`ouf.semantic-deployment-broker-denial.v1`. Il file è esclusivo, 0600 e
limitato a 64 KiB: non viene sovrascritto e un errore di scrittura non cambia
il diniego. Lo stderr riporta `SEMANTIC_DEPLOYMENT_BROKER=DENIED <codice>`.
Prima che l'epoca sia verificata non viene scritto alcun file.

Ogni candidato di `lastObservation.candidates` contiene `denials`, una lista
dei documenti dell'epoca corrente e, se presente, della precedente. Ogni
documento conserva `containerId`, `epoch`, `mode`, `reason`, `at` (secondi
Unix) e `cohort`. I file sono letti tramite `runtime.read`; dimensione,
custodia, schema chiuso e binding a CID/epoca/modalità sono verificati.
Un file non valido diventa `{"invalid":"BROKER_DENIAL_INVALID"}`; un errore
di elenco diventa `{"invalid":"BROKER_DENIAL_LIST_FAILED"}`. Questi campi
sono soltanto osservazioni: non autorizzano azioni e non aggiungono dinieghi
all'operate. I documenti diagnostici non sono attestazioni firmate.

In `cohort-ready`, `cohort.peers` riporta dichiarazioni di rete, ultimo motivo
non pronto, numero dei tentativi, stato/PID runc e snapshot di rete in sola
lettura. `COHORT_PEER_WAIT_TIMEOUT` interrompe l'attesa quando rimangono meno
di 3 secondi del budget originale di 18; i secondi residui servono alla
diagnosi. `snapshotError` indica un'osservazione fallita o senza budget.
Ambiente, argv, bundle, indirizzi IPv6 e credenziali non sono riportati.
Per IPv6 compare soltanto il conteggio. Un MAC osservato diverso da quello
dichiarato continua a negare l'ammissione: questa versione non configura MAC.

Il gate `OUF_R3_COHORT_NATIVE=1` in `test_semantic_provider_r3_cohort.py` usa
un daemon Docker isolato in namespace mount/rete privati, dati/eseguibili
sotto `/var/lib` e un'immagine importata da sleep/librerie locali, senza pull.
Due container sono collegati a due bridge con IPv4 statici, senza opzioni
MAC. Una fase iniziale ne cattura le aspettative OCI negando la creazione;
poi trasporti reciproci `CREATED_CANDIDATE` con MAC derivati dagli IP sono
vincolati all'autorizzazione firmata dalle chiavi della fixture. `operate`
esegue plan/apply start concorrente tramite Engine, wrapper, runc e broker
reali. Il test stampa versione Docker e i due dinieghi, verifica epoche
FAILED, container fermi, lease QUIESCED e presenza dei `denials` nell'output.
Non impone un particolare codice: anche differenze OCI fra cattura e nuova
creazione restano dinieghi di collect osservabili. Systemd, nft e quiescer
sono simulatori espliciti, sempre WAITING/QUIESCED: non provano il servizio
o il rilascio del lease. L'esito nativo è demandato alla CI.

Il compositore resta invariato. Le regressioni v1/v2 riusano i rispettivi
input storici: la fixture v2 conserva hash e due sorgenti compressi dal
commit `e5db56dfafa8823ffa3a9a81c563c50df1ed0d17`, così la prova funziona
anche con checkout shallow. La mappa hash v1 originale non viene riscritta;
la composizione v3 verifica invece i nuovi byte e binding della chiusura.
