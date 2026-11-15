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

Il gate originario v3 (storico) `OUF_R3_COHORT_NATIVE=1` usava
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

Nella chiusura v3 il compositore restava invariato. Le regressioni v1/v2 riusano i rispettivi
input storici: la fixture v2 conserva hash e due sorgenti compressi dal
commit `e5db56dfafa8823ffa3a9a81c563c50df1ed0d17`, così la prova funziona
anche con checkout shallow. La mappa hash v1 originale non viene riscritta;
la composizione v3 verifica invece i nuovi byte e binding della chiusura.

## L2 osservato

R3 v4 usa nome di interfaccia e MAC osservati per epoca secondo D-037 esteso.
`transport.json`,
`preparer-template.json` e le dichiarazioni `CREATED_CANDIDATE` contengono il
segnaposto MAC `02:00:00:00:00:00` e nomi `l2live0`, `l2live1`, eccetera,
univoci nell'ordine firmato di ogni lista NIC; non configurano nomi o MAC Docker.
Il peer Semantic
`BRIDGE_PORT` e il suo indice firmato non cambiano (task-46b fuori perimetro).
Le regressioni v1, v2 e v3 confrontano tutti gli hash con fixture fisse e
`retainedSources`; la nuova fixture v3 conserva i byte precedenti di questo
task senza richiedere la storia Git completa.

Il broker pubblica una sola volta `registry/<cid>/epochs/<epoca>/l2-binding.json`
quando tutta la coorte è osservata. Il file 0600 lega candidato e peer a CID,
PID, start ticks, inode netns, nome reale, MAC e indici reciproci delle NIC. Tutte le fasi
di ammissione successive richiedono nuove osservazioni uguali. Non riusare o
riscrivere il file per superare un diniego: una variazione richiede una nuova
epoca secondo il lifecycle esistente. IPv4, bridge, workloadRef, bindingRef,
ordine e numero delle NIC, reciprocità,
assenza di IPv6 e stabilità restano obbligatori. Le regole `ether saddr` e
`arp saddr ether` sono materializzate con il MAC osservato.

`l2_binding.observe` associa ciascun IPv4 firmato a una sola NIC reale e verifica
che il veth host reciproco appartenga al bridge firmato. Il nome reale deve
rispettare `[A-Za-z0-9_.-]{1,15}`. IP duplicati, nomi/indici ambigui, NIC aggiuntive
o indirizzi estranei e bridge diversi sono dinieghi definitivi. Solo l'assenza
di una NIC con l'IPv4 atteso resta `PEER_INTERFACE_MISSING`, quindi riprovabile.
`effective` sostituisce esclusivamente i due segnaposto espliciti nella stessa
posizione; ogni altro campo diverso produce `L2_SIGNED_FIELD_DRIFT`. Un cambio
del nome osservato dopo la pubblicazione produce `L2_BINDING_CHANGED`.
Broker, evidenza, preparer e driver v2 mantengono lo strato del task-46a:
le librerie storiche ricevono copie effettive, i documenti firmati restano intatti.

Il gate aggiornato `OUF_R3_COHORT_NATIVE=1` usa Docker e runc reali, due reti
con IP statici e MAC assegnati dal daemon, oltre a nft, ip e nsenter reali
nel namespace isolato. L'immagine è importata da file locali, senza pull.
Gli endpoint non hanno `DriverOpts` per il nome: le NIC reali sono `eth0`/`eth1`,
le dichiarazioni v4 usano `l2live0`/`l2live1`. Il fixture cattura gli IPv4 reali
prima della firma e sceglie per adapter un ordine firmato opposto ai nomi Docker;
non dipende dall'ordine di allocazione di un altro container.
Le aspettative OCI sono catturate prima della firma e il sigillo rootfs è
calcolato indipendentemente. L'osservatore frame della fixture verifica OCI
completo e generazione reale, esercitando il protocollo frame; non qualifica
l'osservatore produttivo di mount/sorgenti. Systemd e quiescer restano fixture
esplicite WAITING/QUIESCED; nessuna lease viene attivata e nessun DNS interrogato.

Il test richiede `cohort-ready` superato e processi/consumo `STARTED`, verifica
il file L2 contro nomi, MAC e PID reali di Docker e le regole nft contro i MAC del
binding. Stampa versione Docker, binding, dinieghi e traceback. Non accetta
`PEER_MAC_IP_DRIFT`, `APPROVED_MAC_IP_BINDING_DRIFT` o
`NAMESPACE_PORT_BINDING_DRIFT`. `operate` resta HELD per la mancata attivazione
del supervisore simulato, distinta dal successo di ammissione e avvio.

### Netns del fixture e Docker 29.8.1 (task-46d)

Il vecchio `unshare --mount --net --fork` lasciava `/proc/1/ns/net` del runner
visibile nel nuovo host di test. Questo è un disallineamento concreto del
fixture; che spieghi il `L2_HOST_LINK_INVALID` della PR104 va confermato nel
prossimo CI. Il fixture ora aggiunge `--pid --mount-proc` e richiede che PID1,
fixture e bridge Docker condividano il netns host. Il daemon usa configurazione
vuota esplicita, data/exec root privati e il proprio containerd, senza importare
configurazioni del runner. Non cambia il risolutore host nel codice produttivo.

Il log stampa `COHORT_PROCESS_NETNS` per dockerd, containerd e shim,
`COHORT_FIXTURE_HOST_LINKS` e `COHORT_BROKER_HOST_LINKS`. Questi ultimi sono letti
da un proxy diagnostico della sola fixture che esegue il vero `ip`, preservando
stdout/stderr/exit code e registrando netns e antenati del processo del broker.
Entrambe le viste includono `ip -j link show` e `ip -j -d link show`: il codice
di ammissione continua a usare la prima, senza mascherare un veth mancante.
`link_index` è verificato nel netns host con reciprocità e master firmato;
`link_netnsid` non è un ifindex sostitutivo e non autorizza la ricerca in netns
estranei. Su VPS senza unshare restano gli stessi controlli host.

Il workflow `semantic-provider-r3-install.yml` conserva il job col Docker del
runner e aggiunge `cohort-docker-29`. Solo in CI scarica l'archivio statico
ufficiale `https://download.docker.com/linux/static/stable/x86_64/docker-29.8.1.tgz`,
stampa lo SHA256 calcolato e lo confronta con `DOCKER_29_SHA256`:
`d8db66739d2e28d4933786d73e918d9be643a67fbd835db1bf740d650a259e70`.
Il pin proviene dalla qualifica MAC conservata del 25 ottobre, già nel repository;
nessun download locale. Il PATH esplicito seleziona docker, dockerd, containerd,
shim e runc di quell'archivio solo per il daemon privato del fixture.

Eseguire il gate soltanto in CI Linux root:root con i prerequisiti nativi;
su Windows si eseguono le suite portabili. Restano necessari anche i gate
`OUF_R3_OPERATE_NATIVE` e `OUF_R3_UPGRADE_NATIVE`: l'aggiornamento del fixture
non è un PASS nativo né una prova VPS.
