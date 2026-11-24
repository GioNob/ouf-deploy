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
[--volatile-rootfs-result PATH --volatile-rootfs-result-sha256 SHA --volatile-source PATH]
```

`restart-one` richiede anche `--role adapter|southbound`; le altre azioni
rifiutano `--role`. Timeout intero fra 1 e 600 secondi, default 180. Tutti i
binari sono espliciti, con hash verificati prima e dopo ogni chiamata anche
in caso di errore. Stdin chiuso, stderr scartato, output letto con limite;
ambiente minimo PATH/LC_ALL/OPENSSL_CONF come nell'installatore.

Da D-047, `start` richiede i tre argomenti `--volatile-*` sopra riportati:
risultato rootfs v3 D-042 e suo hash, sorgente storico vincolato dal manifest
del risultato. Il plan include `volatileRestore` nel corpo canonico.
Prima dei due start ripristina soltanto i volatili APISIX dichiarati nell'upper
southbound e verifica con il sealer storico upper e vista unita contro i
sigilli originali. Qualunque errore dà HELD e zero start; il contatore
`volatileEntriesRemoved` e le evidenze parziali restano nel report.
L'adapter viene soltanto verificato. Input, allowlist, lock e gate overlay
sono descritti nel [contratto D-047](OUF_SEMANTIC_PROVIDER_R3_VOLATILE_RESTORE.md).
Il runbook deve consegnare il modulo di operate e le dipendenze storiche;
closure installata e versione R3 restano invariate.

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
  bootId, failure pubblico e generazione viva sì/no. Le epoche terminali conservano il legame con la loro autorizzazione storica.
  Per quelle aperte valgono la testa e la configurazione correnti. Lo start tratta
  il cambio di boot secondo le condizioni sotto riportate. La lettura del journal
  precedente usa il validatore installato e, per `ABANDONED`, riporta anche il digest;
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
- leggono la presenza delle tabelle inet/bridge dei due ruoli. Dalla v12 il gate di
  start legge anche le due tabelle condivise e ne verifica il sigillo strutturale.

I contenuti dei documenti privati e lo stdout/stderr dei processi non vengono
copiati nelle ricevute. PID e boot sono osservazioni pubbliche selezionate.

## Stato dopo un reboot

| Stato letto | Persistenza e condizione per lo start |
| --- | --- |
| Testa, CID, ruoli ed epoche | Restano su disco. Cambia il boot ID. Un’epoca aperta del boot precedente richiede la prova descritta sotto. |
| Processi, stato runc e frame Docker | Il reset perde i processi e lo stato volatile. Docker deve attestare il fermo di entrambi i CID. Per ciascuna epoca da abbandonare, runc deve attestare l’assenza nella radice registrata. |
| Tabelle e set nft | Si perdono al reboot. Il guard ricostruisce le tabelle condivise vuote. Il gate di start verifica ancora il sigillo dell’owner, inclusi gli handle. |
| Coordinatore e supervisore | Il journal del coordinatore, lo stato del supervisore e la cronologia delle attivazioni persistono. Serve una nuova osservazione di quiescenza e del servizio attivo in `WAITING` sulla testa corrente. |
| Namespace, mount e veth | Gli oggetti kernel scompaiono. Possono restare ricevute e punti di mount. Servono un peer Semantic verificabile e un overlay smontato per il ripristino. |
| Upper, PID file e socket | Persistono. D-047 qualifica i residui nominati prima della rimozione e verifica entrambi i sigilli accettati. |
| Lock, consegne, output e claim | Il kernel libera i lock. Il guard verifica il lock comune ripredisposto al boot e il runtime usa quelli per CID. Consegne, claim e marcatori dell’autostart restano leggibili. Un tentativo consumato conserva il proprio output. |

Con stop R3 governato, il readback prima dell’arresto attesta epoche terminali,
lease quiescente e tabelle dei ruoli assenti. L’autostart rispetta l’intento di stop.
Con spegnimento ordinato a R3 attivo, il supervisore su SIGTERM revoca il lease,
verifica la quiescenza e solo allora pubblica `STOPPED`. La chiusura delle epoche
dipende dal completamento del delete. Con reset improvviso il disco può conservare
`LEASE_READY` e un’epoca `STARTED`. Il guard richiesto prima di Docker può
rifiutare quel journal prima della ricostruzione nft.

Dopo un boot ammesso, il guard lascia `BLOCKED`. Il supervisore al riavvio
esegue la quiescenza. Solo se verifica ownership e set vuoti può riportare il
coordinatore a `QUIESCED` e raggiungere `WAITING`. Journal ancora bloccato
o sigillo diverso conservano rispettivamente i dinieghi
`R3_LEASE_KERNEL_JOURNAL_BLOCKED` e `R3_LEASE_KERNEL_STRUCTURE_DRIFT`.

Per lo start, sotto i lock dei CID e del coordinatore, il plan confronta il
boot ID del runtime, testa autorizzata, configurazione, CID e ruolo. Richiede
Docker fermo con PID zero, prova di assenza runc nella radice dell’epoca,
coordinatore quiescente, tabelle dei ruoli assenti e set del lease vuoti.
La scadenza è provata quando l’elemento è scomparso dalla lettura nft.
Una radice ignota o un errore generico di runc danno `HELD`.
Un’epoca aperta dello stesso boot continua a impedire lo start.

Il digest del plan lega il boot corrente (`recoveryBootId`) e la mappa
`epochsToAbandon` al numero e al digest atteso di ogni journal dopo l’abbandono. La `create` del runtime pubblica
`ABANDONED` e apre l’epoca seguente. Il readback richiede il journal storico
previsto e la nuova epoca viva `STARTED` con numero incrementato di uno.
Dopo un’interruzione il claim resta consultabile. Un nuovo plan legge lo stato
corrente e richiede una nuova destinazione. Una coorte già partita impedisce
un secondo start.

**R-025 resta aperto.** Il recupero pre-Docker e del kernel del lease con nuovi
handle spetta ai task successivi. Per chiudere il rischio serve anche la
qualifica in esercizio del reboot completo.

Riferimenti al codice del boot e della quiescenza al commit base del task:
[precondizione del guard](../tools/semantic_lease_kernel_migration/boot_runner_v2.py#L17),
[avvio e arresto del supervisore](../tools/semantic_provider_operation/lease_supervisor_v2.py#L398),
[transizione del coordinatore](../tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_lease_coordination.py#L231),
[abbandono in create](../tools/semantic_runtime_v52/semantic_provider_docker_runtime_v52.py#L650).

## Azioni e traguardi

| Azione | Precondizioni | Effetti diretti e readback |
| --- | --- | --- |
| `start` | Due CID created/exited, Running false/PID 0, RestartPolicy `no` su entrambi, epoca assente, terminale o del boot precedente con le prove sotto indicate; servizio attivo WAITING sulla sequenza corrente; lease QUIESCED/non autorizzato | Due `docker start` concorrenti, ciascuno con timeout, senza `docker update`. Entrambi running con policy ancora `no`, epoche STARTED vive incrementate esattamente di 1 (assente = 0), supervisore ACTIVE sulle stesse epoche, lease LEASE_READY/autorizzato, quattro tabelle presenti. |
| `restart-policy` | Disattivata da D-045: plan sempre negato con `R3_RESTART_POLICY_DISABLED_D045`, qualunque sia lo stato dei CID | Nessun effetto, nessun update. L'argomento resta disponibile per rendere esplicito il diniego. |
| `restart-one` | Due CID running, epoche STARTED vive; supervisore ACTIVE sulle stesse epoche e sequenza | `docker restart --time 30 CID` del solo ruolo. Nuova epoca esattamente +1 STARTED viva, precedente DELETED, testa invariata, altro ruolo con stessa epoca/PID; supervisore nuovamente ACTIVE, lease pronto e tabelle presenti. |
| `stop` | Almeno un CID running | `docker stop --time 30 CID` dei soli ruoli running, in parallelo. Entrambi exited/PID 0, epoche terminali, supervisore attivo WAITING, lease QUIESCED/non autorizzato e quattro tabelle assenti. |

Esiti: `SEMANTIC_PROVIDER_R3_STARTED`,
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

## Politica di restart (D-045, sostituisce D-044)

Docker deve mantenere `RestartPolicy: no` su entrambi i container. Con
`unless-stopped`, la coorte nativa ha mostrato riavvii autonomi dopo uno start
negato o compensato da R3: container running fuori dal lease (`EPOCH_NOT_LIVE`)
e secondo start negato con `R3_START_CANDIDATES_NOT_IDLE`. Questo viola il
principio R3 di nessun riavvio automatico dopo un fallimento.

Lo start richiede `no` nel plan e di nuovo nell'osservazione prima degli effetti;
una policy diversa su uno dei ruoli produce `R3_RESTART_POLICY_MUST_BE_NO`.
Esegue soltanto i due start e il readback finale richiede ancora `no` su entrambi.
Non corregge automaticamente policy preesistenti. `restart-policy` è disattivata:
il plan la nega sempre con `R3_RESTART_POLICY_DISABLED_D045`, senza effetti.
Stop e restart-one mantengono il comportamento esistente e accettano `no`.

L'avvio al boot sarà affidato a un'unità systemd con tentativi limitati, in un
task separato, fuori dal perimetro di questa modifica.

Il gate Docker nativo del task-58 resta una prova documentale del comportamento
Engine: su un container fermo `docker update --restart` aggiorna la configurazione
senza passare dal runtime OCI, mentre su uno running raggiunge il runtime R3,
che rifiuta `update`. Questo risultato non giustifica l'impostazione di una
politica di restart e non è usato dal percorso operativo.

Il plan è uno snapshot: non impedisce interventi concorrenti esterni. Non
trattenere lock runtime durante le chiamate Docker e non rigiocare un apply
consumato per correggere un parziale.

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
Questo ciclo non prova Docker Engine reale, politica di reboot o supervisore reale.
Il gate nativo su piattaforma/utente errati fallisce esplicitamente.

Il gate distinto `OUF_R3_RESTART_POLICY_DOCKER_NATIVE=1`, nel workflow
installazione R3, richiede Linux root:root e Docker/runc reali del runner.
Avvia un daemon con socket, configurazione, data/exec root privati, bridge
e iptables disabilitati; importa sleep e librerie locali senza pull. Registra
un runtime di prova che traccia gli argv, rifiuta update con exit 42 e delega
le altre operazioni a runc. Verifica update riuscita in created ed exited
senza invocazione OCI update, e la stessa richiesta fallita in running con
una invocazione update registrata. Il gate abilitato fallisce se mancano i
prerequisiti; senza gate il test è esplicitamente skipped. La presenza del
test non attesta un PASS CI né il funzionamento al reboot o sul VPS.

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

## Pulizia delle epoche fallite

Il runtime v5.2 nella chiusura v4 accetta `state`, `kill` e `delete` per
un'epoca `FAILED` del boot corrente, sotto il medesimo `operation.lock`.
La pulizia non apre epoche né ripete `create` o l'autorizzazione iniziale.
Il percorso delle epoche di boot precedenti rimane invariato.

Per un'epoca mai preparata (`driverHash` nullo), prima di inoltrare ogni
operazione il runtime interroga `runc --root <root> state <cid>` e richiede
CID esatto, `runtimeRoot` esatto e bundle ombra `epochs/<epoca>/bundle`.
Sono ammessi soltanto `created` e `stopped`; `running` è sempre negato.
Se il PID è vivo e il giornale `deployment.json` contiene una generazione,
PID e start ticks devono coincidere. Il giornale di consumo, quando letto,
deve appartenere allo stesso CID, epoca e autorizzazione. Anche una generazione
presente nell'adapter deve coincidere. Non è richiesta l'uguaglianza del
`configurationHash` storico con quello corrente: una configurazione precedente
può aver lasciato il task da rimuovere. La configurazione e gli eseguibili
correnti restano verificati. Non vengono invocati broker, preparer, driver o
quiescer. Anche il `delete` ordinario senza driver usa queste prove e non
richiede un rollback inesistente.

L'assenza deve essere provata con lo stesso protocollo rigoroso di `inactive()`:
exit 1 e messaggio esatto `container does not exist`, anche nella forma JSON-log
testuale di runc già ammessa da `inactive()`. Timeout, errore di permessi o
messaggio soltanto simile non dimostrano assenza. In questo caso soltanto
`state` e `delete` vengono inoltrati, preservando l'exit code di `state`;
`kill` resta negato. Un `delete` non riuscito non prova la pulizia.

Dopo `delete` riuscito viene creato esclusivamente, con modo 0600 e fsync del
file e della directory, `epochs/<epoca>/runtime-cleanup.json`:

```json
{"schema":"ouf.semantic-docker-runtime-cleanup.v1","epoch":1,"operation":"delete","at":1794740400,"runcStatusBefore":"created"}
```

`at` è un timestamp Unix in secondi; l'esempio è illustrativo.
`runcStatusBefore` può essere `created`, `stopped`, `running` (solo epoche
preparate) o `absent`. Il file esistente viene validato e conservato byte per
byte: i successivi delete verificano ancora l'assenza con runc e inoltrano la
richiesta, senza ripetere il rollback. Un container ricomparso dopo una ricevuta
è negato. Un diniego non produce mai la ricevuta. Per le epoche senza driver
`adapter.json` e il puntatore `current` restano invariati e terminali; la normale
apertura successiva può quindi assegnare l'epoca seguente.

### R-012 — epoca FAILED già preparata

Con `driverHash` valorizzato il delete richiede i binding sigillati ordinari:
configurazione corrente e autorizzazione dell'epoca, hash e binding del driver,
broker `PROTECTED`, consumo `READY`/`STARTING`/`STARTED` coerente e journal preexec
ammesso al rollback (`INSTALLING`, `PROTECTED`, `REMOVING`). Lo stato runc deve
ancora appartenere al CID, bundle, root e generazione dell'epoca; in questo
percorso è ammesso anche `running`, e runc resta responsabile di accettare o
rifiutare il delete richiesto da Docker.

Il broker esistente richiede l'adapter in `DELETING`: il runtime pubblica
transitoriamente quello stato mediante CAS, quindi esegue nell'ordine runc
delete, quiesce, `driver_call('rollback')`, `broker_phase('cleanup')`. Driver e
broker conservano tutti i propri controlli su lock comune, footprint e richieste
sigillate. Alla fine viene ripristinato via CAS l'esatto giornale `FAILED`
originario, compreso il motivo del primo diniego, e registrata la ricevuta.
Non sono introdotti nuovi stati né modifiche al validatore delle epoche.

Prerequisiti mancanti, configurazione storica preparata incompatibile, rollback
non consentito o un errore in qualsiasi fase restituiscono
`FAILED_PREPARED_EPOCH_REQUIRES_RECOVERY`, senza ricevuta di successo. Anche in
caso di errore viene tentato il ripristino CAS del `FAILED` originale; un errore
CAS resta un diniego. Una caduta del processo durante `DELETING` o un rollback
parziale richiedono riconciliazione governata; non vengono dichiarati puliti
né ripetuti automaticamente i passi già consumati.

Per il caso stesso boot con preexec già `ROLLED_BACK` e autorizzazione
superata, seguire il [runbook di riconciliazione R3 v18](OUF_SEMANTIC_PROVIDER_R3_RECONCILE.md).

Il test portabile usa runc simulato e verifica sia i dinieghi sia la sequenza
di rollback. `OUF_R3_COHORT_NATIVE=1` aggiunge un veto esplicito della fixture
su `cohort-ready` dell'epoca 1, dopo la creazione reale. Stampa entrambi gli
start e lo stato finale; il secondo start deve far eseguire a Docker la pulizia
del task obsoleto e aprire l'epoca 2, superando `cohort-ready` con i MAC osservati.
Verifica ricevute, vecchie generazioni terminate e assenza di `runc init`
residui dei candidati salvo le generazioni della nuova epoca. Non intervengono
delete runc manuali, reset di journal o kill diretti fra i tentativi.
La lease della fixture resta QUIESCED e `operate` resta HELD per il supervisore
WAITING, come nel gate precedente. Queste asserzioni native richiedono CI Linux;
la modifica del test non ne attesta il superamento.
