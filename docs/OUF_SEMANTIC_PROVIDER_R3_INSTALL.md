# Installazione R3 e ripristino prima della prima epoca

Task sprint-01/task-41b. I programmi sono destinati a Linux, root:root,
Python `-I -B`. L'emissione task-40b precede l'installazione; il primo avvio
e la RestartPolicy dei container appartengono al task-42. Questo documento
descrive codice e fixture, senza attestare azioni o stati correnti sul VPS.

## Input e plan

`scripts/install-semantic-provider-r3.py --plan` non scrive, non prende lock,
non legge chiavi e non firma. Gli argomenti obbligatori sono:

```text
--inputs PATH --inputs-sha256 SHA256
--install-root PATH --issued-at UNIX_SECONDS
--table-name adapter=NOME southbound=NOME
--acceptance-signature PATH --acceptance-signature-sha256 SHA256
--v51-root PATH
--wrapper PATH --current-wrapper-sha256 SHA256
--lock PATH
--docker PATH --docker-sha256 SHA256 --docker-socket unix:///PATH
--systemctl PATH --systemctl-sha256 SHA256
--output-directory PATH_NUOVO
```

`--inputs`, `--issued-at`, `--install-root` e `--table-name` sono gli stessi
del task-40b. L'indice pubblico mantiene lo schema e gli insiemi chiusi
`DATA_INPUTS`/`SOURCE_INPUTS` del compositore. Non serve il profilo contenente
i binding delle chiavi. Il binding pubblico della firma di accettazione è
esplicito: il payload già nell'indice viene autenticato dal verificatore
B1/B2 reale, nello scope v5.1, prima di qualsiasi pubblicazione.

Il wrapper deve avere lo SHA dichiarato e gli esatti byte canonici che
puntano al Python, sorgente e configurazione della root v5.1. Il sorgente
v5.1 è fissato alla chiusura del 29b e compilato dai byte installati;
`load_configuration`, `verify_files` e `arming_absence` sono quelli reali.
L'accettazione e l'ancora devono coincidere con gli input ricomposti.

La root R3 deve esistere root:root 0700 e contenere esattamente
`authorization/`. La catena viene interamente autenticata con
`authorization.head`; la testa deve essere `OPERATE`, sequenza almeno 1.
Dal payload ricomposto si sostituiscono **solo** `sequence`, `supersedes`,
`issuedAt`, `decision` con i quattro valori della testa. La serializzazione
`authorization.canonical(atteso)` deve coincidere con **tutti i byte** di
`<sequence>.json`, altrimenti `R3_AUTHORIZATION_PAYLOAD_MISMATCH`.
Una testa `STOP` dà `R3_AUTHORIZATION_NOT_OPERATE`. Una testa 2 con stessi
documenti e supersedes valido è ammessa; nessun documento viene derivato
dalla testa per mascherare un delta di composizione.

Il plan osserva i due CID A2 con `common.successor_frames`, invariata:
solo `docker --host … inspect CID`, stato created/PID 0, mai avviati,
RestartCount 0; nessuna esclusione globale di `Config.MacAddress`.
Osserva inoltre il guard vuoto e il journal del coordinatore QUIESCED,
lease/start false, con binding e contenuto attesi. Il confronto del journal
usa il documento canonico: canonico e canonico più LF, entrambi ammessi
dal compositore, rappresentano lo stesso journal. Non vengono ignorati campi.

Il risultato include inventario delle pubblicazioni con path, modo, hash
dei file, directory 0700 (hash `null`, non avendo contenuto serializzato),
testo/hash dell'unità, wrapper proposto, testa/sha/confronto positivo,
osservazioni e contatori a zero. `planSha256` è lo SHA256 del JSON canonico
del plan senza il campo digest. Nessun orologio osservato, percorso generato
di staging o directory temporanea di consegna viene aggiunto al digest;
i path espliciti degli input/output e le identità osservate ne fanno parte.

## Apply e pubblicazione

Ripetere gli stessi argomenti con `--apply --plan-sha256 DIGEST`.
Il digest viene ricalcolato e controllato, poi ricontrollato sotto il guard.
La directory di output, nuova e separata dall'installazione, è il claim
duraturo e ospita `installation-claim.json`, evidenze della primitiva e
`result.json`. **Qualsiasi primo effetto**, anche mkdir o apertura O_EXCL
prima di un errore di scrittura, imposta `doNotRerunApply=true`.
Non rilanciare l'apply su una root o un claim parziale; conservarli per review.

La pubblicazione usa esclusivamente mkdir 0700 e file O_EXCL/NOFOLLOW 0600,
con fsync dei file e dei parent. Nessuna sovrascrittura della catena. Si
pubblica il layout del compositore: source completo e alias, configurazione
runtime, broker e documenti dei due ruoli, configurazione/profilo DNS del
supervisore, registry con operation.lock vuoti ed epochs vuote, senza current.

Differenza di forma già prevista dal compositore: `supervisor/state/`
contiene **soltanto la sottodirectory vuota `recovery/`**, richiesta dalla
configurazione esistente. Nessun file di stato viene precreato. Dopo
l'abilitazione il supervisore può pubblicare i propri file di stato.

Prima della switch, i byte installati vengono verificati e compilati con
isolamento degli import: loader e verify_files v5.2, load dei due broker,
Configuration/custody del supervisore e `runtime(configuration)` per
comporre la chiusura recovery e quella storica del proprietario. Quest'ultima
deve già esistere accanto alla configurazione owner originale: non viene
ricostruita né copiata arbitrariamente. Non si esegue Service durante questa
verifica. Il primo smoke chiama direttamente il v5.2 installato con
`--version`, delegando a runc; il secondo passa dal wrapper dopo la switch.

Il guard viene rilasciato prima di `systemctl enable --now`: il supervisore
deve poter acquisire il medesimo common lock per la propria quiescenza.
La switch usa **invariata** `switch_existing_wrapper` e il suo lock reale.
Il callback riesegue osservazione completa, confronto con il plan,
caricatori della pubblicazione e readback del servizio a BEFORE_CLAIM,
BEFORE_RENAME e AFTER_RENAME. L'osservazione finale ripete le verifiche.
Ogni osservazione ricontrolla la testa autenticata; avanzamenti della catena
richiedono un nuovo plan prima del primo effetto, oppure review del parziale.

Docker e systemctl usano binari espliciti verificati per hash prima/dopo la
chiamata, argv chiusi, timeout e ambiente minimo PATH/LC_ALL/OPENSSL_CONF.
Non vengono eseguiti docker start/update né altre operazioni di lifecycle.
I contatori delle operazioni dirette dell'installatore restano a zero;
il servizio avviato esegue autonomamente la quiescenza prevista dal proprio
contratto, che può revocare set nft. L'installer non rinnova lease.

## Unità systemd

Il path fisso è
`/etc/systemd/system/ouf-semantic-lease-supervisor-v2.service`, O_EXCL 0600.
L'intero contenuto deterministico è nel plan; nessun override CLI del path.

- ExecStart: Python fissato per hash, `-I -B`, entrypoint installato,
  `--configuration` e `--configuration-sha256` del supervisore.
- User/Group root, UMask 0077, Restart always, RestartSec 2.
- After docker e boot guard; BindsTo docker; WantedBy multi-user.target.
- NoNewPrivileges, ProtectSystem full, ProtectHome, PrivateTmp,
  ProtectKernelTunables/Modules, ProtectControlGroups, RestrictSUIDSGID,
  LockPersonality e sole famiglie AF_UNIX/AF_NETLINK/AF_INET/AF_INET6.
- ReadWritePaths riapre lo stato del supervisore, il **parent** del journal
  owner (necessario per replace/fsync atomici) e il file common lock.
  Tutti sono derivati dai documenti vincolati e mostrati nel plan.
- Si conserva il namespace di rete host e la capacità di usare nft/netlink;
  non si impone PrivateNetwork né si rimuove CAP_NET_ADMIN. Le restrizioni
  di mount lasciano scrivibili i percorsi espliciti precedenti anche se sono
  sotto `/etc`. Non viene usato un filtro syscall non qualificato.

Dopo daemon-reload ed enable --now, entro 30 secondi il readback deve dare
ActiveState active, SubState running, FragmentPath esatto, NeedDaemonReload no,
nessun DropInPaths e stato privato WAITING/EPOCH_NOT_LIVE, epochs null e zero
renewals/attivazioni, con authorizationSequence uguale alla testa autenticata.
Il controllo non equivale a un lease attivo o al primo start.
L'esito positivo è `SEMANTIC_PROVIDER_R3_INSTALLED_WAITING`.

## Ripristino

`scripts/restore-semantic-provider-r3.py` usa gli argomenti comuni seguenti:

```text
--plan | --apply --plan-sha256 DIGEST
--install-root PATH --v51-root PATH
--wrapper PATH --current-wrapper-sha256 SHA_WRAPPER_V52
--prior-wrapper-sha256 SHA_WRAPPER_V51
--installation-output-directory CLAIM_INSTALLAZIONE_R3
--lock PATH --docker PATH --docker-sha256 SHA --docker-socket unix:///PATH
--systemctl PATH --systemctl-sha256 SHA --output-directory PATH_NUOVO
```

Verifica ricevuta di installazione, sorgente/configurazione runtime installati,
v5.1 ancora senza arming, backup 0600 e hash prior/proposed del claim della
switch R3. Il backup deve anche coincidere con il wrapper v5.1 canonico.
Entrambi i CID devono risultare mai avviati. Per entrambi, `current` deve
essere assente (anche un symlink pendente è presenza) ed `epochs/` vuota.
Un'epoca o un puntatore dà HELD/`R3_EPOCH_PRESENT_RESTORE_DENIED`.

L'apply prende i lock operation dei CID in ordine, poi il guard, nello
stesso ordine del runtime v5.2. Ricontrolla l'assenza di epoche e conserva
i lock dei CID durante switch e disabilitazione. Ripristina soltanto i byte
del backup con `switch_existing_wrapper`, in una root di evidenza nuova;
poi disable --now e readback inactive. Nessun file installato, journal o
autorizzazione viene cancellato. Esito `SEMANTIC_PROVIDER_R3_RESTORED_V51`.
Il servizio può pubblicare il proprio STOPPED durante lo shutdown reale.

Errori: solo codici pubblici; errno per OSError e callChain (funzione/linea,
senza path o valori) per eccezioni sconosciute. Si conservano claim, backup,
diagnosi e stato incerto della primitiva, senza rollback automatico.

## Verifica e limiti della consegna

`tests/test_semantic_provider_r3_install.py` contiene contratti portabili e
sette scenari nativi gated `OUF_R3_INSTALL_NATIVE=1`, Linux root:root.
Il gate su piattaforma/utente errati fallisce esplicitamente. Ogni scenario
nativo gira in namespace mount/rete privati, con il path systemd fisso
coperto da bind mount privato; docker, systemctl, runc e stato WAITING sono
finti e registrano argv. Si riusano ricette, topologia e broker reali del 41a,
compositore/emissione reali e chiavi Ed25519 **effimere della fixture**.
Il vecchio launcher e il loop storico owner inutilizzati sono stub vincolati
per hash; le librerie owner effettivamente composte sono quelle reali.
Il quiescer è lo stesso fake esplicito del 41a; il servizio systemd reale e
le sue restrizioni non vengono esercitati dalla fixture.

Copertura nativa predisposta: plan riproducibile/apply/restore; drift separati;
testa 2 valida, mismatch e STOP; presenza epoca o current su ciascun CID;
errore parziale dopo pubblicazione; create tramite wrapper v5.2 fino al broker
reale, poi ripristino negato. Nessun primo start viene eseguito dal nuovo test.

Il workflow `semantic-provider-r3-install.yml` configura gli scenari nativi,
regressioni 29b, switch invariata, integrazione 41a, runtime v5.2, compositore,
supervisore e py_compile. Sul Windows locale WSL risponde E_ACCESSDENIED:
i test nativi restano **da eseguire in CI**, non sono dichiarati passati.
Non sono stati contattati VPS, reti, servizi esterni o segreti reali.

### Correzione fixture e diagnostica CI (run 3)

Il run 2 si è fermato sul primo plan con errno 13 all'esecuzione del docker
finto; l'ammissione parte A ha inoltre riportato `NODE_OBSERVATION_UNPROVEN`.
Questi esiti non dimostrano la causa: `/run` con `noexec`, permessi degli
antenati e interprete dello shebang devono essere verificati sul runner.
I writer delle fixture chiudono il file prima di eseguirlo.

Le sole fixture installatore R3 e ammissione parte A (anche quando ereditata
dal preparer) ora creano la propria directory temporanea 0700 sotto
`/var/lib`, con antenati root non scrivibili da altri. Il cambio della factory
è limitato al binding della fixture base durante il setup: il task-37 e la
fixture 41a restano invariati. Tutti i file della fixture, incluso il wrapper
e la chiusura installata, condividono quel filesystem. Non si usa `/tmp`, che
non soddisfa i controlli reali sugli antenati, e non si rimonta il filesystem.

Ogni script finto eseguibile ha una sonda esplicita `--fixture-exec-probe`
che termina prima della logica della fixture e della registrazione argv.
Il setup esegue direttamente lo stesso inode e shebang, dopo la chiusura del
writer, con ambiente minimo: un diniego resta un fallimento, senza retry né
fallback a un interprete esplicito. Hash, argv applicativi e caricatori reali
restano verificati. La sonda non compare nei contatori docker/systemctl/runc.

I workflow `install` e `r3` stampano identità, mount di `/run`, `/tmp` e
`/var/lib`; i test stampano il mount della directory temporanea effettiva.
La diagnostica di esecuzione riporta path della fixture, errno/timeout,
shebang e modo/UID/GID degli antenati, senza argv, documenti o chiavi.
Nella parte A l'eccezione originale viene rilanciata prima della normale
sanificazione di produzione; per la CLI R3, un esito inatteso aggiunge i path
dei programmi finti e una sonda diagnostica. Nessun controllo di produzione,
codice pubblico, timeout o budget è modificato. La conferma della causa e
l'esito nativo della correzione richiedono il nuovo run CI.
