# Aggiornamento governato R3 — task-43

Questa procedura aggiorna la chiusura R3 con un'autorizzazione d'esercizio
N+1 già firmata. Descrive codice e prove del repository; non attesta un
aggiornamento o uno stato corrente del VPS.

## Sequenza operativa

1. Con la consegna operativa della versione corrente, eseguire il plan e
   l'apply di `operate --action stop` se il provider è acceso, con la testa
   ancora allineata alla versione installata. Prima
   dell'emissione successiva tutte le epoche devono essere assenti o
   terminali, i due CID fermi e il lease `QUIESCED`, con autorizzazioni
   lease/start false. Per ogni `FAILED` preparato serve la ricevuta di cleanup
   del wrapper. Se nessuna epoca è mai stata aperta e i CID sono già
   fermi, il comando stop non è necessario: task-42 rifiuta uno stop senza
   candidati running.
2. Emettere l'autorizzazione successiva con l'issuer, aggiungendo
   `--supersede` sia al plan sia all'apply. Conservare la ricevuta. [Gate di
   supersessione nell’issuer](OUF_SEMANTIC_PROVIDER_R3_COMPOSE_AND_ISSUE.md#emissioni-successive-con---supersede).
3. Eseguire il plan dell'upgrade; rivedere pubblicazioni, unità e wrapper.
   Usare gli stessi argomenti e il suo `planSha256` nell'apply.
4. Dopo `SEMANTIC_PROVIDER_R3_UPGRADED_WAITING`, usare `operate --action start`
   con l'hash del nuovo wrapper. La registry rimane la stessa e la nuova
   epoca prosegue la numerazione, con l'autorizzazione N+1.

L'ordine è necessario: v5.2 rifiuta il cambio di configurationHash di
un'epoca aperta; il supervisore ritira il lease quando cambia la testa;
il delete usa broker/configurazione correnti. Nessun aggiornamento con
container accesi è ammesso. Un esito parziale richiede riconciliazione
dell'evidenza; non autorizza un nuovo apply, un rollback automatico o la
cancellazione dei parziali.

## Composizione e layout

L'API pura è:

```python
compose(inputs, version=1)
compose(inputs, version=N+1, sequence=N+1, supersedes=sha_payload_N)
```

`version` è un intero almeno 1; bool e altri tipi sono rifiutati. La versione
1 conserva tutti i byte e i percorsi del task-40b. La fixture
`tests/fixtures/r3-v1-document-hashes.json`, acquisita su HEAD `77aa1733`
prima delle modifiche, fissa gli hash di tutti gli input e documenti.
Il test confronta l'intera mappa, comprese copie sorgenti, lock e payload.

Da versione 2 i documenti e i relativi binding puntano a:

```text
<installRoot>/versions/<v>/source/
<installRoot>/versions/<v>/runtime-configuration.json
<installRoot>/versions/<v>/broker/
<installRoot>/versions/<v>/documents/
<installRoot>/versions/<v>/supervisor/configuration.json
<installRoot>/versions/<v>/supervisor/dns-profile.json
```

Restano condivisi `<installRoot>/registry/`, `authorization/` e
`supervisor/state/`, inclusi stato, attivazioni e recovery. La composizione
da v2 non produce copie dei lock della registry. L'upgrade pubblica solo
la nuova versione; non riscrive i documenti della root o di versioni
precedenti, i journal, la catena o la storia delle attivazioni.

## Emissione N+1

Gli argomenti del task-40b rimangono validi; `--supersede` seleziona la
catena esistente. La testa viene autenticata integralmente con
`authorization.head`: deve essere `OPERATE`. Il nuovo payload ha sequenza
N+1, supersedes uguale allo SHA dei byte di `N.json` e issuedAt non inferiore
alla testa. La versione composta è N+1. Senza `--supersede` resta la prima
emissione in una catena vuota.

Il plan non apre chiavi. L'apply mantiene la disciplina dell'issuer
esistente: un solo utilizzo logico della chiave installer, dal path di
custodia originale; hash prima e dopo, nessuna copia della chiave. OpenSSL
deriva il pubblico e firma usando quel medesimo path. La directory della
catena viene bloccata e la testa ricontrollata prima della firma e della
pubblicazione. Payload e firma sono creati con `O_EXCL` come
`<N+1>.json` e `<N+1>.signature.json`. La rilettura autenticata deve restituire
esattamente N+1 e il nuovo hash. Un file preesistente o una coppia parziale
non vengono sovrascritti.

## CLI di aggiornamento

Richiede Linux root:root e Python `-I -B`. Gli argomenti obbligatori sono:

```text
/usr/bin/python3 -I -B scripts/upgrade-semantic-provider-r3.py
--plan | --apply --plan-sha256 SHA256
--inputs PATH --inputs-sha256 SHA256
--install-root PATH --issued-at UNIX_SECONDS
--table-name adapter=NOME southbound=NOME
--wrapper PATH --current-wrapper-sha256 SHA256
--lock PATH
--docker PATH --docker-sha256 SHA256 --docker-socket unix:///PATH
--systemctl PATH --systemctl-sha256 SHA256
--output-directory PATH_NUOVO
```

L'indice pubblico e i settings mantengono lo schema chiuso del compositore.
Il journal di coordinamento negli input deve coincidere con quello corrente
QUIESCED: va legato esplicitamente per hash, senza riportarlo allo stato
iniziale. Non sono input dell'upgrade il profilo delle chiavi o le chiavi
private. L'accettazione è quella della chiusura ricomposta e già legata al
payload firmato; l'upgrade non emette una nuova firma d'accettazione.

Il plan è in sola lettura, senza creazioni o lock acquisiti. Autentica
la testa N+1 e confronta l'intero payload con la ricomposizione della versione
N+1; solo sequence/supersedes/issuedAt/decision sono sostituiti dalla testa,
come nel 41b. La catena verifica a sua volta sequenza, supersedes e tempo.
La configurazione della versione N è autenticata dal payload N prima di
compilarne il runtime; non deve coincidere con i sorgenti nuovi del repository.
Il runtime installato verifica i suoi binding. Wrapper e unità devono essere
gli esatti byte attesi per N. Sono verificati anche FragmentPath, assenza di
drop-in, caricamento dell'unità e NeedDaemonReload=no.

Il lettore reale delle epoche verifica puntatore e journal; sono controllati
anche i journal storici. Ogni epoca deve essere terminale oppure assente,
Docker deve essere fermo con PID zero e il lease QUIESCED. I comandi Docker
sono esclusivamente inspect; nessun confronto Config/NetworkSettings o
cambiamento di container. La versione N+1 deve essere assente, anche come
link. Il plan elenca directory 0700, file 0600, hash, nuova unità e wrapper.

L'apply ricontrolla il digest e acquisisce i lock CID prima del guard,
come runtime e restore. Mantiene i lock CID fino alla fine, rilasciando il
guard durante le operazioni systemd per non impedire al supervisore di
acquisire il proprio lock. Esegue quindi:

1. claim separato e pubblicazione esclusiva della nuova versione;
2. verifica dei byte pubblicati e dei caricatori reali di runtime v5.2,
   broker v2 e supervisore, inclusa la chiusura owner/recovery;
3. compilazione di `driver_v7` e dipendenze dai byte pubblicati, con il
   verificatore delle sorgenti usato da `driver_v7.load`; non esiste ancora
   un grant della nuova epoca da caricare. Il caricamento del grant reale è
   verificato dal ciclo nativo start dopo l'upgrade, senza costruire epoche
   o profili artificiali nell'upgrader;
4. smoke diretto `--version`, senza creare o avviare container;
5. stop del supervisore, file temporaneo esclusivo, rename atomico della
   nuova unità, fsync, daemon-reload e start del supervisore;
6. readback active/running e WAITING/EPOCH_NOT_LIVE con la sequenza N+1.
   Il contatore storico delle attivazioni può essere maggiore di zero e
   rimane conservato;
7. CAS del wrapper con `switch_existing_wrapper` dal wrapper N, rilettura
   e smoke del wrapper, quindi `result.json`.

Ogni controllo del CAS ricontrolla testa, input, stato fermo, unità e
pubblicazione. Il primo effetto rende `doNotRerunApply=true`, anche se una
scrittura o una fase successiva fallisce. Come in `install_common`, i dinieghi
usano `HELD`, codici pubblici, errno e diagnosi del primitivo senza messaggi
di eccezione o output dei processi. Se la root di evidenza è stata creata,
si tenta di salvarvi l'esito. Nessun rollback automatico.

## Esercizio e ripristino

`operate` seleziona la configurazione dal wrapper verificato, ammettendo solo
la root originale o `versions/<intero almeno 2>`. Per le epoche aperte restano
obbligatori boot, hash della configurazione e autorizzazione correnti.
Le epoche terminali, comprese quelle precedenti, conservano i loro binding:
devono corrispondere a un payload OPERATE della catena autenticata e al suo
runtimeConfigurationSha256. Non vengono riclassificate o riscritte.
Questo è l'adeguamento minimo al task-42 necessario per il nuovo start.

Il restore 41b verso v5.1 non viene ampliato: rimane il ripristino della
ricevuta iniziale, prima della prima epoca, con i dinieghi già presenti.
Non è un rollback fra versioni R3 né uno strumento per chiudere epoche aperte.

## Verifiche e limiti

I test portabili verificano la regressione v1, percorsi condivisi/versionati,
catena N+1, confronto del payload, dinieghi per epoche aperte, versione già
presente, wrapper/unità difformi, ordine dell'apply, contatori e diagnosi
parziali. Il workflow R3 install mantiene le non regressioni 41b/42 e aggiunge:

```text
sudo -n env OUF_R3_UPGRADE_NATIVE=1 /usr/bin/python3 -I -B
-m unittest discover -s tests -p test_semantic_provider_r3_upgrade.py -v
```

Il gate nativo fallisce se abilitato fuori da Linux root:root. Riusa la fixture
41b/42 sotto `/var/lib`, in namespace mount/rete privati: installazione v1,
start, stop, issuer CLI --supersede, upgrade v2, start sulla stessa registry
con nuova epoca/sequenza 2, restart-one, stop. Controlla anche un upgrade
negato con epoca aperta. Runtime, broker, hook, firme, writer delle epoche e
switch sono reali; Engine, systemd e coordinamento del lease sono simulatori
espliciti ereditati dalle fixture precedenti. Non è una prova systemd/Docker
reale o un'operazione VPS. I test nativi sono demandati alla CI dopo il commit
del reviewer; non vengono eseguiti nella working tree Windows.

I runbook `ops/vps/r3-*.sh` restano la consegna storica v1 e non vengono
modificati. Il relativo test verifica byte LF, hash e chiusura sul commit
già fissato nei runbook; non pretende che quella consegna storica abbia
gli hash della nuova implementazione. I workflow nativi verificano invece
le CLI correnti. Non è stato preparato un launcher VPS per l'upgrade.
