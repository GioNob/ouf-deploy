# Lettori R3 in sola lettura — D-046(a)

Consegna task-60 per `oufadmin`. Nessuna installazione o osservazione del VPS è
attestata da questo documento. Il codice runtime e i runbook R3 preesistenti
restano invariati.

## Lettori e invocazioni

Il prefisso per tutte le forme autorizzate è:

```text
sudo /usr/bin/python3.13 -I -B /usr/local/libexec/ouf-readers/r3/
```

Al prefisso si aggiunge una delle forme seguenti:

| Forma | Output |
| --- | --- |
| `r3-status.py` | Testa delle autorizzazioni, epoche correnti, ultimo diniego per mtime, Docker, lease, supervisore e tabelle nft R3 |
| `r3-epoch-timeline.py adapter N` | File dell'epoca adapter |
| `r3-epoch-timeline.py southbound N` | File dell'epoca southbound |
| `r3-epoch-timeline.py both N` | File di entrambi i ruoli |
| `r3-watch.py adapter` | Osservazione dei processi adapter |
| `r3-watch.py southbound` | Osservazione dei processi southbound |
| `r3-supervisor-journal.py` | Ultime 200 righe del supervisore, filtro prima del troncamento a 300 caratteri |
| `r3-epoch-diag.py` | Diagnostica storica, default versione 7 / ultima epoca |
| `r3-frame-diag.py` | Diagnostica storica, default versione 5 / ultima epoca |
| `r3-guard-diag.py` | Diagnostica storica, default versione 8 |

Le copie dei diag accettano anche versione e, dove previsto, epoca esplicite,
solo come interi ASCII maggiori o uguali a 1, con rifiuto degli argomenti extra.
Il sudoers consegnato abilita per questi tre script esclusivamente le forme
senza argomenti. Eventuali altre forme richiedono nuove enumerazioni esatte,
non ulteriori jolly. Le versioni di default sono quelle originali, non una
presunzione sulla versione attualmente installata.

I nuovi lettori selezionano la root dal wrapper fisso
`/usr/local/sbin/ouf-semantic-admitted-v2`, accettando soltanto la root canonica
`/etc/ouf/deploy-snapshots/semantic-provider-r3-install-v1` o una sua versione
numerica, come `operate.observe`. Leggono `runtime-configuration.json`, i candidati,
le configurazioni vincolate per hash del supervisore e dei broker, e i journal
nelle rispettive root. Non occorre consegnare runbook all'utente SSH.
`r3_common.py` è un modulo ausiliario nello stesso percorso root, senza grant sudo.

Lo stato è una fotografia diagnostica, non un'ammissione: l'hash dell'autorizzazione
è quello del documento pubblico con sequenza massima; `verified=false` dichiara
che non vengono eseguite verifiche delle firme o della catena dei mandati.
Il puntatore dell'epoca viene confrontato con l'hash del journal; `live` richiede
STARTED, boot corrente e stessa generazione PID/startTicks. Letture concorrenti
possono produrre errore o una fotografia non atomica; non vengono presi lock.
Gli errori dei nuovi lettori riportano soltanto il tipo, senza contenuti privati.

La timeline mostra mtime UTC e percorso relativo dei file, e soltanto i campi
scalari `state`, `failure`, `reason`, `code`, `mode`, `schema`; in `failure` oggetto
mostra esclusivamente `code` e `reason`. Stringhe non conformi a codici pubblici
o contenenti token/secret/password/authorization sono redatte. Altri campi e
contenuti binari non vengono stampati. I link simbolici non vengono letti.

Il watcher cerca PID numerici nel cgroup esatto del CID selezionato: runc-init e
Python. Non usa sottostringhe del CID e ricontrolla startTicks e appartenenza
prima delle osservazioni di rete. La porta TCP è ricavata dall'unica porta dei
flussi di trasporto vincolati che hanno destinazione negli indirizzi del ruolo;
assenza o ambiguità causano errore, senza fallback a 9443. Per ciascun processo
mostra limiti selezionati, conteggi fd per tipo (nessun percorso privato),
link/indirizzi del netns e presenza LISTEN in `/proc/PID/net/tcp{,6}`.
Attende l'apparizione fino a 25 minuti; dopo la cattura termina con GONE oppure
STILL_UP_20S. Se nessun processo appare, termina con TIMEOUT_25M (exit 1).

Gli unici eseguibili chiamati dai lettori nuovi sono `/usr/bin/docker inspect`,
`/usr/sbin/nft -j list tables`, `/usr/bin/journalctl` con unità e opzioni fisse e
`/usr/bin/nsenter --net=/proc/PID/ns/net /usr/bin/ip -br link|addr`.
Il frame diag conserva anche `/usr/bin/docker ps -q --no-trunc`.
Non vengono stampati argv dei processi, variabili ambiente Docker o file privati.

## Confine sudoers

`91-ouf-r3-readers` contiene dieci grant, tutti con interprete assoluto e `-I -B`.
Il solo jolly è l'ultima posizione EPOCH delle tre forme della timeline.
Sudo confronta gli argomenti come una stringa e `*` può comprendere spazi:
la sicurezza dipende quindi anche dal controllo dello script, che richiede
esattamente ROLE ed EPOCH e rifiuta tutto ciò che non è un solo intero ASCII
maggiore o uguale a 1. Non è possibile introdurre ulteriori argomenti, opzioni
Python o percorsi: l'interprete ha già ricevuto il percorso fisso dello script.
Non sono concessi interpreti generici, apply, runbook o journalctl libero.

## Installazione umana

Il runbook `ops/vps/r3-readers-install.sh` va eseguito da root da parte
dell'operatore autorizzato. Il pin `C` è intenzionalmente tutto zero: Claude lo
fisserà dopo review e commit, secondo D-001. Con il pin zero ogni modalità
rifiuta l'esecuzione prima di download o modifiche.

```bash
bash ops/vps/r3-readers-install.sh plan
bash ops/vps/r3-readers-install.sh apply <planSha256>
```

Plan scarica esclusivamente i nove blob elencati dal commit fissato, controlla
gli SHA-256 dei byte LF, verifica la copia temporanea con `visudo -cf` e stampa
hash, destinazioni, proprietari e modi. Non installa file; usa una directory
root temporanea eliminata all'uscita. Il digest del piano comprende manifest,
commit e hash dello stesso runbook.

Apply ripete download, hash e visudo, e confronta il digest con il piano
approvato prima dell'installazione. Rifiuta antenati esistenti simbolici,
non root o scrivibili da gruppo/altri. Installa directory e Python root:root
0755; valida ancora il sudoers temporaneo root:root 0440 nella stessa directory
di destinazione e lo pubblica con rename atomico. Stampa gli hash installati.
Non modifica il file sudoers 90. I file Python non sono pubblicati come un'unica
transazione: l'operatore deve evitare letture durante l'aggiornamento del set.

## Qualificazione offline

```bash
python -B -m unittest discover -s tests -p test_r3_readers.py -v
bash -n ops/vps/r3-readers-install.sh
sudo /usr/sbin/visudo -cf ops/vps/readers/91-ouf-r3-readers
```

Undici test verificano sintassi, argomenti, copie dei diag mediante confronto
AST, albero finto invariato (hash, modi e mtime), sentinelle di segreti,
redazione, cgroup/generazione PID, comandi netns, porta da configurazione,
esiti temporali del watcher, jolly sudoers e hash LF della consegna.
Nessun test accede al VPS, a Docker reale o a una rete.

Esecuzione locale: 11/11 PASS con Python 3.12.14; `bash -n` PASS.
La CI dedicata usa `ubuntu-24.04` e Python 3.13, esegue gli stessi test e
`visudo -cf`. Non è stata avviata da questa worktree: esito CI e controllo
visudo non sono attestati localmente. Verificato anche il rifiuto di plan con pin zero, prima di ogni download.
Non sono stati eseguiti plan con pin attivo o apply,
installazioni, commit, staging Git o push.
