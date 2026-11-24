# Cattura fuori host e ricostruzione su un secondo host

## Preparazione del custode

Usare il checkout custodito da root del commit di consegna su Linux e Python 3.13.
Dopo la review il manutentore fissa `C` nel launcher al commit dei blob consegnati.
Completare il profilo privato secondo il [contratto](../contracts/capture-profile-v1.schema.json).
Il file ha modalità 0600. Predisporre per la singola cattura una directory vuota 0700,
su un filesystem con spazio disponibile. I suoi antenati e quelli degli eseguibili e
del socket appartengono a root e sono protetti dalla scrittura di terzi. Indicare i
percorsi reali, risolvendo prima i symlink amministrativi. Il gruppo autorizzato del
socket può scrivere. Fissare i byte di `nice`, `docker` e `age` con SHA-256.

Associare ogni istanza al suo ID nel registro del commit. Per PostgreSQL dichiarare anche
i database predefiniti e quello IAM. Individuare nel profilo le tabelle applicative
il cui contenuto è fuori perimetro.
In `postgres.omitTableData` dichiarare database, schema, tabella e
`capture.logical-exclusions` per oggetti, risultati, cache sacrificabili, sessioni
e token. Per questi database il dump conserva schema e vincoli e omette le righe delle
tabelle indicate. Gli altri database e gli oggetti globali passano da pg_dumpall.
Il custode deve confermare le selezioni rispetto alle migrazioni installate e ai
vincoli fra tabelle. Una tabella che richiede un predicato per riga richiede una
regola del suo owner prima di acquisire il database. L'utente deve poter leggere il cluster,
compresi i ruoli. La connessione di backup nel container deve funzionare senza prompt.
Per etcd occorrono un solo endpoint locale, autenticazione del membro, `etcdctl`, una shell
POSIX, `flock` e tmpfs in /dev/shm con capacità sufficiente per lo snapshot.
Verificare in anticipo sulla distribuzione scelta. Il lettore usa il CID osservato nel piano.

Includere le sorgenti dei bind, i profili e la configurazione del demone, le fonti apt,
Caddy, il corredo TLS, i lettori, i sudoers, le ricevute e i journal. Dichiarare i
pattern delle unità, compresi i drop-in Docker del guard. Includere esplicitamente
puntatore, dispatcher e closure della generazione. Per i volumi PostgreSQL ed etcd
associare le rispettive copie logiche. Per storage/staging usare l'esclusione D-064.
Riservare la voce dei volumi ricreabili a volumi di cui serve la sola definizione.
Per un volume locale con file Caddy/TLS scegliere `capture.proxy`; la cattura
percorre il mountpoint osservato. Per un bind di PGDATA o del data-dir etcd indicare
in `excludePaths` il corrispondente archivio logico. La distinta delle istanze e la
corrispondenza fra riferimenti pubblici e percorsi esclusi stanno nell'inventario cifrato.

Indicare tutte le radici di chiavi private R3, registrazione del runner, token,
payload e copie di lavoro tra le esclusioni. L'esclusione di una directory precede
qualsiasi inclusione discendente. Compilare custode, regola di rotazione e consumatori
nelle righe private `secretOwners`. Motivare in `absent` gli elementi opzionali assenti
nella distinta dell'installazione. L'identità privata age rimane con l'umano.
Sono ammessi destinatari pubblici age X25519 e SSH compatibili con la versione installata.

## Misura, acquisizione e custodia D-066/D-070

Concordare con gli owner una finestra coerente tra dump, snapshot e file. Sospendere
rilasci e scritture applicative che renderebbero incompatibili le famiglie. Conservare
le ricevute. Il lock della cattura serializza gli apply nella stessa directory.

```sh
export OUF_PYTHON=<interprete-assoluto>
export OUF_CAPTURE_PROFILE=<profilo-assoluto>
bash ops/vps/capture.sh --measure
bash ops/vps/capture.sh plan
bash ops/vps/capture.sh apply "$PLAN_SHA256"
```

Sostituire i segnaposto prima dell'uso. Valutare dimensioni, spazio libero,
esclusioni e motivi HELD. I riferimenti pubblici alle esclusioni sono SHA-256 dei
nomi UTF-8. Le stime di PostgreSQL, etcd e immagini possono differire dai byte
effettivi. I limiti sui flussi e la riserva disco valgono anche durante la cifratura.
Solo il manifest finale identifica una cattura completa. Dopo un'interruzione,
ripetere l'apply con il digest osservato. Le famiglie confermate vengono rilette
e verificate. Il journal registra la pulizia dei residui. Un cambio inventariale
richiede un nuovo plan e una directory di cattura distinta. Conservare i parziali
per la riconciliazione. Il cambio del solo inode del socket custodito è ammesso.

Dalla postazione di custodia scaricare manifest e cifrati, registrare l'impronta
del manifest tramite il canale operatore e confrontarla dopo ogni trasferimento.
Pubblicare gli asset nella release del repository privato d'installazione.
Per asset oltre il limite della release dividere il solo cifrato in parti numerate,
custodirne ordine e digest e ricomporlo byte per byte prima di verify.

```sh
set -eu
scp "$VPS:$REMOTE/manifest.json" "$COPY/"
scp "$VPS:$REMOTE/*.age" "$COPY/"
test "$(gh repo view "$PRIVATE_REPO" --json visibility -q .visibility)" = PRIVATE
gh release create "$TAG" -R "$PRIVATE_REPO" "$COPY/manifest.json" "$COPY/"*.age
gh release download "$TAG" -R "$PRIVATE_REPO" -D "$DOWNLOADED"
python -I -B scripts/capture.py verify "$DOWNLOADED"
python -I -B scripts/capture.py verify "$DOWNLOADED" --identity "$IDENTITY"
```

Il secondo comando verify è del custode, su Windows o Linux, con spazio privato per
il chiaro della famiglia più grande. Per un eseguibile fuori PATH aggiungere
`--age "$AGE"`. Custodire solo digest, conteggi, istanti ed esiti nel verbale.
Conservare 14 giornaliere, 3 mensili e sempre l'ultima verificata. Eliminare gli
asset scaduti per release. Dopo la doppia verifica della copia riscaricata, l'operatore
confronta tag, directory esatta e digest del manifest e cancella la sola copia
corrispondente sul VPS. Registrare byte liberati e ricevuta D-070.

## Ricostruzione sull'host di prova

L'operatore indica nel verbale commit, tag, versione del registro, baseline privata,
finestra della cattura e host isolato. Per ogni livello registra inizio e fine UTC,
durata, esito, evidenza e custode. L'RTO totale va dall'inizio del livello 1 al
completamento del livello 10. Un controllo fallito interrompe l'avanzamento.

| Livello | Operazione sull'host di prova | Verifica prima del livello successivo |
|---|---|---|
| 1. Host e reti | Predisporre host e DNS separati, bloccare default route verso esercizio, callback, servizi condivisi e writer. Installare versioni compatibili. Ripristinare rete, subnet, IPAM, configurazione Docker e proxy dal materiale privato. | Provare diniego verso le destinazioni d'esercizio e connessioni ammesse solo ai servizi di prova. Confrontare subnet, gateway e alias. Il VPS resta unico writer d'esercizio. |
| 2. Immagini | Recuperare le immagini pubblicate per digest e caricare i tar delle immagini locali verificate con docker load. | Confrontare ID, digest e architettura con l'inventario. |
| 3. PostgreSQL, etcd, storage | Preparare tablespace e cluster vuoto della stessa major. Importare il dump con psql e controllare gli errori. Verificare lo snapshot con etcdutl e ripristinarlo in una nuova directory con un token cluster nuovo. Provisionare backend e staging vuoti. | Confrontare database, owner, ruoli, privilegi e vincoli. Verificare salute del membro etcd e lettura/scrittura di un oggetto sintetico. |
| 4. IAM | Configurare realm, client, mapper e callback sul dominio di prova. Ruotare i segreti condivisi anche nei consumatori, invalidare sessioni/token precedenti. | Login con utente fixture, token nuovo, controllo issuer, subject, firma e audience. |
| 5. Gateway | Ripristinare configurazione locale e TLS per il dominio di prova. Collegare etcd e attivare il Gateway con upstream isolati. | Confrontare rotte, metodi, plugin e upstream con baseline privata dopo la sostituzione autorizzata degli endpoint. |
| 6. Moduli | Installare moduli e collegare i database ripristinati. Applicare migrazioni approvate e ordine di avvio con cancelli chiusi. | Confrontare schema, gate e readiness di ciascun modulo prima di aprire il cancello successivo. |
| 7. MCP | Installare l'immagine approvata, ripristinare binding e materiale persistente d'identità, collegare IAM e Gateway di prova. | Verificare readiness, catalogo, tool disponibili e diniego con credenziali invalide. |
| 8. Unità e timer | Ripristinare file, proprietari e modalità. Validare sudoers, verificare fragment, drop-in, guard Docker e puntatore prima del reload. Riattivare i timer solo dopo il controllo delle destinazioni. | Confrontare comandi effettivi, dipendenze, calendari e stato. Verificare il guard e il dispatcher secondo il runbook del kernel del lease. |
| 9. R3 nuova | Importare le ricevute storiche, ricomporre i binding con le identità vive e svolgere la cerimonia con chiavi generate sul nuovo host. Installare supervisore e autostart secondo l'owner. | Verificare firme, testa, WAITING, set e lease iniziali, poi ammissione e start governati. Provare il rifiuto del vecchio mandato. |
| 10. Accettazione | Eseguire ouf.system.status e un E2E CSV di fixture fino al grafo UDP locale. | Confrontare conteggi, lineage, URI e risultato di lettura. Registrare RTO e conferma di isolamento. |

Decrittare per il restore solo in una directory privata del custode o in streaming.
Verificare proprietari, destinazioni e symlink del tar dei file prima di ripristinare
singoli percorsi sotto una radice di staging. Associare ogni segreto al consumatore
prima dell'avvio. [Guard e dispatcher](OUF_SEMANTIC_LEASE_KERNEL_MIGRATION.md)

Sul secondo host il custode assegna `RESTORE` alla directory privata dei chiari
già verificati e `RTO_LOG` al verbale privato. Per ogni livello usa lo stesso orologio.

```sh
start=$(date +%s)
# Eseguire operazioni e verifica del livello selezionato.
end=$(date +%s)
printf '%s %s %s %s\n' "$LEVEL" "$start" "$end" "$((end-start))" >> "$RTO_LOG"
```

Al livello 2 caricare ogni tar locale e verificarne l'ID per confronto con la distinta.
Al livello 3 inizializzare il cluster con un ruolo di bootstrap distinto dai ruoli
da importare. Preparare i percorsi tablespace. Usare psql con interruzione al primo
errore, in un cluster dedicato vuoto, e un data-dir etcd nuovo.

```sh
docker image load --input "$RESTORE/$IMAGE_TAR"
docker image inspect --format '{{.Id}}' "$EXPECTED_IMAGE"
psql -X -v ON_ERROR_STOP=1 -U "$BOOTSTRAP_ROLE" -d postgres -f "$RESTORE/postgres.sql"
etcdutl snapshot status "$RESTORE/etcd.db" -w table
etcdutl snapshot restore "$RESTORE/etcd.db" --data-dir "$NEW_DATA" \
  --name "$MEMBER" --initial-cluster "$MEMBERS" --initial-cluster-token "$NEW_TOKEN" \
  --initial-advertise-peer-urls "$PEER"
```

Per i livelli 6–9 usare le procedure degli owner con profili e identità di prova.
[Riavvio e cancelli](OUF_PLATFORM_RESTART.md) ·
[Composizione ed emissione R3](OUF_SEMANTIC_PROVIDER_R3_COMPOSE_AND_ISSUE.md) ·
[Autostart R3](OUF_SEMANTIC_PROVIDER_R3_AUTOSTART.md)

## Prova generale dei rilasci privilegiati

Nel perimetro isolato installare esecutore, profilo privato, sudoers e un runner
registrato per la prova. Riprodurre il manifest del bootstrap, verificare il
rifiuto di un commit differente, poi selezionare uno ZIP di modulo con pin CI.
Eseguire plan, approvazione, apply al cancello e readiness. Eseguire il ritorno
governato e confrontare CID, immagine, journal e stato applicativo con il predecessore
di prova. Acquisire i digest delle ricevute e verificare di nuovo la fixture E2E.
[Esecutore privilegiato](OUF_PRIVILEGED_PIPELINE.md) · [Rilascio dei moduli](OUF_MODULE_RELEASE.md)

## PET A5 / D-082

| ID | Dove | Evidenza per R-041 |
|---|---|---|
| A5-REG | CI ospitata, test_configuration_register | Grafo del registro, destinazioni degli installer, unità e schemi. |
| A5-CAP | CI ospitata, test_capture | Host finto, drift, pin, soglie, interruzioni e ripresa per famiglia. |
| A5-VERIFY | CI ospitata, test_capture | Alterazione, famiglia mancante, strutture e coppia age generata nel test. |
| A5-FIRST | Prima cattura in esercizio | Distinta riconciliata, spazio, manifest e doppia verifica della release riscaricata. |
| A5-REBUILD | Secondo host isolato | Dieci livelli con RTO, login, catena nuova, rilascio con ritorno ed E2E di fixture. |

R-041 resta aperto fino alla prova sul secondo host. Dati degli oggetti e copie
di lavoro sono sacrificabili. Sessioni e token si rigenerano, l'autorità R3 si riemette.
