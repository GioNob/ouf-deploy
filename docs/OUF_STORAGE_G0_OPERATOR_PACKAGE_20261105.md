# Pacchetto unico G0 — consegna per l'operatore

## Scopo e stato

Un solo pacchetto collega le otto sezioni G0: runtime, oggetti, accessi, writer, DB, capacità, custodia e finestra. Contiene il collector Go, i moduli Python qualificati e il nuovo coordinatore con osservazione host. È una raccolta read-only con scritture delle sole evidenze locali. **Non è il comando di migrazione e non concede autorità runtime.** I binding privati dell'installazione devono essere compilati e la raccolta deve seguire il percorso operativo approvato. La presenza di un collectionDecisionRef documenta un riferimento: il programma non ne autentica l'autore e non emette una conferma HUMAN.

Il comando `check` legge soltanto i file locali di input e il pacchetto; non apre Docker/S3/PostgreSQL e non consuma lo scope. Il comando `collect` riserva un tentativo comune, osserva host/capacità, richiama una sola raccolta S3 e un solo export per ciascuno dei tre owner, riconcilia e osserva nuovamente l'host. Conserva successi parziali e dinieghi; nessun retry, grant, chmod di credenziali esistenti, start/stop/exec di container, migrazione SQL, PUT/DELETE S3, cambio di endpoint dei servizi o riapertura del traffico.

Il canale ChatGPT disponibile espone capabilities OUF governate e GitHub; non espone l'accesso host, S3 o SQL richiesto dal pacchetto. Non si ricavano credenziali dal plugin, non si propone un grant per aggirare questo limite. Serve il canale operatore del VPS per i file privati e per l'esecuzione ammessa.

## Input privati da compilare una volta

Il bundle contiene `input-template.json`, deliberatamente incompleto: null non è un valore operativo. Copiarlo nell'area privata dell'installazione e compilare:

| Campo | Input necessario | Provenienza |
|---|---|---|
| operationId / installationRef | Nuova identità monouso e installazione esatta | Percorso operativo, nessun riuso13–17 |
| roles | I13ruoli elencati nel template, ciascuno con containerId64hex e nativeImage sha256 | Binding corrente verificato dall'operatore; non copiare automaticamente gli ID storici |
| capacityPaths | Directory esistenti per sorgente, destinazione prevista e backup | Mount effettivi; il collector non crea o ammette volumi |
| connectionFiles | File0600 S3 e tre DB per gli owner effettivi | Credenziali già custodite e privilegi già applicabili |
| operatorEvidenceFiles.runtime | Dichiarazione con storageBuckets onboarding/udp | Bucket effettivi dei due owner, obbligatori prima di qualsiasi lettura target |
| priorReceiptFiles | I17file ricevuta già consumati, con path privato e SHA256 | Archivio storico locale, senza rieseguire launcher |
| outputParent | Directory privata esistente, distinta dagli scope/input precedenti | Custodia operatore; nuovo sottoscope operationId |
| collectionDecisionRef | Riferimento alla decisione applicabile alla raccolta esatta | Approvazione separata, non delega di sviluppo |

Ogni connectionFile deve avere installationRef identico e operationId uguale a `<operationId>-s3`, `-onboarding`, `-udp` o `-ingestion`. La struttura dei file S3 e DB è documentata nel dossier `OUF_STORAGE_G0_COLLECTORS_20261105.md`; i moduli nel pacchetto sono identici alle versioni qualificate. Onboarding deve selezionare esplicitamente `onboarding-retained` oppure `onboarding`; il source-lock candidato non attesta cosa è installato. Credenziali da file privati0600 del medesimo utente che esegue il collector, non da argv. Il passfile PostgreSQL è quello libpq. Nessuna correzione automatica dei permessi. Accesso al socket Docker `/run/docker.sock` già consentito all'operatore; host Linux con Python3 e psql disponibili. Binary Go linux/amd64 incluso. Il coordinatore usa la rete del processo operatore: non entra automaticamente nei namespace Docker. Gli endpoint devono essere già raggiungibili da quel contesto con il profilo TLS/loopback ammesso. Il vecchio launcher usava nsenter; non si assume che i suoi indirizzi loopback siano riutilizzabili sulla rete host. Se occorre un ingresso nei namespace, il binding e quel percorso devono essere qualificati prima della raccolta, senza pubblicare nuove porte o cambiare i servizi per aggirare il limite.

Per gli altri documenti operatorEvidenceFiles può essere null: la raccolta conserva MISSING_OPERATOR_EVIDENCE e G0 rimane aperto. Schema per runtime/access/capacity/custody/window: `ouf.storage-g0-operator-evidence.v1`, installationRef, section maiuscola, provenance (`OPERATOR_DECLARATION` oppure `TECHNICAL_OBSERVATION`), ownerRef, capturedAt ed evidenceRefs non vuoti. `runtime` aggiunge `storageBuckets`. Le etichette sono dichiarazioni di provenienza da autenticare nella review, non attestazioni emesse dal collector.

Il documento writer usa `ouf.storage-g0-writer-census.v1` con gli11percorsi del dossier precedente. Per ogni percorso: presenza, owner, binding, attività/queue/intenti, drain/fence e riferimenti alle prove; separare osservazione tecnica e dichiarazione. MISSING/UNKNOWN non equivale ad ABSENT. Includere manutenzione, bootstrap, amministratori, backup con effetti e consumer esterni: i soli container non provano la loro assenza.

Il documento WINDOW deve portare alla review la finestra di manutenzione, il criterio concreto di quiescenza, responsabile HOLD/recupero, RPO cutover0 e valori numerici approvati per RPO/RTO disaster e RTO migrazione. Il documento CAPACITY deve collegare crescita, throughput rappresentativo, riserva di spazio e domini di guasto indipendenti. CUSTODY collega custodia di credenziali, backup/configurazioni/chiavi e immagine esatta. ACCESS collega ACL/owner/grantee, policy effettive, identità e controllo equivalente quando publicAccessBlock è UNSUPPORTED. Questi requisiti di review non sono soddisfatti dalla sola validità JSON.

## Verifica e comando da sottoporre al gate

La ricevuta pubblica di consegna riporta SHA256 e dimensione di `operator-package.tar.gz` e SHA256 di `package-manifest.json`. Verificare l'archivio esatto prima di estrarre il contenuto in una nuova directory custodita; confrontare le fonti e la provenienza con il commit e il run indicati nella ricevuta. Il manifest copre tutti i file del bundle, incluso l'eseguibile; file aggiunti o alterati fanno fallire il check.

Comando locale di preparazione, con percorsi e digest effettivi della consegna:

```sh
python3 -I -B -S /percorso/pacchetto/launch.py check /area/privata/package-input.json --package-sha256 DIGEST_DEL_MANIFEST
```

Restituisce input e digest vincolati, limiti, documenti mancanti e `targetCommandAuthorized:false`. Non stampa password, chiavi degli oggetti, righe DB o percorsi privati. Il JSON di input e il riferimento alla decisione non sostituiscono la verifica dell'identità o dell'autorità richiesta dal progetto.

Solo dopo review dei binding/digest, custodia e decisione esplicita applicabile, il comando concreto da autorizzare usa gli stessi argomenti con `collect` al posto di `check`. **Questa consegna non chiede ancora di eseguirlo:** gli input target e il canale operatore non sono disponibili alla chat. Nessuna autorizzazione può essere dedotta dall'esempio o dal ruolo ouf-admin.

L'esito pubblico è `result.json`. Le evidenze complete restano nel nuovo scope privato. Per la review successiva condividere il solo risultato redatto e i digest tramite il canale governato; non caricare archivio DB/inventari/credenziali in chat o Git. Dopo errore/crash, conservare lo scope: non cancellarlo, rinominarlo, cambiare operationId o creare nuove sessioni per riottenere il budget. Una ripresa richiede riconciliazione e decisione separata.

## Limiti e budget complessivo

Un tentativo,900secondi complessivi, fino a130GET Docker e32MiB di risposte host; due osservazioni, al massimo64container ciascuna. Le richieste sono riservate su disco prima dell'invio. Contatori storici17controlli/52GET preservati come checkpoint di partenza; non è stato assegnato o eseguito un nuovo controllo target. La raccolta verifica i digest dei17file precedenti prima e dopo e non li modifica.

S3 eredita3000richieste/300s,256oggetti,16MiB per oggetto,64MiB di corpi/128MiB wire. DB: tre export, ciascuno120s/32MiB,10000righe per sezione, una transazione READ ONLY REPEATABLE READ; nessuna query arbitraria. Gli input di connessione vengono congelati nello scope prima dei figli. I risultati vengono legati a input/installationRef/operationId e all'endpoint/database/ruolo effettivamente riportati da PostgreSQL.

Le osservazioni host conservano ID, immagine nativa, PID/avvio/stato, mount e binding storage ammessi. I valori delle altre variabili ambiente vengono esclusi; endpoint con credenziali incorporate vengono respinti. Sono inclusi anche container fuori dai13binding, senza inferirne natura o autorizzazione. Stato stopped non viene trattato come autorizzazione a riavviare. Revisioni dichiarate e ID immagine non provano appartenenza dei byte rootfs al sorgente.

La capacità misura filesystem e memoria correnti; stesso/differente st_dev non prova indipendenza di guasto o capacità sufficiente. La classificazione ACL distingue owner, grantee non-owner e gruppi ampi e conserva i risultati policy/publicAccessBlock. Non è un interprete completo delle policy IAM né un controllo equivalente automaticamente approvato.

Un risultato completo delle osservazioni resta `g0Complete:false`, `runtimeAuthorityIssued:false`, `acceptanceCreditAdded:0`: snapshot separati, writer non necessariamente fermi, provenienza dei documenti operatore ancora da autenticare. Riferimenti fuori profilo/manifest slice/shadow lifecycle mantengono i dinieghi del reconciler. G0 si chiude tramite la review dell'inventario reale completo, non tramite questo flag locale.

## Qualifica senza ripetere i laboratori precedenti

I moduli S3 e DB/join sono vincolati byte per byte al profilo `storage-g0-package-profile-20261105.json`; le prove native42111278483 e42114275442 vengono riusate. Nuovi controlli:13test di orchestrazione/preflight, incluso percorso completo con provider sostituiti nella fixture; osservazione Docker nativa di un container creato e mai avviato, redazione, negazione di un percorso mutativo prima della richiesta e osservazione capacità. Il nuovo binario viene ricompilato da sorgenti invariati con Go1.27.3, buildvcs=false/trimpath, scansionato e avviato soltanto per uno smoke di diniego senza config. Non è un secondo laboratorio completo S3+DB e non qualifica il target.

Il pacchetto non installa un verificatore HUMAN/THS, endpoint o servizio. Attestazione CI e digest permettono la review della consegna; custodia durevole e gate operativo sono separati. La ricevuta finale nel repository riporta commit, run, artifact, dimensioni, digest e risultato del readback indipendente.
