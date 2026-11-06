# Preparazione locale dei binding e delle connessioni G0

Giovanni ha chiesto di proseguire senza attendere la ricognizione del backup esterno. Questa indicazione consente di avanzare nella preparazione; non prova DR, backup indipendente, G0 chiuso o approvazione runtime. I percorsi dati/backup restano proposte; il preparatore non li crea.

## Due passi nello stesso comando locale

1. Verifica area già preparata, manifest del bundle9053aa38 e17ricevute; crea una sola bozza privata separata. Verifica il digest canonico del seed storico e ricava i13ID/immagini attesi. Boot e cinque generazioni di processo (MinIO, PostgreSQL, Onboarding, UDP, Ingestion) devono ancora coincidere. Crea il binding rete dei due provider. I13binding Docker completi restano candidati storici: non viene eseguito Docker inspect.
2. Legge al massimo quattro `/proc/PID/environ` da131072byte, con pin prima/dopo. Prepara tre connessioni PostgreSQL dalle variabili esplicite OUF_ONB/UDP/ING_DB_URL/USER/PASSWORD; URL deve corrispondere a un alias storico del PostgreSQL fissato, porta5432, senza credenziali/query ambigue. Non prova DNS o configurazione Spring effettiva: override noti sono trattenuti per review. Per MinIO riusa senza modifiche minio_input_observation/minio_credential_binding/custody_capture: precedenza env/file dichiarati, massimo5file/81920byte e nessun symlink. Nessun vecchio collector/launcher consumato viene invocato.

Le credenziali esistenti vengono copiate **solo** nella nuova bozza root0600; nessun valore o hash dei segreti viene stampato o pubblicato. Il riepilogo contiene conteggi e codici di mancanza. I permessi e i contenuti delle sorgenti restano invariati; leggerle non ne ammette la custodia. MinIO può aver cambiato credenziali senza restart: la copia locale non prova autenticazione riuscita.

## Output e limiti

Area: `/var/lib/ouf-g0-network-preparation-20261106/inputs/binding-draft-20261106`, root0700. File nuovi0600, creazione esclusiva e fsync. Bozza originale, pacchetto e17ricevute preservati. Ripetere il comando dopo un risultato legge soltanto quel risultato; non rilegge credenziali. Area parziale senza risultato: HOLD, nessuna pulizia/ripresa automatica. Budget cooperativo30s dopo claim; nessun ciclo provider/retry.

`package-input.review.json` rimane separato dall'input originale; network.review.json, runtime.review.json e provenance.private.json indicano esplicitamente cosa è osservato e cosa è storico/proposto. L'operationId è seaweedfs-g0-20261106-v1; installationRef ouf-retained-14e42ac9 è una correlazione locale alla coorte, **non identità IAM o autorità**. Il profilo Onboarding proposto è retained: richiede review dell'installazione; il collector qualificato nega schema incompatibile senza fallback o migrazione.

La directory evidence rimane vuota: nessun G0 collect o check viene eseguito. Il preparatore non apre Engine/S3/SQL, non entra nei namespace, non avvia container, non crea grant o volumi. Il backup esterno resta un requisito da documentare per l'accettazione e il passaggio operativo, non il motivo per fermare questa preparazione.

Restano espliciti nel JSON: review binding/immagini/mount correnti; configurazione applicativa effettiva e profilo retained; percorsi capacità e custodia; accessi/writer/finestra/backup; decisione raccolta separata. Campi DB/S3 o bucket mancanti/ambigui rimangono mancanti. Non chiedere di incollare password, passfile o file privati: soltanto result.json redatto.

## Verifica

14casi locali/CI dedicata: preparazione completa sintetica con resolver MinIO originale; segreti non presenti nel rapporto; passfile con escape corretto; modalità0600; nessuna directory dati/backup creata; risultato esistente senza nuova lettura; boot/processo mutati; ricevuta/seed alterati; URL DB estraneo; query credenziali; override Spring; symlink; bucket discordi; environment duplicato/troncato; area parziale conservata. Le letture processo sono iniettate nella fixture: **non nuova qualifica kernel, provider o dati reali**. Le prove native del bundle9053aa38 restano riutilizzate, non rilanciate.

Il pacchetto strumenti contiene solo sorgenti e manifesto, con tre dipendenze invariate verificate per SHA256. L'archivio e i test devono essere qualificati al commit esatto prima della consegna. MiniPET invariato39,78%,0/8gate,0/21AT,0/120oggetti reali.
