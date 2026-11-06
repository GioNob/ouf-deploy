# Continuazione privata dei tre input PostgreSQL G0

La diagnosi operatore al22554a8f ha individuato i canali che fermano le bozze: JSON per Onboarding/UDP, additional location per Onboarding/Ingestion. Non sono variabili SPRING_DATASOURCE duplicate. Le configurazioni aggiuntive sono una fattispecie già gestita da tools/chatbot_file_cohort/preparation.py: riusare quelle regole, non interpretare la presenza come errore e non rimuovere il guard alla cieca.

## Perimetro

Il launcher riceve solo tre sorgenti pubblici immutabili, verificati per SHA256 prima dell'esecuzione root: questa continuazione, review-storage-g0-datasource-20261106.py invariato e preparation.py al22554a8f. Da quest'ultimo estrae con AST esattamente validate_json_overlay e ingestion_properties; nessun import del modulo operativo, Engine, SQL o vecchio entrypoint. Il reader file è InputBinding già qualificato/installato nel bundle6c9de. I suoi controlli regolare/no symlink/limiti/stabilità restano intatti; una preflight separata seleziona una sola configurazione nota per processo.

Selezioni ammesse dalla procedura già esistente: file:/run/secrets/onboarding-ths.yaml, contenuto JSON; file:/run/secrets/ingestion-summary.properties, anche prefisso optional:, contenuto properties letterale senza escape/interpolazioni. Il file opzionale deve comunque essere presente per questa preparazione. Il seed storico verificato deve dichiarare il bind RO noto, ma questo non dimostra il mount corrente: i byte vengono letti dalla vista /proc/PID/root corrente, non dal percorso host storico. Nessuna ricerca di directory o fallback. Sorgenti config possono contenere segreti OAuth/token, restano in memoria, nessun valore o hash viene pubblicato.

Controlli conservati: niente datasource/Flyway/import/profili/OUF_DB negli overlay; niente selector aggiuntivo sconosciuto; confronto della forma dei canali con la diagnosi precedente; cmdline e quattro canali JVM inclusa _JAVA_OPTIONS senza override protetti. Il JSON aggiunge diniego di duplicati canonici/nonfinite/array complessi. Restano intatti URL/host/porta/query/password checks di g0_input_draft.db_connection: soltanto i due canali già ispezionati vengono tolti dalla sua proiezione di input. Questo è un gate della preparazione, non una prova di risoluzione completa Spring o ammissione SQL.

## Effetti e budget

Richiede staging e vecchi risultati custoditi, identità operazione/installazione del config S3. Nuovo scope root0700 inputs/database-draft-continuation-20261106; claim/result e tre passfile/config root0600 con creazione esclusiva/fsync. Claim prima di seed/environment/config: massimo1tentativo,30secondi cooperativi,3environment da128KiB,3cmdline da64KiB,2config da64KiB,3scritture password. Boot/cinquegenerazioni e stabilità file vengono ricontrollati. Le17ricevute e gli input originari vengono verificati prima delle scritture.

Tutti e tre i ruoli devono superare l'ispezione prima di copiare una password. Scrittura interrotta può lasciare file privati: conteggi tentativi/successi e credentialsMayBePresentInDraft lo dichiarano. Scope parziale senza risultato resta HELD; ripetere con risultato lo legge soltanto. Nessuna pulizia/replay automatico. La nuova package-input.review.json punta ai tre nuovi DB e conserva S3/rete/runtime; l'originale non viene modificato. S3.json viene letto come metadato di connessione; access key e secret S3 non vengono aperti.

Esito atteso DATABASE_CONNECTION_DRAFTS_PREPARED_REVIEW_REQUIRED: quattro bozze di connessione presenti, **non check G0 passato**. Configurazione effettiva, immagine/mount correnti, profilo retained Onboarding, custodia delle sorgenti, capacità, writer/accessi/finestra e decisione di raccolta rimangono aperti. Non viene invocato check o collect. Nessun servizio avviato, deploy, SQL, Engine, S3 o grant.

## Verifica

14casi locali; workflow dedicato storage-g0-database-continuation.yml esegue gli stessi14casi. Reader originale usato su file temporanei, processo/boot/env/cmdline iniettati: non nuova qualifica kernel/provider né operazione target. Riuso dei due validator esatti protetto dal digest completo del sorgente Git. Receipt locale evidence/storage-g0-db-continuation-local-20261106.json; qualifica CI e commit esatto nella PR54. MiniPET39,78%,0/8gate,0/21AT,0/120oggetti reali invariati. Backup esterno rimane non provato per accettazione/passaggio operativo, non un prerequisito riaperto per questa preparazione.
