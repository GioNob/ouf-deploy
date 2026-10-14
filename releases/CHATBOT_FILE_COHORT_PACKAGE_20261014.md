# Unico pacchetto del percorso chatbot/file

Il workflow `semantic-proposal-candidate-package.yml` legge esclusivamente `chatbot-file-cohort-20261014.json`: sei commit interi, senza branch mobili e senza riusare i tre pacchetti staged del run38508140057. I pin si aggiornano qui quando viene qualificata una nuova modifica funzionale.

Costruisce cinque immagini non-root (Semantic Registry, Onboarding, Ingestion, UDP e MCP) congelando i digest delle basi Docker. Esporta ogni immagine effettiva, il JAR o il binario estratto dalla stessa immagine, il sorgente e l'inventario Git. Gateway include il sorgente e39 rotte concrete materializzate dagli stessi generatori di produzione con la proiezione fixture conservata: il file è esplicitamente non vincolato al target e non va applicato direttamente al VPS.

Trivy respinge HIGH, CRITICAL e UNKNOWN, anche senza fix disponibile; scansione legata all'imageId e copertura OS+JAR/Go. Gateway controlla le dipendenze Python dichiarate, senza affermare la qualificazione del runtime Python transitivo.

Prima di Java il job Semantic calcola un rootfs seal indipendente su container CI fermo al gate. Poi avvia la stessa immagine con PostgreSQL e quattro mount sintetici: directory token rinnovabile, chiave consultation, configtree database, chiave proposal distinta. Provider e discovery sono entrambi disabilitati. Questa verifica prova il boot della nuova immagine e le migrazioni V1–V10; non prova ammissione token, TLS IAM del target o accettazione frame/custodia. Un truststore aggiuntivo serve soltanto se la CA IAM reale non è già riconosciuta dalla JVM, da verificare sul target.

Il job finale rifiuta parti mancanti, SHA di sorgente superati, lock diversi, link e file non dichiarati. Pubblica **un solo artefatto** `chatbot-file-cohort-<runId>` con `cohort-manifest.json`, i sei moduli, `COHORT_SHA256SUMS` e la firma keyless del publisher sui checksum. Questa provenienza non concede autorità di installazione.

Il comando di consegna usa lo script dello stesso commit produttore, scegliendo il gh portabile già presente prima di PATH:

```bash
python3 scripts/download-file-cohort.py --run RUN_VERIFICATO --producer-commit SHA_PRODUTTORE_VERIFICATO --output "$HOME/ouf-chatbot-file-cohort-RUN_VERIFICATO"
```

Il launcher finale deve sostituire run e commit soltanto dopo il successo di tutti i sei job e dell'assemblaggio. Lo script controlla run, workflow, commit, digest GitHub dell'archivio, tutti i membri e i sei pin; conserva la firma del publisher. Non estrae, esegue, carica immagini né modifica servizi. L'installazione deve legare questi stessi hash alla transazione e alle autorità pertinenti: il vecchio executor Semantic non installa implicitamente gli altri cinque moduli.

La coorte sorgente congelata include il test composto Ingestion `98e33a16839e9253b37bf74f37e77cc20dc938e7`, run `38534861649`, passato con i quattro owner riportati nel lock. La prova usa i moduli reali in ambiente disposable e fixture di identità/Gateway esplicite; non è una prova di installazione o di accettazione sul VPS. Il bundle contiene anche le dichiarazioni JSON Gateway compilate e verificate: il prepare target può materializzare le 43 rotte con la source qualificata usando solo la libreria standard Python.

## Variante qualificata per la cronologia MCP del VPS

Il pacchetto completo corrente del percorso target è il run `38584614991`,
tentativo 2, commit produttore `8bff54a52a0ce15daccaf2aee932004f106dd178`.
Artefatto `11907557440`, 1.708.479.761 byte, SHA256
`144699ab7756c8312d49783967cfbb64acc02a617015ad89f5adf51e25a10300`.
Tutti gli otto job sono SUCCESS. Il pin MCP è la variante PR69
`f249b3dcc58c2a96742092d90fa09fd90b705bd0`; gli altri cinque restano invariati.

Il launcher di consegna PR29 al commit
`f9b42b8cd4358a908c7a0e88777f9e55b8400258` seleziona questo archivio e la
capsula sorgenti `126e49f3830667934bf8f8d7a5b3bb096fd4982fa0ad0014b11b862984155da9`.
Il vecchio archivio è storico e non è intercambiabile con questa consegna.
L’estrattore dell’installatore verifica anche i tre source archive MCP,
Onboarding e Gateway in CI disposable. Publisher e test CI non concedono
permessi di installazione né decisioni applicative HUMAN.

La consegna operatore è [chatbot-file-cohort-vps-20261014.sh](chatbot-file-cohort-vps-20261014.sh).
Verifica il client GitHub già presente, scarica il launcher da commit immutabile,
controlla SHA256 e avvia la preparazione privata esistente. Login, osservazioni
correnti e revisione completa restano al terminale dell’operatore; non inserire
credenziali o contenuti della revisione privata in GitHub o in chat.
L’azione effettiva richiede l’approvazione dell’hash generato sul VPS e conserva
il limite di un’ora, i budget, lo storico e i journal monouso. Le approvazioni
semantiche e delle sorgenti rimangono nel THS. Questo comando non costituisce
accettazione target o servizio permanente.
