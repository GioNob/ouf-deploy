# Obiettivo di industrializzazione e criteri di consegna

Decisione dell'owner, 10 ottobre 2026, 15:29 Europe/Rome: il risultato richiesto è un sistema facilmente installabile, aggiornabile e recuperabile senza interventi manuali ordinari nel VPS. I launcher puntuali attuali sono preparazione e recupero dell'installazione esistente; non costituiscono il prodotto finale.

## Percorso da consegnare

Un pacchetto di release versionato deve contenere gli artefatti firmati, le identità dei build, le migrazioni, i contratti applicativi e i programmi di installazione qualificati. Un profilo di installazione separato deve fornire domini, rete, storage, issuer/audience e riferimenti ai segreti, senza incorporare password o chiavi nel repository. UID, mount e policy devono essere coerenti con il profilo qualificato e verificati sul target.

Un solo ingresso operativo deve orchestrare preflight, preparazione, piano revisionabile, apply autorizzato, verifica e recupero. Il passaggio privilegiato va predisposto nel bootstrap iniziale con un helper ristretto e autenticato, senza sudo generale e senza usare Docker per aggirare i controlli host. La password sudo ripetuta a ogni fase della sperimentazione non è il modello operativo finale.

I percorsi temporanei, container ID, PID, ifindex e hash degli snapshot attuali restano evidenze dell'installazione migrata. Non diventano costanti valide per ogni installazione: il sistema deve derivare binding nuovi e autenticarli per la generazione corrente. L'installer deve distinguere una nuova installazione da una migrazione di una preesistente.

La sequenza deve avere stato persistente e ricevute per ogni fase. Le letture sono ripetibili; le mutazioni già consumate non vengono rieseguite: una ripresa verifica il risultato custodito oppure produce una nuova transizione governata. Un errore deve lasciare un esito esplicito e recuperabile, con accessi di rete fail-closed. Non si introducono retry/restart che ricreano implicitamente autorità.

## Criteri di accettazione dell'installer

| Prova | Risultato richiesto |
| --- | --- |
| Host pulito del profilo supportato | Installazione dal solo pacchetto e profilo documentati; nessuna modifica manuale a file, container o firewall |
| Seconda installazione indipendente | Stesso comportamento da stessi input; nuovi binding locali, nessuna dipendenza dai percorsi o ID di questo VPS |
| Ripetizione del comando | No-op verificato oppure ripresa esplicita; nessun replay dei claim consumati |
| Upgrade N→N+1 | Backup fresco e writer fencing, compatibilità/migrazione e readiness verificati |
| Guasto durante una fase | Arresto sicuro, diagnosi e ripresa/recupero qualificati; nessun restore che cancella scritture successive |
| Reboot e generazioni ricreate | Policy di avvio verificata, binding correnti, nessun riarmo automatico dell'autorità R9 consumata |
| Percorso applicativo reale | Route e grant correnti verificati, provider reale, Cinema preservato e discovery nazionale senza fallback locale |
| Operatore | Un comando o pipeline documentata; interventi umani limitati a bootstrap/segreti e decisioni protette previste dai PET |

Il punto d'ingresso unico e queste prove non sono ancora consegnati. Il supporto iniziale sarà quello esplicitamente qualificato; non si promette portabilità arbitraria su ogni cloud o sistema operativo.

## Stato e prossima sequenza

Sul VPS sono preparati gli input runtime, il truststore Java pubblico e il contratto applicativo che corrisponde al binding provider originale. Il contratto distingue provider workload ouf-semantic da caller discovery ouf-mcp-server e lega tre mount read-only alle identità di ruolo. Non sono ancora provati complete OCI del nuovo container, binding reciproco/transport firmato, applicatore coordinato e cutover/readiness. I bytes dei segreti e le generazioni devono essere verificati privatamente nell'apply.

La priorità è completare l'applicatore della combinazione candidata, insieme alla sua macchina di stato e ai confini di privilegio, quindi rendere pacchetto/profilo e orchestrazione riusabili. Ogni incremento corrente va ricondotto a questo percorso e non lasciato come procedura manuale indispensabile. La migrazione dell'installazione esistente è una prova necessaria; la prova indipendente su host pulito è una distinta condizione di industrializzazione.

## Coerenza PET

Restano applicabili Matrix1.7, Blueprint0.3 e i sette PET indicati nella [riconciliazione](PET_ROADMAP_RECONCILIATION_20261010.md). Authorization valuta; owner applicano; Gateway media; MCP proietta capability; THS conserva le decisioni HUMAN. L'automazione dell'installazione non concede adozione/pubblicazione semantica o grant applicativi per effetto della delega tecnica in chat.

Supply chain, custodia, network default deny, audit, migration/recovery e readiness entrano nei gate dell'installer. R5 resta parziale e R6 aperto; i gap di dominio/OA/HA/load/DR e i blocchi Ingestion/storage non sono risolti da questa decisione. I23 gap originali conservano il proprio stato. Cinema e asset/profilo Teatri sono preservati.


## Verticale file → semantica → ingestion → UDP → search, 10 ottobre15:42

La [roadmap dettagliata F0–F11](https://github.com/GioNob/ouf-semantic-registry/blob/a315de5b33a6d9074a04bcbbbca224efd0c4c135/docs/FILE_TO_SEARCH_ROADMAP_20261010.md) esplicita owner, dipendenze e gate del giro richiesto dall'owner. L'identità richiede natura semantica compatibile e evidenze sufficienti; relazioni tra nature diverse, target tardivi e navigazione inversa sono gestiti separatamente. La prima prova file-to-search e la prova multi-fonte precedono l'accettazione su host pulito, mentre il disegno dell'installer procede insieme all'applicatore. I claim consumati, i23 gap PET e Cinema/Teatri sono preservati. La presenza di filtri/riconciliazione nel codice non è accettazione del target; CI Ingestion/UDP rosse e cutover incompleto restano gate espliciti.

## 11 October: composed checkpoint executor, not a qualified target installer

The target native V11 declaration/request is now prepared: [target receipt](../evidence/native-v11-plan-prepared-target-20261011.json). The new [Executor](../tools/semantic_application_cutover/cutover_executor.py) composes all13 ordered phase intents, finite current externally verified authority and bound native checkpoints with the existing durable Transition journal. Crash after each phase is reconciled without retransmission; ambiguity/no-effect stop progression; completion never grants release acceptance. Its stopped [CreationAdapter](../tools/semantic_application_cutover/creation_adapter.py) uses the bounded Engine while Executor owns the intent, avoiding duplicate claim ownership.

[CI38176804114](https://github.com/GioNob/ouf-deploy/actions/runs/38176804114), job114580802467 SUCCESS:39 unit tests plus original8-subject signed package/containerd native proof. The original Semantic image is really created by its exact native manifest, killed after create, reopened and reconciled through Executor without a duplicate; no JVM is started. External authority and preceding phases in this fixture are synthetic. Target stop/fence/backup/complete OCI/signed transport/distinct worker/migration/application readiness adapter wiring and its authenticated root entrypoint remain OPEN. The generic executor is not the target installer; no source-bound transition authority is issued by it.

[Atomic private review publication](NATIVE_V11_ATOMIC_REVIEW_20261011.md) is qualified separately and is the next root operation. It binds all four prepared files in one immutable no-replace directory, with crash/race checks, without promoting historical observations to runtime authority. Existing R12/import claims, budgets and all original private bytes remain retained. A hash/snapshot alone cannot satisfy HUMAN/THS, crypto, full OCI/peer, writer fencing or producer readiness gates.
