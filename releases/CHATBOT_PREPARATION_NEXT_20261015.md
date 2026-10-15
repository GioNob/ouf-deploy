# Current finding: published image identity differs under containerd (2026-10-15)

The operator completed pure archive validation: all five retained tagless files exactly match their approved audits. Semantic is still IN_FLIGHT/attempt 1, all other images READY/attempt 0, expected image IDs return 404, no later-stage recovery journals exist. No automatic repeat is permitted.

A disposable two-store CI reproducer on source `7464582615d285999a56518c355ed6cbf5e81f74` downloaded the exact existing semantic artifact 11907831957 from producer run 38584614991, rederived the same 390021120-byte tagless archive (SHA256 `9f1961025f0e55d7a12e7f3f6df5c5fe0980ff4cad730086262bedecdaf6a357`), and ran the existing Import owner and real Docker load stream. Run https://github.com/GioNob/ouf-deploy/actions/runs/38700933784 has one PASS/classic and one expected reproduced failure/containerd:

- Classic overlay2, Docker 28.0.4, job 116308656259: load succeeds as original configuration ID `sha256:29e32c1487b5ba29d6d29ec04f7daa3baeb1e30f392a46c838eef01493d60489`; native custody verification passes.
- Containerd overlayfs, Docker 28.0.4, job 116308655931: load exits 0 with native ID `sha256:b61bc39c1593c28404a8258962008c024d13689d7e9b132e6a85619580003ca3`. Looking up the original config ID is 404; existing Import.verify raises ValueError `IMPORT_ABSENCE_DOES_NOT_PROVE_NO_EFFECT`. Its journal remains IN_FLIGHT/attempt 1. Rootfs matches. Full raw Config equality is false; selected execution fields have not yet been inspected on target. Do not claim this tested VPS Docker 29.8.1 or that raw native Config equals the archive Config.

This closes the reproduction gap, not the deployment. Earlier image-import tests used tiny fixtures; the exact-image TLS/frame test loaded the original archive. Neither exercised these exact derived bytes with the containerd store. No application code, image, target service or database was changed by the new CI. The new branch is diagnosis only; it must not be used as a deploy source.

The next necessary operator action is read-only `scripts/read-chatbot-native-image-identity-20261015.py`, SHA256 `cc9aa1b3bc2cda61ce476f7de0a7483b53efcd00028c78372b025ef6be3ee075`. It is bound to dd03/authority48c7/sourceb646 and lists images by exact source revision, then compares rootfs and execution fields against the sealed audits. It emits identifiers, approved archive hashes, comparison booleans and mismatching field names/types, never raw config/environment. Ten local tests pass; native HTTP transport is mocked locally. No import, restart, IAM login, authority renewal or DB write. Target proof is pending; preserve old consumed claims and keep the execute wrapper suspended.

The product correction must bind both published config-byte identity and exact native image identity throughout import, plan/creation and realized validation; retain strict config/rootfs checks and the unchanged six-module package pins. Fixing only the failed GET or accepting any source-labelled image is insufficient. Recovery must reconcile the image already loaded under its native ID before any further import; old auth-only predecessor gate deliberately does not cover this image-stage attempt.

See `evidence/chatbot-containerd-image-identity-diagnosis-20261015.json` and the full small CI report `evidence/chatbot-containerd-tagless-ci-report-20261015.json`. CSV/chatbot acceptance remains unproven.

---

## Previous handoff (historical)

# Current target readback: first image attempt unresolved (2026-10-15, 09:33 CEST)

The pinned target readback completed. The dd03 finite process is inactive/MainPID 0. Its authority binding matches. Semantic image journal is IN_FLIGHT/version 1/effectAttemptCount 1; the exact image GET is 404. UDP, onboarding, ingestion and MCP remain READY/version 0/attempt 0 and their images are absent too. No recovery.json exists for containers/databases/gateway/gatewayRuntime. These facts narrow the stop to the first image import; image absence alone does not reconcile its consumed claim. Systemd Result=success is not deployment success.

**Do not repeat the execute command.** The exact ValueError body was redacted by the running source. The next diagnostic is `scripts/read-chatbot-image-archives-20261015.py`, SHA256 `938b73013d3de2c4ebfeebe5da1b9017fe27d3665933a1776df4d50bbb0ede86`. It preserves the previous readback and additionally executes only the pure archive validator from the retained approved bundle, after checking its exact known source SHA256 `d118924b52618f00871ccd4ae9ade379ccb818ce517e34e31d815fe5abdfdd23`. It opens the five approved archives read-only, verifies bytes/layers/config against their reviewed audits and prints only safe error codes or mismatch field names. It never imports the delivery bootstrap or load callback. Import requests, service changes, database changes and authority renewal remain zero. Some disk reading is expected, with an ARCHIVE_READ_BEGIN progress line before each image.

Thirteen local tests pass, including real synthetic compressed archive parsing, serialized audit equality, changed archive denial, pinned source rejection, safe output, and complete context read preserving files. Engine transport uses mocks in local tests; native Docker integration is not claimed for this diagnostic. Target archive verification is pending; no product patch is inferred from unobserved archive results. See `evidence/chatbot-image-journals-readback-20261015.json`.

---

## Previous handoff (historical)

# Current stop: image-import reconciliation required (2026-10-15, 09:25 CEST)

The latest VPS attempt accepted the fresh HUMAN decision and reconciled the expired auth-only predecessor successfully. It then reached `IMPORTING_QUALIFIED_IMAGES_BEFORE_FIRST_GRANT` and stopped with `PAUSED_REQUIRES_RECONCILIATION`, reason `ValueError`. Image effects remain unknown. Do not run the previous execute wrapper again: its predecessor gate only covers auth-only history, not this new image-import attempt.

Run only `scripts/read-chatbot-image-import-20261015.py` from the new evidence commit, hash `28597621dcb87444e6248e12266ec0529ba77ce11808d986ce0a2b00c0291fe4`. It is pinned to the exact failed dd03 context, authenticates its authority/bundle/prepared bindings, reads five image journals, and makes at most five image-inspection GET requests. It does not load images, start/restart services, write DBs, refresh IAM sessions, or renew authority. Output includes only journal states, exact comparison booleans and names/types of mismatching image-config fields; no raw configuration/environment.

Nine local tests passed, including a complete synthetic retained-context read that preserves all files. Engine request method is verified with mocks; native Unix sockets were unavailable in the current sandbox (EPERM). Target readback is pending. The exact inner cause is still unknown; CSV chatbot end-to-end remains unproven. See `evidence/chatbot-image-import-paused-20261015.json`.

---

## Previous handoff (historical, execution instructions suspended)

# OUF — ripresa revisionata del ciclo CSV, 15 ottobre 2026

## Riferimento corrente

Usare soltanto il wrapper [chatbot-file-cohort-reconcile-execute-vps-20261015.sh](chatbot-file-cohort-reconcile-execute-vps-20261015.sh) di questa revisione. I precedenti wrapper di esecuzione restano documenti storici e non vanno rilanciati. Il ramo di queste evidenze contiene sorgenti applicativi storici: il wrapper scarica esplicitamente il sorgente qualificato dalla PR31, non esegue il prodotto da questo ramo.

- Sorgente eseguibile: **b64645982655f58a2907bf1425dd86fd6ab0ed9f**.
- Wrapper SHA256:1124633ee2c3d28c5c62eaed6a2b9e8fe9eb4804d57d68c108d019945f2788c6.
- Launcher SHA256:60ea50d9ba9ccb88befb7f422cae9d7b3ab06add6f27a53bd75c3e3aa4846ae5.
- Capsula SHA256:ebbccef8be1ed62d8c32a3325dbd83c6396d2dde486a18d2469af6661b1b6b9f.
- Archivio esistente obbligatorio:`$HOME/ouf-chatbot-file-delivery-126e49f3830667934bf8f8d7/cohort/cohort.zip`.
- SHA256 archivio:144699ab7756c8312d49783967cfbb64acc02a617015ad89f5adf51e25a10300.
- Producer 8bff54a52a0ce15daccaf2aee932004f106dd178,run 38584614991,artifact 11907557440. Nessuno dei sei pin applicativi è cambiato.

## Esito acquisito

La preparazione completa precedente è riuscita. La decisione terminale delle07:48:03 CEST è stata accettata; il processo separato systemd è partito. La proposta dei ruoli è poi scaduta senza conferma, con link presentato soltanto nel JSON approvalPath. Il recupero mirato ha creato una nuova proposta con contenuto identico e l'operatore riferisce di averla confermata.

Una lettura OUF autenticata conferma il ruolo admin con le tre nuove capacità e un catalogo corrispondente alla review, salvo i soli campi predefiniti aggiunti dall'owner sui tre permessi nuovi. I ruoli pubblicati restano acquisiti.

Ultimo stato persistito: **PAUSED_REQUIRES_RECONCILIATION**,reason **PlanDenied**,aggiornato2026-10-15T06:37:47.806355Z. Il processo è inactive/dead, nessun thread osservato; la finestra è scaduta alle 08:48:03 CEST. Result=success/ExecMainStatus=0 dell'unità ormai inattiva non costituiscono prova di completamento. Il codice interno preciso del PlanDenied non era registrato. L'installazione e il CSV non sono dimostrati.

## Difetti verificati e correzioni

Il compilatore proponeva constraints parziali; il DTO Java dell'owner li restituisce con tutti i campi vuoti/null. La fixture precedente copiava targetRoles invece di attraversare tale serializzazione. L'hash della review è ricostruibile esattamente togliendo solo quei default dai tre nuovi permessi della risposta reale.

Il nuovo compilatore genera i soli nuovi permessi direttamente nel formato completo del GrantConstraints qualificato. Non normalizza il catalogo storico e mantiene la sua uguaglianza rigorosa. Il nuovo test attraversa il DTO Java e Jackson reali: riproduce il vecchio errore, applica la correzione e dimostra che una ripreparazione dopo pubblicazione non crea un'altra proposta ruoli o delta IAM.

PlanDenied conserva ora il codice pubblico sicuro. Il terminale mostra una richiesta browser esplicita, link e scadenza fuori dal JSON. Proposte EXPIRED/REJECTED richiedono intervento e non rimangono in attesa automatica. Il figlio invia diagnostica pubblica al journal systemd, senza traceback o corpi arbitrari di eccezione. Una vera unità systemd usa il bootstrap reale e verifica la persistenza del fallimento pubblico dopo distacco del terminale.

## Qualificazione

[CI38696421404](https://github.com/GioNob/ouf-deploy/actions/runs/38696421404),job 116293919549: **223 test, 29 suite,PASS,zero skip**. Run PR 38696428010/job 116293939782 PASS. Verificatore HUMAN 38696428157/job 116293940620 PASS.

Il DTO viene compilato dai sorgenti owner 84828f74ac586bae09a78f0fb197b75b1a3d98d1 con BOM Jackson 2.21.7. Sono qualificati anche i controlli di custodia e lineage della ripresa, inclusa la cartella snapshot pubblica root-owned con figli privati.

Composizione frame con immagine pubblicata e TLS Java rimangono qualificati dalla run 38684997298 del sorgente 951f91c; quei percorsi e le immagini non sono modificati. La CI non equivale a prova E2E sul VPS.

## Prima della nuova finestra

Il programma riconcilia soltanto il predecessore noto 6959b1d dello stesso pacchetto. Deve trovare:
- vecchio mandato scaduto e processo spento;
- claim di avvio consumata ancora presente, senza replay;
- tutti gli effetti amministrativi registrati APPLIED, con conteggi conservati;
- directory delle fasi successive senza registri di import immagini, applicazione, backup/migrazione o primo grant.

Qualsiasi storico successivo/ambiguo blocca questa ripresa. I record sono letti con custodia root e hash, inclusi review, decisione, autorità, ultimo stato, claim, identità directory e journal amministrativo. Entrano nella nuova review e vengono ricontrollati nel figlio prima dell'esecuzione. È una riconciliazione mirata di una finestra fermata nella fase amministrativa, non un meccanismo generale per riavviare qualunque cutover.

La verifica sul target non è ancora eseguita: il nuovo comando la effettua prima dell'approvazione. Il processo precedente resta fermo e i suoi file non vengono modificati.

## Istruzioni operatore

1. Il wrapper verifica e riusa lo ZIP già scaricato e il client gh portatile prima di sudo.
2. Completare eventuali prompt sudo e amministrazione Keycloak nei terminali previsti; nessuna password va in chat.
3. Se compare OPEN_IN_BROWSER con codice XXXX-YYYY, aprire il link e usare quel codice per il login della sessione corrente.
4. Dopo tutte le verifiche viene pubblicata una NUOVA review privata. La sintesi identifica il tentativo precedente e indica se occorre una nuova conferma ruoli. Con i ruoli già pubblicati e invariati non è prevista una nuova proposta ruoli.
5. Leggere la review e digitare `APPROVO ` seguito dall'intero nuovo hash mostrato. Il lettore ammette massimo tre risposte nello stesso prompt; l'incolla del solo hash è supportato. Non automatizzare l'approvazione o riutilizzare vecchi hash.
6. La nuova finestra finita, massimo 3600 secondi, inizia dalla nuova decisione. Non deriva dal vecchio mandato. Eventuali conferme browser dei ruoli sono mostrate come AZIONE RICHIESTA con link esplicito e scadenza 15 minuti.
7. Inviare stati PAUSED/BLOCKED o COHORT_READY_FOR_ACTUAL_CHATBOT_CSV_ACCEPTANCE. Dopo un esito mutativo ambiguo non rilanciare il wrapper.

La review comprende cinque sostituzioni applicative, backup/migrazioni previsti, Gateway/IAM, owner policy-token e ritiro delle unità legacy. Se richiesto dal piano, APISIX viene sostituito con la stessa immagine e la configurazione revisionata. MCP può richiedere il ruolo audit NOLOGIN e privilegi temporanei selezionati, revocati prima dell'avvio. Il primo grant rimane distinto e limitato a 300 secondi; nessun restore DB, replay R12, reset di budget o rinnovo automatico è autorizzato.

## Prova CSV ancora da eseguire

Teatri: asset 6609b245-86ed-4315-8ce0-73f2a8555bf3,profile 7984c39c-7396-4248-ab0a-f2efc390b49c/versione 1,13 righe e 20 colonne alla lettura precedente. I 20 nomi corrispondono al mapping in releases/teatri-reuse-semantic-proposal-20261014.json del sorgente qualificato. Proposta e Turtle sono preparati; non inventare pubblicazioni o pin approvati.

Classe: https://schema.org/PerformingArtsTheater; ontologySemanticId: https://api.ouf-lab.it/semantic/teatri#TeatriOntology. La proposta richiede review/classificazione HUMAN effettiva. Dopo il cohort: proposta/review/pin semantici, onboarding e review della sorgente, ingestion, distinzione ACK/commit, lineage UDP e ricerca chatbot fresca. Poi nuova sorgente governata con gli stessi byte e verifica MATCH/NOOP. Le decisioni applicative rimangono nelle rispettive THS.

La baseline osservata è 8 Cinema ACTIVE/revisione1 con gli stessi IRI di proprietà, non una prova di uguaglianza di tutti i valori. Le capacità aggiornate del client ChatGPT e la ricerca fresca devono ancora essere verificate dopo l'upgrade. Nessuna review infrastrutturale prova il ciclo CSV.

B01/B02/B03: acquisiti sulla precedente preparazione completa. B04: primo processo avviato e fermato nella fase amministrativa, nuova riconciliazione target da osservare. B05/B06: CSV Teatri e seconda sorgente ancora aperti.

Evidenze: [qualificazione e stato del tentativo](../evidence/chatbot-role-roundtrip-reconciliation-qualification-20261015.json), [diagnosi owner](../evidence/chatbot-role-owner-roundtrip-diagnosis-20261015.json), [preparazione target riuscita](../evidence/complete-target-preparation-20261015.json).
