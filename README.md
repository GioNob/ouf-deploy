# OUF: file → semantica → Onboarding → ingestion → UDP

## Stato corrente — 8 ottobre 2026

La migrazione delle protezioni di rete provider/OIDC è completata sul VPS: l'operatore ha riportato `EMPTY_GUARD_EXTENDED`, runtime `RUNTIME_PROVIDER_OIDC_EMPTY`, due candidati mai avviati, destinazioni provider vuote e handle originali preservati. Zero operazioni sul ciclo di vita, nessun riavvio del daemon, nessuna chiamata al provider e nessuna lettura di chiavi private. [Ricevuta target dell'operatore](evidence/provider-v2-network-guard-target-20261008.json): fonte `semantic-network-guard-source-ib5rco84`, snapshot `semantic-coordinated-boot-install-v2-e4repg0a`. Non ripetere la migrazione né le preparazioni di runtime, creazione fermata, immagini/rootfs, TLS, input o reti già completate. La ricevuta non concede avvio, lease o accettazione del rilascio; riavvio reale e stabilità tra letture non sono provati.

Il prossimo lavoro è [completare l'orchestratore della transazione e dell'avvio controllato](releases/PROVIDER_V2_ADMISSION_NEXT.md): input completi autorizzati, profili firmati vincolati ai due CID e ai sigilli effettivi, allowlist runtime, ammissione coordinata e diagnosi conservata. Questo orchestratore target resta incompleto; nessun comando di avvio target è pronto. Poi rollout Semantic/MCP e percorso nazionale Teatri → approvazione umana → onboarding → ingestion/duplicati → UDP e lettura in chat. Nessun job nazionale Teatri è stato eseguito. Il pacchetto normativo v1.7 fornito nella chat è stato verificato integralmente (321 file, zero differenze); Matrice L0 v1.7 e PET L1 applicabili governano ogni sprint. Le sezioni successive conservano la cronologia: questo paragrafo identifica lo stato corrente.


> **Original attempt blocked before trust generation.** The read-only root diagnosis confirms `/etc/ouf/deploy-snapshots/semantic-provider-v2-trust-dlz2t6B6` contains no preparation claim, certificates, keys or trust receipt. The original script incorrectly selected an OpenSSL fingerprint from earlier authority preparation instead of the current system `/usr/bin/openssl`. The observed system fingerprint is `acc10176d038aeb7b2a77d9ec972ac2985857a7191f7aecb7c54ef0e2c7e9549`; existing authority receipts remain unchanged. Corrected source `8474237d4b2ef7eefbb2ba9a0a0b524dcdbd241f`, bootstrap `b5b4f4494665854cf43f75c9aeece09afcab3552`, now include explicit failure-stage output and the exact system fingerprint. [CI 37692870614](https://github.com/GioNob/ouf-deploy/actions/runs/37692870614), job 113037145459, passed all 9 root-private/OpenSSL tests with zero skips plus Bash syntax validation. The new operator action creates a separate snapshot; preserve the failed snapshot and do not rerun its old script. The corrected preparation has not yet been applied to the VPS.


Questo repository privato gestisce l'installazione sul VPS di test. Il percorso prodotto deve essere eseguito dal chatbot tramite MCP: nessun accesso al server per caricare o elaborare un file.

## Stato provato, 7 ottobre 2026

- Runner `ouf-vps-test` installato come servizio e collegato a GitHub.
- Docker accessibile direttamente dal runner: job 112916316548, run [37657523800](https://github.com/GioNob/ouf-deploy/actions/runs/37657523800).
- Inventario completo: 96 container, 13 in esecuzione; zero scritture di configurazione e zero operazioni sul ciclo di vita.
- Confronto Semantic installato/candidato: V1–V9 identiche nei byte; unica aggiunta V10 per l'idempotenza discovery. Run [37657736363](https://github.com/GioNob/ouf-deploy/actions/runs/37657736363).
- Pacchetti Semantic/MCP firmati: [Semantic 37665730385](https://github.com/GioNob/ouf-semantic-registry/actions/runs/37665730385), [MCP 37665728762](https://github.com/GioNob/ouf-mcp-server/actions/runs/37665728762). Zero Critical/High/Unknown con database del 7 ottobre. Le immagini precedenti non sono quelle selezionate per il rilascio.
- Pacchetti trasferiti sul VPS e firme/byte verificati indipendentemente: [37667405182](https://github.com/GioNob/ouf-deploy/actions/runs/37667405182). Nessuna importazione o partenza; evidenza in `evidence/discovery-signed-target-stage-20261007.json`.
- Suite Semantic e controllo PR MCP passati; il controllo separato di latenza MCP è passato al secondo tentativo sullo stesso sorgente, dopo il primo fallimento p95=100.7 ms contro 25 ms. [37664542956](https://github.com/GioNob/ouf-mcp-server/actions/runs/37664542956). Si tratta di CI, non di una misura del VPS.
- Compatibilità V10 e ripristino del backup provati su PostgreSQL 17 isolato: [37668331670](https://github.com/GioNob/ouf-deploy/actions/runs/37668331670). Dati storici, vecchie scritture e funzioni job preservati. Backup privato dello schema Semantic reale ora completato: [37672523223](https://github.com/GioNob/ouf-deploy/actions/runs/37672523223). Archivio mode 0600 analizzato integralmente, nessuna scrittura al database né ripristino sul VPS. Nessuna migrazione del database reale ancora eseguita.
- Accesso IAM esistente ripristinato senza cambiare client, scope o grant: `ouf-semantic` ha già `gateway.southbound.invoke` DEFAULT. [37667120379](https://github.com/GioNob/ouf-deploy/actions/runs/37667120379).
- Connessione OUF della chat verificata con l'account `giovanni-chatgpt`, 7 ottobre circa 20:50 Europe/Rome: MCP `HEALTHY`, `actionRequired=false`, `partial=false`. La selezione esplicita del plugin rende disponibile il riferimento dell'account; il precedente errore era nella chiamata senza tale riferimento, non una prova di disconnessione del server.
- Helper privilegiato di sola lettura installato sul VPS e utilizzabile dal runner senza password: [37671471821](https://github.com/GioNob/ouf-deploy/actions/runs/37671471821), job 112964021220 riuscito. Regola sudo limitata al comando senza argomenti; nessun sudo generale. Mount attesi presenti, nessuna scrittura o operazione sui container. Le ricevute storiche conservano i flag di trust/avvio non accettati. Gli elenchi nft vuoti dipendono da un filtro sui nomi e non provano assenza delle tabelle. Evidenza in `evidence/discovery-privileged-target-preflight-20261007.json`.
- Aggiornamento v2 del solo helper di lettura installato e verificato sul VPS: [12 controlli passati](https://github.com/GioNob/ouf-deploy/actions/runs/37674663012). Riutilizza l’inventario nativo originale, con ricevuta runtime fissa e stesso lock, senza applicare/ripetere transizioni. Sostituisce soltanto la versione v1 nota e la conserva per recupero; regola sudo invariata. L’operatore lo ha installato; [runner 37675793488](https://github.com/GioNob/ouf-deploy/actions/runs/37675793488) passato. La verifica nativa conferma RUNTIME_EMPTY, custodia integra, due candidati mai avviati e lease vuoti. Nessuna regola, servizio o container modificato dalla verifica.
- Pacchetto operativo coordinato pronto per staging privato: [5 controlli, inclusa prova nft reale, passati](https://github.com/GioNob/ouf-deploy/actions/runs/37677924958). Preparatore e bootstrap sono vincolati a hash/revisioni fissi; verifica il comando root contro le tabelle esistenti e conserva regole, journal e lock. Lo staging crea solo nuovi file privati con lease/start disabilitati. Staging eseguito sul VPS in `/etc/ouf/deploy-snapshots/semantic-coordinated-owner-package-p0mxeups`: guard di sola lettura verificato, journal QUIESCED senza autorità. Il [controllo indipendente 37678450910](https://github.com/GioNob/ouf-deploy/actions/runs/37678450910) conferma identici i tre hash del runtime originale e i candidati mai avviati. Daemon non avviato, guard non installato; evidenza in `evidence/discovery-coordinated-owner-target-stage-20261007.json`.
- Integrazione del riavvio preparata nel comando root isolato, sorgente Gateway `df103735c1fe75a31e6d4c752360e9368e6aa52d`: [31 test unitari e 5 nativi passati](https://github.com/GioNob/ouf-deploy/actions/runs/37680983756), senza skip. Provate revoca del lease prima del ripristino, ricostruzione delle tabelle vuote, conservazione delle regole estranee e del journal originale, rifiuto di codice alterato. Nessuna riattivazione automatica dopo il cambio degli handle. Questa è una prova isolata, non un riavvio del VPS né una modifica dei suoi servizi. Evidenza: `evidence/discovery-coordinated-boot-preparation-20261007.json`.
- Primo tentativo del bootstrap fallito prima delle scritture: errore di caricamento del lettore senza estensione `.py`, non coperto dal precedente adapter simulato. [Diagnosi sul VPS 37684853514](https://github.com/GioNob/ouf-deploy/actions/runs/37684853514) conferma lettore v2 e comandi originali, Docker attivo, custodia e tre hash originali invariati. Loader esplicito corretto e prova sul lettore v2 reale aggiunta: [13 controlli e 2 prove native passati](https://github.com/GioNob/ouf-deploy/actions/runs/37685283731). Bootstrap precedente ritirato. La procedura corretta è stata applicata: [verifica indipendente 37685657539](https://github.com/GioNob/ouf-deploy/actions/runs/37685657539) passata, lettore v3 e nuovo guard installati, custodia e journal originali invariati. Nessun avvio di provider/container; autorità, lease e riavvio reale ancora da completare. Evidenza: `evidence/discovery-coordinated-boot-target-installation-20261007.json`.
- Lettura reale del catalogo ruoli tramite account amministratore: assegnazione nominale admin presente, tre permessi discovery assenti dal ruolo. Nessuna modifica di grant o IAM. Evidenza in `evidence/discovery-authorization-role-read-20261007.json`.
- Provider nazionale ancora disabilitato, origine Gateway e autenticazione provider non configurate esplicitamente. Il guard di rete preparato è EMPTY_ONLY. Supervisore e comando root coordinati sono ora preparati nella PR Gateway #57, sorgente a10df126d229dfefd9e0a4d716a07f1f535b6cd6: [25 controlli unitari e 3 prove native passati](https://github.com/GioNob/ouf-deploy/actions/runs/37674161315), senza skip. Revoca all’avvio/stop, DNS nuovo, blocco dell’avvio con lease attivi e rifiuto di riattivazione autonoma sono provati. Il passaggio del guard installato è completato; le autorizzazioni locali e il ciclo attivo restano da completare.
- Semantic mantiene entrambi i mount esistenti: autenticazione e chiave del proprietario della consultazione.
- Nessun rilascio di discovery effettuato. I tool discovery del candidato MCP restano INACTIVE.

## Percorso verso il risultato

| Passo | Risultato verificabile | Stato |
|---|---|---|
| Collegamento operativo | ChatGPT avvia un job che accede al VPS tramite runner | Docker e lettura privilegiata limitata disponibili; applicazione provider da completare |
| Pacchetto discovery | Immagini Semantic/MCP e sorgenti Gateway da revisioni fisse | Firmato, trasferito e verificato sul target; non applicato |
| Installazione discovery | V10, provider nazionale autenticato, tre rotte, policy e tool attivi | Da completare: applicatore privilegiato, collegamenti e policy di installazione |
| Discovery Teatri | Richiesta reale `CLASS / teatro / it,en`, stato e candidati letti in chat | Non eseguita |
| Semantica e Onboarding | Mapping, decisioni umane e approvazioni tramite tool governati | Operazioni mancanti da completare |
| Ingestion e UDP | Run reale, controlli duplicati/merge, materializzazione e lettura in chat | Da eseguire sul nuovo percorso |

Il CSV Teatri è già caricato e profilato: asset `6609b245-86ed-4315-8ce0-73f2a8555bf3`, profilo `7984c39c-7396-4248-ab0a-f2efc390b49c`. Non caricarlo di nuovo. Discovery nazionale, nessun fallback locale.

## Workflow e limiti

- `channel-check.yml`: connessione del runner.
- `release-readiness.yml`: inventario Docker filtrato, senza valori segreti.
- `discovery-release-plan.yml`: confronto delle migrazioni nel JAR realmente installato con la revisione candidata.
- `discovery-candidate-package.yml`: pacchetto iniziale rifiutato dalle scansioni, conservato come evidenza; non usarlo per il rilascio.
- `oss-semantic-candidate.yml` / `static-mcp-candidate.yml`: qualificazione delle dipendenze aggiornate su CI ospitata.
- Workflow firmati nei repository Semantic/MCP: pacchetti selezionati con provenienza e scansioni.
- `signed-discovery-target-stage.yml`: trasferimento e verifica crittografica dei pacchetti sul VPS, senza importazione/start.
- `discovery-operational-access.yml`: stato effettivo IAM e privilegi del runner.
- `discovery-migration-recovery.yml`: V10 e dump/ripristino del database di prova, senza toccare il VPS.
- `semantic-target-backup.yml`: validazione CI, poi dump privato dello schema `ouf_sem` sul target e analisi completa dell’archivio; nessun upload dei dati o ripristino automatico.

Una build riuscita e un digest non costituiscono accettazione del rilascio. Provenienza verificata, copertura vulnerabilità, collegamenti di installazione, policy e recupero della migrazione devono essere completati prima dell'applicazione.

Il [piano di installazione corrente](releases/NATIONAL_DISCOVERY_INSTALLATION_PLAN.md) descrive pacchetti pronti, blocchi e operazioni mancanti. Il candidato coordinato è in `releases/national-discovery-candidate.json`; le evidenze effettive sono in `evidence/`. Gli script non emettono segreti. Non registrare nuovamente il runner, non ripetere l'installazione e non ricominciare i test manuali già conclusi.

## Regole del rilascio

Preservare dati, volumi, servizi esistenti e rotta di ricerca UDP già riparata. Il vecchio helper Semantic richiede migrazioni identiche e un solo mount: non è applicabile a questo candidato. Preparare un applicatore consapevole di V10 e dei due mount attuali, con backup e recupero esplicito. Nessun ripristino automatico del database che possa cancellare dati scritti dopo il rilascio.

Le PR Semantic #31/#32, Gateway #57 e MCP #49 restano bozze; non sono merge o rilascio autorizzato automaticamente. Le decisioni umane di adozione/pubblicazione semantica non possono essere sostituite dal chatbot.


## Creation-only authorization issuer, 7 October 2026

The initial creation intent now has a production, source-sealed issuer at Gateway `ace683b1019f79adaace86796b67e463b93ec12e`. [CI 37688373813](https://github.com/GioNob/ouf-api-gateway/actions/runs/37688373813), job 113021951881, passed 66 tests with real OpenSSL, the isolated issuer CLI, actual production broker creation-phase consumption and no runtime invocation. The issuer reuses existing keys, requires an explicit root creation-only invocation and a bounded root-private mandate, preserves failed issuance claims and never authorizes application start. This does not provision transaction-specific mandates or acceptance on the VPS.

The operator supplied the actual authority bindings for installation `ouf-lab-netcup-01`, entity `ouf-lab`, separate installer/attestor identities and key references. No key was generated or read. Exact policy/custody receipts are retained. A bounded source installation bootstrap at `942acda2ca5d0638714c2958ffe6dfdff427340c` downloads 19 source files with closed hashes and installs them in a new root-private snapshot, binding the existing public policy and key references. It does not read private keys, sign evidence, link transaction consumers, change services/rules/databases/IAM or create/start containers. [Installation CI 37689237859](https://github.com/GioNob/ouf-deploy/actions/runs/37689237859) passed 7 root-private publication/refusal tests and bootstrap syntax validation, zero skips. Source installation has completed on the VPS; its exact receipt and remaining transaction gates are recorded below. It does not complete the seven existing target admission gates. Evidence: `evidence/discovery-creation-intent-preparation-20261007.json`.


## Issuer source installation on the VPS completed

The operator completed the bounded installation at `/etc/ouf/deploy-snapshots/semantic-creation-issuer-install-USjonf22`, authority profile SHA256 `7fb7880d58e43ab40f9f53dac07a5dbad462d12e3a96f3b1287c6763b1d7ce18`. All 19 source hashes and existing authority/public-key references were verified. No private key was read, signature issued, rule changed or container lifecycle action performed. This is `SOURCE_INSTALLED_EXISTING_AUTHORITY_BOUND`; transactionConfigured, policyConsumerLinked, roleSigningAuthorized and startAuthorized remain false. Do not rerun the source installation bootstrap. Evidence: `evidence/discovery-creation-issuer-target-installation-20261007.json`. The next work is a new role-specific candidate transaction using the remediated adapter/southbound artifacts, preserving the old candidates and the live Gateway. The old Gateway-bound candidate stager cannot be reused for the new southbound image.


## Nuove immagini provider: prossimo intervento concreto

Letture indipendenti sul VPS completate: [configurazioni di avvio e archivi 37690207099](https://github.com/GioNob/ouf-deploy/actions/runs/37690207099), [layer e account 37691307786](https://github.com/GioNob/ouf-deploy/actions/runs/37691307786). Adapter 10006:10006, southbound 636:636, entrambe le immagini esattamente quelle del pacchetto corretto. Nessuna importazione o esecuzione.

Il nuovo blocco [PROVIDER_V2_PRIVATE_TRUST.md](releases/PROVIDER_V2_PRIVATE_TRUST.md) prepara soltanto certificati e chiave di ricevuta privati per i due nomi nuovi, in uno snapshot separato. [CI 37691852247](https://github.com/GioNob/ouf-deploy/actions/runs/37691852247), job 113033729445, ha passato 7 prove con OpenSSL reale e file root privati, senza skip, più la validazione Bash. La prima versione è stata bloccata; la preparazione corretta è ora completata come riportato sotto. Le chiavi dell’autorità di installazione, i container e i servizi esistenti non cambiano. Il runner ha sudo limitato alla lettura; questo passaggio di scrittura protetta richiede l’operatore.

Il risultato prodotto resta da completare: provider nazionale funzionante e discovery MCP, adozione/revisione/approvazione umana, ingestion e riscontro UDP in chat. Nessun job Teatri nazionale è stato eseguito e nessuna accettazione/start è implicata dalle nuove prove.


## Provider v2: certificati preparati, file di avvio pronti per applicazione

L'operatore ha completato la preparazione corretta in `/etc/ouf/deploy-snapshots/semantic-provider-v2-trust-vf7B4SM5`: `PRIVATE_TRUST_PREPARED`, certificati per i due nomi v2 e chiave di ricevuta generati, account numerici verificati. La ricevuta esatta è in `evidence/discovery-provider-v2-private-trust-target-prepared-20261007.json`; è output dell'operatore, non una lettura indipendente del runner. Mount, immagini, container e servizi non sono stati modificati; start e accettazione restano disabilitati.

Il preparatore dei file di avvio è pronto, bootstrap fisso `066e04c1b8c86fc8f9b908ab3978d12b2e9c0073`. [CI 37694547721](https://github.com/GioNob/ouf-deploy/actions/runs/37694547721), job 113042884081: nove test riusciti, senza skip, con compilatori nativi sigillati, TLS reale e file privati con account di ruolo; sintassi Bash valida. Prepara sei file in un nuovo snapshot root privato, mantiene endpoint/scopi/limiti del provider originale e copia solo la credenziale OIDC esistente e la nuova chiave di ricevuta. Legge soltanto il candidato southbound fermo e gli input originali fissi; non importa, crea o avvia container. Il preparatore completo non è ancora stato eseguito sul VPS. Restano transazione di creazione/ammissione/avvio, rollout Semantic/MCP e percorso prodotto Teatri.


## Avanzamento effettivo dell'8 ottobre: input pronti, runtime mancante

La preparazione dei sei input v2 è completata sul VPS in `semantic-provider-v2-inputs-XE7IwlGm`, con provider originale preservato e credenziale OIDC riutilizzata. Ricevuta operatore: `evidence/discovery-provider-v2-startup-inputs-target-prepared-20261008.json`. Non ripetere i bootstrap TLS/input. [Lettura indipendente delle reti 37695489801](https://github.com/GioNob/ouf-deploy/actions/runs/37695489801) conferma due vecchi candidati mai avviati, reti dedicate vuote e nomi v2 disponibili. Gli ID di rete differiti vengono risolti tramite nome configurato; ciò non prova allocazione di endpoint o namespace vivo. [Catalogo runtime reale 37695629985](https://github.com/GioNob/ouf-deploy/actions/runs/37695629985) registra soltanto `runc` e `io.containerd.runc.v2`: l'adapter OUF di ammissione non è registrato. Non creare il candidato avviabile col runtime standard come sostituto. Il prossimo input necessario è una lettura root fissa della configurazione daemon e del guard originale, preparata in `scripts/read-provider-v2-runtime-host.py` a `e0a7baf2011d5bf36f199cf78ffa07735a0940cb`, SHA256 `e03608985c9c49d35203794143c8278674fc260d5cf246f96e0f9a4740517f0e`. Sintassi Python verificata localmente; non ancora eseguita sul target. La lettura non apre chiavi/ambiente e non cambia daemon, servizi, container, rete o autorità. Richiede l'operatore perché il runner ha solo il precedente helper root senza argomenti. Dopo queste informazioni: provisioner del runtime e transazione di creazione, ammissione/avvio reale, rollout Semantic/MCP, discovery e percorso prodotto. Non è stata ancora effettuata una discovery Teatri nazionale.


Provider v2 approved-transaction integration now connects guarded switching and concurrent admitted-runtime Docker requests. The 39-file source closure and 25 local authenticated tests are development validation only. Complete target acceptance/role mandates and real Docker cohort verification remain required; no target command or VPS operation is issued. See releases/PROVIDER_V2_ADMISSION_NEXT.md.


Recovered existing signed dependency evidence for both v2 configs from Semantic PR #26, including already-completed operator fresh verification. Current DB validity ends 9 October 2026 08:31:48 Europe/Rome; avoid repeating completed scans/verifications. The transaction now checks freshness across all signed authority windows. See releases/PROVIDER_V2_IMAGE_REVIEW_DRAFT_20261008.md for actual custom/publisher decisions and remaining authority work. No target start command is issued.


## Explicit human lab image acceptance, 8 October 23:38:09 Europe/Rome

The user answered "accetto" to the concrete image review proposal. Receipt: evidence/provider-v2-lab-image-human-acceptance-20261008.json, approvalRef OUF_PROVIDER_V2_LAB_IMAGE_REVIEW_20261008_233809. It accepts the two exact v2 images for OUF-LAB, custom-component maintenance by OUF/GioNob, omitted WASM and documented provenance/advisory-coverage limits, with current 5/142 Medium counts. Do not ask this same acceptance again. This is the human message record, not a cryptographic issuer signature or target authorization token. It does not grant complete OCI/rootfs acceptance, role signing, runtime publication, leases, startup or release acceptance. Database freshness remains mandatory. Proceed autonomously with complete target input/profile closure and actual Docker cohort integration; no target start command is ready.


Hosted CI 37849612355 now also passes a real concurrent two-Docker creation-window fixture (runner Docker 28.0.4, not target 29.8.1). Full production admitted-runtime Docker cohort remains unproved. Next required operator input: read the existing fixed private frames with tools/semantic_target_review/read_private_frame_summary.py; no preparation or signing. Lab image acceptance already recorded. See releases/PROVIDER_V2_ADMISSION_NEXT.md.


9 October: fixed private frame summary received successfully; do not repeat. Pinned isolated Docker29.8.1/overlayfs window CI and all31 authenticated/preparer preflight tests pass. Next required operator action is the new unsigned document closure helper tools/semantic_target_review/prepare_private_transaction_draft.py; it reuses completed snapshots, prepares only new private review inputs and issues no authority/start. See releases/PROVIDER_V2_ADMISSION_NEXT.md for exact hash, limits and pending full admitted-runtime Docker integration/role acceptance.
