# OUF: file → semantica → Onboarding → ingestion → UDP

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
- Lettura reale del catalogo ruoli tramite account amministratore: assegnazione nominale admin presente, tre permessi discovery assenti dal ruolo. Nessuna modifica di grant o IAM. Evidenza in `evidence/discovery-authorization-role-read-20261007.json`.
- Provider nazionale ancora disabilitato, origine Gateway e autenticazione provider non configurate esplicitamente. Il guard di rete preparato è EMPTY_ONLY. Supervisore e comando root coordinati sono ora preparati nella PR Gateway #57, sorgente a10df126d229dfefd9e0a4d716a07f1f535b6cd6: [25 controlli unitari e 3 prove native passati](https://github.com/GioNob/ouf-deploy/actions/runs/37674161315), senza skip. Revoca all’avvio/stop, DNS nuovo, blocco dell’avvio con lease attivi e rifiuto di riattivazione autonoma sono provati. Il passaggio del guard installato e le autorizzazioni locali restano da completare.
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
