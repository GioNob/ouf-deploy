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
- Compatibilità V10 e ripristino del backup provati su PostgreSQL 17 isolato: [37668331670](https://github.com/GioNob/ouf-deploy/actions/runs/37668331670). Dati storici, vecchie scritture e funzioni job preservati. Nessun backup o migrazione del database reale ancora eseguito.
- Accesso IAM esistente ripristinato senza cambiare client, scope o grant: `ouf-semantic` ha già `gateway.southbound.invoke` DEFAULT. [37667120379](https://github.com/GioNob/ouf-deploy/actions/runs/37667120379).
- Connessione OUF della chat verificata con l'account `giovanni-chatgpt`, 7 ottobre circa 20:50 Europe/Rome: MCP `HEALTHY`, `actionRequired=false`, `partial=false`. La selezione esplicita del plugin rende disponibile il riferimento dell'account; il precedente errore era nella chiamata senza tale riferimento, non una prova di disconnessione del server.
- Blocco infrastrutturale: il runner non dispone di `sudo` non interattivo per guard/trust/configurazioni provider protette da root. La salute MCP non prova l'installazione della discovery o i suoi grant.
- Provider nazionale ancora disabilitato, origine Gateway e autenticazione provider non configurate esplicitamente.
- Semantic mantiene entrambi i mount esistenti: autenticazione e chiave del proprietario della consultazione.
- Nessun rilascio di discovery effettuato. I tool discovery del candidato MCP restano INACTIVE.

## Percorso verso il risultato

| Passo | Risultato verificabile | Stato |
|---|---|---|
| Collegamento operativo | ChatGPT avvia un job che accede al VPS tramite runner | Docker disponibile; accesso privilegiato provider mancante |
| Pacchetto discovery | Immagini Semantic/MCP e sorgenti Gateway da revisioni fisse | Firmato, trasferito e verificato sul target; non applicato |
| Installazione discovery | V10, provider nazionale autenticato, tre rotte, policy e tool attivi | Bloccata: canale privilegiato provider e collegamenti/policy di installazione |
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

Una build riuscita e un digest non costituiscono accettazione del rilascio. Provenienza verificata, copertura vulnerabilità, collegamenti di installazione, policy e recupero della migrazione devono essere completati prima dell'applicazione.

Il [piano di installazione corrente](releases/NATIONAL_DISCOVERY_INSTALLATION_PLAN.md) descrive pacchetti pronti, blocchi e operazioni mancanti. Il candidato coordinato è in `releases/national-discovery-candidate.json`; le evidenze effettive sono in `evidence/`. Gli script non emettono segreti. Non registrare nuovamente il runner, non ripetere l'installazione e non ricominciare i test manuali già conclusi.

## Regole del rilascio

Preservare dati, volumi, servizi esistenti e rotta di ricerca UDP già riparata. Il vecchio helper Semantic richiede migrazioni identiche e un solo mount: non è applicabile a questo candidato. Preparare un applicatore consapevole di V10 e dei due mount attuali, con backup e recupero esplicito. Nessun ripristino automatico del database che possa cancellare dati scritti dopo il rilascio.

Le PR Semantic #31/#32, Gateway #57 e MCP #49 restano bozze; non sono merge o rilascio autorizzato automaticamente. Le decisioni umane di adozione/pubblicazione semantica non possono essere sostituite dal chatbot.
