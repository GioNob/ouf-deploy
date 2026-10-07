# OUF: file → semantica → Onboarding → ingestion → UDP

Questo repository privato gestisce l'installazione sul VPS di test. Il percorso prodotto deve essere eseguito dal chatbot tramite MCP: nessun accesso al server per caricare o elaborare un file.

## Stato provato, 7 ottobre 2026

- Runner `ouf-vps-test` installato come servizio e collegato a GitHub.
- Docker accessibile direttamente dal runner: job 112916316548, run [37657523800](https://github.com/GioNob/ouf-deploy/actions/runs/37657523800).
- Inventario completo: 96 container, 13 in esecuzione; zero scritture di configurazione e zero operazioni sul ciclo di vita.
- Confronto Semantic installato/candidato: V1–V9 identiche nei byte; unica aggiunta V10 per l'idempotenza discovery. Run [37657736363](https://github.com/GioNob/ouf-deploy/actions/runs/37657736363).
- Immagini Semantic/MCP aggiornate e verificate: [Semantic 37664690994](https://github.com/GioNob/ouf-deploy/actions/runs/37664690994), [MCP 37664694124](https://github.com/GioNob/ouf-deploy/actions/runs/37664694124). Zero Critical/High/Unknown con database del 7 ottobre. Non sono installate.
- Suite Semantic e controllo PR MCP passati; un controllo separato di latenza MCP è in ripetizione dopo p95=100.7 ms contro 25 ms. Non attribuire questo risultato al VPS.
- Provider nazionale ancora disabilitato, origine Gateway e autenticazione provider non configurate esplicitamente.
- Semantic mantiene entrambi i mount esistenti: autenticazione e chiave del proprietario della consultazione.
- Nessun rilascio di discovery effettuato. I tool discovery del candidato MCP restano INACTIVE.

## Percorso verso il risultato

| Passo | Risultato verificabile | Stato |
|---|---|---|
| Collegamento operativo | ChatGPT avvia un job che accede al VPS tramite runner | Completato |
| Pacchetto discovery | Immagini Semantic/MCP e sorgenti Gateway da revisioni fisse | Immagini aggiornate: zero Critical/High/Unknown; firma in corso |
| Installazione discovery | V10, provider nazionale autenticato, tre rotte, policy e tool attivi | Da completare |
| Discovery Teatri | Richiesta reale `CLASS / teatro / it,en`, stato e candidati letti in chat | Non eseguita |
| Semantica e Onboarding | Mapping, decisioni umane e approvazioni tramite tool governati | Operazioni mancanti da completare |
| Ingestion e UDP | Run reale, controlli duplicati/merge, materializzazione e lettura in chat | Da eseguire sul nuovo percorso |

Il CSV Teatri è già caricato e profilato: asset `6609b245-86ed-4315-8ce0-73f2a8555bf3`, profilo `7984c39c-7396-4248-ab0a-f2efc390b49c`. Non caricarlo di nuovo. Discovery nazionale, nessun fallback locale.

## Workflow e limiti

- `channel-check.yml`: connessione del runner.
- `release-readiness.yml`: inventario Docker filtrato, senza valori segreti.
- `discovery-release-plan.yml`: confronto delle migrazioni nel JAR realmente installato con la revisione candidata.
- `discovery-candidate-package.yml`: build su runner GitHub ospitato, archivi immagine e sorgenti Gateway con digest. Non usa il VPS e non distribuisce il pacchetto.

Una build riuscita e un digest non costituiscono accettazione del rilascio. Provenienza verificata, copertura vulnerabilità, collegamenti di installazione, policy e recupero della migrazione devono essere completati prima dell'applicazione.

Il candidato coordinato è in `releases/national-discovery-candidate.json`; le evidenze effettive sono in `evidence/`. Gli script non emettono segreti. Non registrare nuovamente il runner, non ripetere l'installazione e non ricominciare i test manuali già conclusi.

## Regole del rilascio

Preservare dati, volumi, servizi esistenti e rotta di ricerca UDP già riparata. Il vecchio helper Semantic richiede migrazioni identiche e un solo mount: non è applicabile a questo candidato. Preparare un applicatore consapevole di V10 e dei due mount attuali, con backup e recupero esplicito. Nessun ripristino automatico del database che possa cancellare dati scritti dopo il rilascio.

Le PR Semantic #31/#32, Gateway #57 e MCP #49 restano bozze; non sono merge o rilascio autorizzato automaticamente. Le decisioni umane di adozione/pubblicazione semantica non possono essere sostituite dal chatbot.
