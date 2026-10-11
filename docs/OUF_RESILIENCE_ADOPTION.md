# Platform resilience v3 — adoption ledger (11 October 2026)

[Normative policy](OUF_RESILIENCE_POLICY.md). The owner's decisions authorize implementation choices consistent with the PETs/AWS references; they do not manufacture runtime HUMAN grants or reopen consumed target activation claims.

| Tranche | Concrete boundary | Status |
|---|---|---|
| Project rule | Policy v3 and AGENTS instructions in all seven OUF repos | RECORDED |
| Finite lease recovery protocol | Bounded pause/retry, durable journal, fresh DNS, finite TTL and revocation | QUALIFIED in isolated synthetic-authority CI38102725541;16 tests plus native DNS/nft and four virtual outage hours |
| HUMAN original-run recovery | New budget after exhaustion, preserved history, atomic grants, worker/session fencing, scheduler exclusion and ACK-gated issue resolution | MERGED PR34; PostgreSQL38104209271:35 tests; module38104209251:134 tests; all named candidate checks SUCCESS |
| Initial runs and publication/scheduler activation | Finite incident budget, job slots/checkpoint preservation, no automatic budget renewal | OPEN; scheduler exclusion of exhausted HUMAN run incidents is implemented, but source-health rolling circuit counters are not recovery grants |
| Dependency and downstream scope | Circuit isolation, retries at one owner level, downstream ambiguous-effect reconciliation and finite dispatcher/historical replay budgets | OPEN |
| Quarantine capacity and operator flow | Capacity/retention/backpressure, owner/age/severity, governed actions and safe MCP/THS projection | PARTIAL existing PET mechanisms; complete policy-v3 integration/tests OPEN |
| Gradual recovery across sources/tenants | Protected control capacity, per-dependency/tenant quotas and monitored ramp-up | OPEN; first HUMAN profile serializes batches within one recovered run |
| Target application/lease service | Current private source/command/OCI/peer closure, new finite authority and full resilient owner supervision | OPEN; no VPS apply, old root preflight suspended, R9/R10 consumed |

## Implementation decisions

Work remains inside owner repositories and existing PostgreSQL/owner APIs. No SQS/Kafka/broker or new incident service is introduced by adopting AWS concepts. Sessions track operational recovery, not a new approval/publication authority.

The first HUMAN profile counts existing owned worker batches (100 records/45seconds maximum loop budget), not every downstream HTTP call.128 batches/24hours is a versioned conservative default; operators can grant finite custom limits. The owner still must qualify transport deadlines, concurrency under load and initial/downstream paths separately.

Work already confirmed by durable ACK is preserved; a late immutable lake object remains retained evidence requiring dedup/reconciliation, not an imaginary no-effect outcome. No job is marked successful solely because it was quarantined or granted a new budget.

Future acceptance requires all of: outage/recovery, exactly one grant under operator concurrency, old worker fenced, no duplicate logical effects across sessions, scheduler unable to bypass exhausted incidents, pressure/capacity handling, and usable authorized operator surfaces. Existing Cinema/Teatri results and PET ownership/HUMAN/THS/default-deny contracts remain.


## 11 ottobre2026 — policy di piattaforma v2 e prima tranche HUMAN integrata

L'owner ha confermato quarantena persistente, isolamento dello scope indipendente, budget finiti, nuovi budget concessi da HUMAN, sessioni atomiche/fencing, capacità protetta e recupero graduale. [Policy v2](https://github.com/GioNob/ouf-deploy/blob/main/docs/OUF_RESILIENCE_POLICY.md) e AGENTS.md aggiornati nei sette repository; [registro di adozione](https://github.com/GioNob/ouf-deploy/blob/main/docs/OUF_RESILIENCE_ADOPTION.md). Riferimenti PET/AWS nominati nel documento, nessun nuovo broker/incident service o grant di dominio implicito.

[Ingestion PR34](https://github.com/GioNob/ouf-ingestion-runtime/pull/34) integrata in main, merge6f583ca6b226a63c4a9b55df19f28728c4fd9348. Candidato qualificato80bcb2f8c1f478c0b6d18c46b9eeff5cede5f68f: [PostgreSQL38104209271](https://github.com/GioNob/ouf-ingestion-runtime/actions/runs/38104209271), job114366142916,35 test PASS inclusi16 nuovi; [module38104209251](https://github.com/GioNob/ouf-ingestion-runtime/actions/runs/38104209251),134 test senza errori/failure e controlli supply-chain/nonroot/DR SUCCESS. Tutti gli altri gate owner/pairwise/serving/publication/GIS/continuity sullo stesso candidato sono SUCCESS. [Evidenza](https://github.com/GioNob/ouf-ingestion-runtime/blob/main/evidence/human-recovery-budget-qualified-20261011.json).

V15 additiva introduce un ledger di sessioni, non reset del budget storico. La ripresa originale del run PAUSED richiede HUMAN+capability+tenant+decisionRef e preflight baseline fuori dalla TX; grant/sessione e cambio stato atomici su control_version. Default versionato128 batch owner/24ore, limite100 record/45secondi del loop per batch, una batch recovery posseduta alla volta; limiti finiti personalizzabili. Non è il conteggio di tutti i retry HTTP. Budget verificato prima I/O e pubblicazione; risultato remoto tardivo non avanza handoff/checkpoint. Scheduler non crea nuovi run intorno all'incidente esaurito OPEN, vecchi claim e percorsi unclaimed non aggirano la sessione. Issue risolta soltanto dopo completamento reale e ACK/drain. Dati/checkpoint/lineage/idempotency e storico fallito preservati.

La prima prova38104025072 fallì soltanto per operatore JSON ? nella query di test con JdbcClient; correzione jsonb_exists, senza modificare quel comportamento produttivo, e riesecuzione PASS. La fixture legacy HUMAN_USER è stata allineata a HUMAN+capability del SDK, non rilassata l'autorizzazione.

Adozione completa ancora aperta: retry automatici del worker, budget iniziali/source/publication/dispatcher/replay storico, circuiti/quote multi-run, capacità/retention/backpressure della quarantena e superfici operatore THS/MCP. I rolling counter circuit esistenti non sono nuove concessioni di budget. Nessuna migration/apply sul VPS, cutover, firma o replay R9/R10; precedente root preflight sospeso. Cinema/Teatri e gap PET/F0–F11 preservati. La suite DR prova la fixture nominata, non il recupero dell'intera piattaforma o dei nuovi ledger popolati sul target.

## Policy v3 — incidenti, catch-up e alert (11 October 2026)

Policy integrata approvata dall'owner: distinzione incidenti/eventi/lavori/notifiche, uno outage/una causa invece di5.000 issue equivalenti; priorità prima della limitazione; checkpoint consultazione distinto da login; crisi su segnali temporali e impatto/capacità, non assenza umana; alert attivi deduplicati con consegna durevole e budget finito. README/AGENTS e documenti principali richiamano la fonte canonica.

| Tranche v3 | Stato iniziale verificato |
|---|---|
| Capability summary/incidents/explain | Presenti nel manifest MCP; aggregazione Ingestion/Gateway/self; deploy/grant EVIDENCE PENDING |
| Priorità incidenti | Prima tranche di priorità owner/aggregata e catch-up qualificata per i perimetri sotto; cursor, impatto e selezione completa OPEN |
| Dedup dipendenza e5.000 lavori | Contratto PET presente; chiusura multirun/multi-owner OPEN |
| Checkpoint operatore/cursor | Query since bounded presente; checkpoint durevole accesso/consultazione e cursor completi OPEN |
| Crisi/capacità/isteresi | Circuiti legacy parziali; integrazione policy v3 e prove OPEN |
| Alert email/outbox/escalation | Policy registrata; configurazione trasporto/destinatari e implementazione OPEN; nessuna email inviata |
| Piano di controllo non disponibile | Monitor indipendente/configurazione operativa da qualificare; OPEN |

La policy non dichiara implementate le righe OPEN, non risolve R10 e non autorizza implicitamente replay, deploy o decisioni HUMAN di dominio.

## Prima tranche Operational Awareness integrata e qualificata

- [MCP PR51](https://github.com/GioNob/ouf-mcp-server/pull/51), merge71631d920cc8991d8786c21e4b4826e28a3cada0; candidato9c458fb3662147a39d642631f15e93be4ef80bb0. Priorità unresolved/severity/action/time prima del limite, tie deterministici, troncamento locale/producer e selectionScope esplicito. [Full38105960598](https://github.com/GioNob/ouf-mcp-server/actions/runs/38105960598), job114371431690 SUCCESS; [race38105960600](https://github.com/GioNob/ouf-mcp-server/actions/runs/38105960600),14 test operational top-level,5 nuovi. Tutti i sei gate candidato push/PR SUCCESS, inclusi PostgreSQL/migrazioni, pairwise, conformance, staticcheck e govulncheck.
- [Ingestion PR35](https://github.com/GioNob/ouf-ingestion-runtime/pull/35), mergeddc6104c97a1d8817e61173862b71a01e405c5ae; candidato7883c73a8f69da7fb28276d05e33bfa1b061abc7. Priorità SQL prima del LIMIT e since sulla proiezione last-seen, includendo risoluzioni di issue vecchie. [Native38105677637](https://github.com/GioNob/ouf-ingestion-runtime/actions/runs/38105677637),21 test inclusi3 nuovi/2 authorization/16 HUMAN. [Module38105677584](https://github.com/GioNob/ouf-ingestion-runtime/actions/runs/38105677584),137 test PASS, container/supply-chain/DR SUCCESS; candidate push owner/SDK/R2a/R2b/R2c/GIS/frozen/continuity SUCCESS.
- [Gateway PR59](https://github.com/GioNob/ouf-api-gateway/pull/59), merge92987cf7089e95b1c1c79ad76bcd9bf56c0b1d1b; candidato8429e7af376fa0f7c5ea923617dfe75288c79168. Reference adapter SQLite: priorità owner, conteggi dell'intera finestra, troncamento, since timezone-aware e recuperi vecchi nel catch-up. [38105584454](https://github.com/GioNob/ouf-api-gateway/actions/runs/38105584454) e38105586013 SUCCESS:229 test/2 skipped,1 APISIX reale e1 Authorization pairwise;6 nuovi casi di regressione.

### Sicurezza emersa durante la qualifica

Il primo gate completo MCP38105699846 rilevò10 vulnerabilità raggiungibili preesistenti nel Go1.25.13 e x/text0.39.0. Aggiornati compiler/verifica/CI a Go1.26.9, x/text0.41.0 e x/sync0.22.0 selezionato da tidy; Staticcheck2026.1. Input/checksum generati e verificati in38105883793/job114371210960. Gate finale:0 vulnerabilità raggiungibili;1 finding in modulo richiesto fuori dal codice chiamato, non una certificazione di assenza assoluta di vulnerabilità. Nessuna suppression o disabilitazione di gate. I precedenti fallimenti gofmt sono conservati nella storia; formattazione corretta e suite ripetute.

[Evidenza strutturata](../evidence/operational-priority-qualified-20261011.json) · [Piano organico di allineamento](OUF_OPERATIONAL_RESILIENCE_PLAN.md)

### Limiti che restano aperti

Questa tranche rende coerenti i candidati restituiti; non prova la priorità globale di tutti gli incidenti dopo paginazione/redazione. Serve completare cursor/coverage, last-transition ledger (Ingestion della prima tranche aveva solo created/resolved; la seconda aggiunge observation time), checkpoint accesso/consultazione, urgenze OPEN oltre la finestra, dedup di dipendenza tra job e conteggi impatto, detector sistemico/quote/capacità, outbox email/escalation e monitoring esterno. Summary legacy di finestra non è prova della salute corrente. Gateway SQLite è un reference adapter, non prova dell'hosting/datastore/tenant runtime di produzione.

Nessun deploy/migrazione/restart sul VPS, traffico/provider call o email effettuati. R9/R10 consumati, preflight root sospeso e gap target/PET restano. Nuovi default/policy non generano grant HUMAN di dominio.


## Seconda tranche Operational Awareness integrata e qualificata

- [MCP PR52](https://github.com/GioNob/ouf-mcp-server/pull/52), merge 27ceed89709e7735f68145d335c9ef0c4d1df5d9; candidato 0f8006711895cfb82166e8a3e22fb7c3bf29a00c. Rivalutazione owner di principal/capability/tenant/scope/detail prima di I/O, query tipizzata per tutti i canali, self-state con allowlist fissa e producer incompleto/unknown esplicito. Limiti64KiB request/512KiB producer e risposta finale. [Race38117976185](https://github.com/GioNob/ouf-mcp-server/actions/runs/38117976185), job114406647995:20 test operational top-level,6 nuovi gruppi. [Full38117976205](https://github.com/GioNob/ouf-mcp-server/actions/runs/38117976205), job114406648113, e38117978398/job114406654488 SUCCESS; tutti6 gate push/PR SUCCESS incluse migrazioni/PostgreSQL/pairwise/conformance/staticcheck/govulncheck.0 vulnerabilità raggiungibili,1 finding in modulo richiesto fuori dal codice chiamato.
- [Ingestion PR36](https://github.com/GioNob/ouf-ingestion-runtime/pull/36), merge 736a66eed3fb634e3915748d35f45cf942b030e3; candidato 50595a5b63c5236c9802964a69f934189a4b42cf. V16 additiva mantiene last_updated_at owner per tutte le modifiche reali e nuove osservazioni; first-seen storico distinto dalla persistenza di oggi. Metadata/reopening, no-op, rollback, tentativi di cambiare timestamp, tenant e backfill su tabella legacy popolata qualificati. [Native38117925912](https://github.com/GioNob/ouf-ingestion-runtime/actions/runs/38117925912), job114406491988:28 test (10 observation/priority,7 nuovi;2 authorization;16 HUMAN). [Module38117926040](https://github.com/GioNob/ouf-ingestion-runtime/actions/runs/38117926040), job114406492570:144 test senza failure/error/skipped, container/nonroot/supply-chain/DR SUCCESS; tutti18 gate candidato push/PR SUCCESS.

[Evidenza strutturata](../evidence/operational-read-catchup-qualified-20261011.json) presente anche nei due owner. README e documenti owner aggiornati; [design cursor/consultazione](OUF_OPERATIONAL_CURSOR_DESIGN.md) pubblicato e richiamato dal piano.

La prima qualifica MCP38117580577 fallì formattazione: applicato gofmt nativo. Il candidato intermedio38117671054 attempt1 fallì soltanto il test Reserve p95 PostgreSQL preesistente (59,45ms, soglia25ms); una riesecuzione del job fallito passò attempt2. Soglia/test non rilassati; il candidato finale ha tutti i gate SUCCESS. Ingestion38117719754 aveva27 test sul candidato precedente: aggiunto il caso nuovo incidente con first-seen storico, suite finale28 e full144.

### Confini ancora OPEN

Un timestamp persistente non è un revision ledger commit-ordered o un cursor: transazioni tardive possono ancora attraversare il confine temporale. Le query since richiedono overlap/dedup e non avanzano un checkpoint operatore completo. Le vecchie modifiche non storicizzate non sono ricostruite dal backfill. Cursor/snapshot/coverage globale, checkpoint e ricevute di consultazione, summary salute corrente separata dalla finestra, dedup dipendenza/multirun e impatto, capacità/retention/circuiti/quote, outbox/escalation e monitoring indipendente restano OPEN.

Prove repository/fixture non qualificano deployment, grant reali o rete target. Nessuna migrazione/deploy/restart VPS, provider call, email o grant HUMAN di dominio; R9/R10 restano consumati, preflight root sospeso e gap PET/F0–F11 preservati. Adozione completa di piattaforma non conclusa.


## Owner cursor e pressione — avanzamento autonomo 11 ottobre 2026

Integrate e qualificate [Ingestion PR37](https://github.com/GioNob/ouf-ingestion-runtime/pull/37): V17 ledger immutabile/publicazione per tenant commit-ordered e pagine persistenti con autorizzazione corrente;37 test PostgreSQL focused e18 gate push/PR. [Gateway PR60](https://github.com/GioNob/ouf-api-gateway/pull/60):243 test/2 skip espliciti e APISIX reale, UPSERT dedup concorrente, snapshot SQLite e local policy port fail-closed, binding identità/tenant/policy e digest. Non è una nuova autorità centrale di incidenti.

[Gateway PR61](https://github.com/GioNob/ouf-api-gateway/pull/61) ripara il server pairwise loopback corrente con service identity governata e prova custom identity/forgery. [Gateway PR62](https://github.com/GioNob/ouf-api-gateway/pull/62) implementa il reference controller persistente di pressione attuale:13 gruppi focused, inclusi outage3ore, hysteresis, ripresa1/2/4/8, scope indipendenti e assenza operatore31giorni che non crea crisi da issue storiche. Tutti i gate Gateway PASS. La prenotazione di capacità è ancora un contratto di decisione: sampler/scheduler e quota distribuita target OPEN.

[MCP PR53](https://github.com/GioNob/ouf-mcp-server/pull/53) in qualifica nativa: resource scope owner-specific e chiavi nested su argomenti canonici. Il nuovo pin pairwise ha esposto drift del vecchio fixture host e delle aspettative hard-coded `ouf-mcp-server`: riparati verso la reference IAM installation governata; gate mantenuti, non disabilitati. Stato candidato MCP registrato nell'[evidenza](../evidence/operational-owner-pages-qualified-20261011.json).

OPEN: cursor globale e ricevuta/bookmark operatore su revisione, copertura completa da vecchie modifiche, retention transizioni e hosting HA/local SDK reali, grouping multirun/impatti, sampler/quote/circuiti runtime, outbox alert e monitor indipendente. Le query timestamp non avanzano un checkpoint completo. Nessuna migrazione, restart, email o traffico VPS; R9/R10 consumati e preflight sospeso.
