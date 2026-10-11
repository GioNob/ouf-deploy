# Platform resilience v3 — adoption ledger (11 October 2026)

[Normative policy](OUF_RESILIENCE_POLICY.md). The owner's decisions authorize implementation choices consistent with the PETs/AWS references; they do not manufacture runtime HUMAN grants or reopen consumed target activation claims.

| Tranche | Concrete boundary | Status |
|---|---|---|
| Project rule | Policy v2 and AGENTS instructions in all seven OUF repos | RECORDED |
| Finite lease recovery protocol | Bounded pause/retry, durable journal, fresh DNS, finite TTL and revocation | QUALIFIED in isolated synthetic-authority CI38102725541;16 tests plus native DNS/nft and four virtual outage hours |
| HUMAN original-run recovery | New budget after exhaustion, preserved history, atomic grants, worker/session fencing, scheduler exclusion and ACK-gated issue resolution | MERGED PR34; PostgreSQL38104209271:35 tests; module38104209251:134 tests; all named candidate checks SUCCESS |
| Initial runs and publication/scheduler activation | Finite incident budget, job slots/checkpoint preservation, no automatic budget renewal | OPEN; scheduler exclusion of exhausted HUMAN run incidents is implemented, but source-health rolling circuit counters are not recovery grants |
| Dependency and downstream scope | Circuit isolation, retries at one owner level, downstream ambiguous-effect reconciliation and finite dispatcher/historical replay budgets | OPEN |
| Quarantine capacity and operator flow | Capacity/retention/backpressure, owner/age/severity, governed actions and safe MCP/THS projection | PARTIAL existing PET mechanisms; complete policy-v2 integration/tests OPEN |
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
| Priorità incidenti | Ordinamento aggregato alfabetico identificato; correzione e qualifica in corso, selezione producer da verificare |
| Dedup dipendenza e5.000 lavori | Contratto PET presente; chiusura multirun/multi-owner OPEN |
| Checkpoint operatore/cursor | Query since bounded presente; checkpoint durevole accesso/consultazione e cursor completi OPEN |
| Crisi/capacità/isteresi | Circuiti legacy parziali; integrazione policy v3 e prove OPEN |
| Alert email/outbox/escalation | Policy registrata; configurazione trasporto/destinatari e implementazione OPEN; nessuna email inviata |
| Piano di controllo non disponibile | Monitor indipendente/configurazione operativa da qualificare; OPEN |

La policy non dichiara implementate le righe OPEN, non risolve R10 e non autorizza implicitamente replay, deploy o decisioni HUMAN di dominio.
