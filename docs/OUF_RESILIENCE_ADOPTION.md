# Platform resilience v3 — adoption ledger (11 October 2026)

[Normative policy](OUF_RESILIENCE_POLICY.md). The owner's decisions authorize implementation choices consistent with the PETs/AWS references; they do not manufacture runtime HUMAN grants or reopen consumed target activation claims.

| Tranche | Concrete boundary | Status |
|---|---|---|
| Public publication resume | MCP PR61: HTTP/tool globale qualificati,20 gate PASS; coverage GATEWAY/INGESTION | MERGED; client receipt, altre storie owner e target OPEN |
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


### Qualifica MCP conclusa e outbox reference integrata

[MCP PR53](https://github.com/GioNob/ouf-mcp-server/pull/53) integrata, merge7f38f11f39cc5c7526a70fab2b9e50fadeb0ea8c, candidatoead7568d780ac88fa1f4dfcce78ba407104e2e5d:23 operational race top-level/33 subtest, tutti6 gate PASS; full38121619631 e PR38121623166, PostgreSQL/migrazioni/maintenance, pairwise attuali, conformance/staticcheck/govulncheck con0 vulnerabilità raggiungibili. I drift del fixture e delle reference IAM installation sono corretti senza ripristinare pin storici o disabilitare controlli.

[Gateway PR63](https://github.com/GioNob/ouf-api-gateway/pull/63) integrata, merge4c126d59004bf459d1ef57eba7d36b67810a2cc9, candidato7c739bf2c70b0631179ce2b29708c057af902e7f:278 test/2 skip espliciti, Authorization pairwise e APISIX reale in38122320736/38122322990.20 nuovi gruppi outbox:5.000 eventi equivalenti→una consegna, budget128tentativi/24ore con backoff+jitter/Retry-After persistenti, nuova sessione HUMAN dopo esaurimento/CAS/storia mantenuta, UNKNOWN senza blind resend, query di riconciliazione finite, fencing worker, quote e nessuna perdita delle transizioni owner su capacità. Scope/tenant/resource autorizzati prima di I/O, payload/refs safe e nessuna configurazione reale di email.

[Contratto outbox reference](https://github.com/GioNob/ouf-api-gateway/blob/main/docs/OPERATIONAL_ALERT_OUTBOX_REFERENCE.md): non è un canale email attivo. SDK/trasporto reale, timeout e ricevute provider provate, custodia/destinatari, scheduler, HA/retention e capability di conferma/rinnovo pubbliche restano OPEN. Primitive interne con test grant non creano autorità HUMAN nel runtime. Un receipt provider non è lettura, presa in carico o chiusura incidente. Continua lo sviluppo autonomo di cursor globale e metadati/ACK di consultazione; nessuna richiesta di nuova autorizzazione allo sviluppo.


### Cursor MCP persistenti qualificati; composizione in sviluppo

[MCP PR54](https://github.com/GioNob/ouf-mcp-server/pull/54) integrata (`61643ba0d4d5b6bdadf61537af96c141125319df`) dopo tutti gli otto gate push/PR PASS sul candidato `85ccdb9fe356d4f3fa4b70d158fc6f86109fd2c3`. Run dedicata [38123408694](https://github.com/GioNob/ouf-mcp-server/actions/runs/38123408694): due gruppi Go/race per binding canonico e metadati senza segreti, sei gruppi PostgreSQL reali per riavvio, concorrenza/CAS, replay, scadenza immutabile, scope/finalità e capacità finite. Full lifecycle/maintenance/pairwise correnti, conformance e sicurezza mantenuti e PASS.

[Contratto metadata](https://github.com/GioNob/ouf-mcp-server/blob/main/docs/OPERATIONAL_CURSOR_METADATA.md): store MCP esistente, nessun payload incidenti/delega/grant conservato, quote e TTL 30 minuti, append monotono/digest/posizioni protette. Il digest pagina non è prova di consegna; `consultationRecorded=false` e checkpoint operatore invariato.

[MCP PR55](https://github.com/GioNob/ouf-mcp-server/pull/55) sviluppa il merge bounded delle pagine owner con rilettura autorizzata, scope source salvato e fencing delle modifiche; qualifica in corso. In verifica anche la delega delle chiamate interne: il profilo APISIX status storico elimina la prova e non materializza automaticamente le query aggregate. Non verrà dichiarato funzionante il percorso target senza mediatore qualificato, budget composto e SDK owner reale. Bookmark su revisione, ricevuta client/checkpoint, retention e hosting restano OPEN. Sviluppo autonomo prosegue; nessun intervento operatore necessario per questi lavori di repository. Nessun deploy/VPS/R9/R10 applicato.


### Cursor e delega operativa qualificati; budget composto in verifica

[MCP PR55](https://github.com/GioNob/ouf-mcp-server/pull/55) integrata:10 gruppi di composizione race,2 binding/metadati e6 PostgreSQL; tutti8 gate PASS. Merge `14203ac8b2d96c9c4e7aac003022052f9d7088ec`. Merge bounded delle pagine owner, autorizzazione/digest attuali, quota di chiamate per pagina, ordine stabile e nessuna progressione su owner mancante/redatto/cambiato; è ancora una primitiva interna senza ricevuta operatore.

[Gateway PR64](https://github.com/GioNob/ouf-api-gateway/pull/64) integrata, merge `403787c957cc63d18164c2a1b8e46eadaa2329d8`:316 test Python/2 skip, Authorization pairwise e APISIX/OIDC reale PASS nelle run38124765609/38124768276. Sei rotte READ fisse, producer nascosti/tool-ineligible, delega HUMAN firmata verificata e conservata solo verso il MCP aggregate; bearer e proof eliminati verso gli altri owner. Permessi fine owner restano obbligatori.

[MCP PR56](https://github.com/GioNob/ouf-mcp-server/pull/56) integrata, merge `103541d17b6f21c553b8fc8cceac815da5da7bf0`:tutti10 gate PASS, Service reale con `RequireDelegation=true`,2 gruppi aggregate più2 HTTP, full38125049185 e dedicated38125049199. Contesto vincolato a workload configurato/HUMAN/capability/marker Gateway; nessuna disabilitazione della guardia, serializzazione proof o autorità HUMAN sintetizzata.

[Evidenza strutturata](../evidence/operational-cursor-delegation-qualified-20261011.json) e [contratto delega](https://github.com/GioNob/ouf-mcp-server/blob/main/docs/OPERATIONAL_AGGREGATE_DELEGATION.md). La verifica del registro reale ha mostrato che il vecchio window comune da3 chiamate e l'equivalenza delle riletture della stessa pagina impediscono una consultazione completa: [PR57](https://github.com/GioNob/ouf-mcp-server/pull/57) introduce un profilo control finito separato, contabilizzazione root+producer, retry dei soli abort DB provati dopo rollback e posizione cursor persistita nel fingerprint. Qualifica in corso; nessun aggiramento con nuovi ID/riavvii o rinnovo dei budget business.

Restano OPEN schema/handler globale, bookmark publication-boundary/retention, capability separata con ricevuta client e checkpoint operatore monotono, host Gateway/SDK/network/HA target. `consultationRecorded=false`. Nessuna migrazione/deploy/riavvio/email/VPS o replay R9/R10. Sviluppo autonomo prosegue verso questi gate.


### Budget control persistente qualificato e integrato

[MCP PR57](https://github.com/GioNob/ouf-mcp-server/pull/57) integrata (`652173dd16f4bc5645c70eafac3a713c76e91d9c`), candidato `4ae3e9a10ae54759bf31611d7f07fd9949c5c505`: tutti12 gate push/PR PASS, incluso PostgreSQL reale con Service/aggregate HTTP. Profilo control server-owned finito24 chiamate/minuto,12MiB e2.400 oggetti, distinto dal budget business; guardia semantica invariata, idempotenza preservata, nuovi ID/riavvii non rinnovano il window. Root e2 producer concorrenti contabilizzati, esaurimento persistente e indipendenza business verificati. Riletture cursor autorizzate usano chiavi fresche ma stesso budget; fingerprint legato alla posizione immutabile salvata. Abort serializable/deadlock provati soltanto: massimo3 tentativi/2secondi dopo rollback, senza retry di effetti ambigui.

[Contratto](https://github.com/GioNob/ouf-mcp-server/blob/main/docs/OPERATIONAL_CONTROL_BUDGET.md), [evidenza](../evidence/operational-control-budget-qualified-20261011.json). Avanza ora il collegamento schema/handler pubblico cursor. Bookmark publication-boundary, ricevuta client/checkpoint, target SDK/network/HA e alert reali restano OPEN. Nessuna consultazione registrata, migrazione/deploy/VPS/email o replay R9/R10.


### Mediatore globale cursor integrato; HTTP/tool MCP in qualifica

[Gateway PR65](https://github.com/GioNob/ouf-api-gateway/pull/65) integrata (`5795d304c497cfec22f9cd96682e0cbb6e551ce3`), candidato `eccd2bd94b47bce0bf9a0a1cd106b480e6c2c330`:318 test Python/2 skip espliciti, Authorization pairwise e APISIX/OIDC reale PASS nelle run38126444086/38126445507. Snapshot globale esplicito e cursor-only accettati sulle rotte fisse; mix/null/UUID zero o non canonici rifiutati. Produttori nascosti, proof solo al MCP aggregate e permessi correnti invariati.

[MCP PR58](https://github.com/GioNob/ouf-mcp-server/pull/58) collega store PostgreSQL, owner HTTP e schema/tool opt-in. Le prime prove race/HTTP e PostgreSQL sono PASS (38126499545):root+2 producer consumano9 chiamate su3 letture, anche ricreando il handler su uno store riaperto. Revoca root e cambio principal bloccano prima di producer I/O; errori/modifiche non avanzano la pagina. La verifica del decoder MCP ha rilevato campi snapshot/cursor mancanti:correzione e prova col client ufficiale aggiunte, qualifica finale in corso. Il replay admission senza payload produce errore esplicito, non una pagina vuota riuscita. Non è ancora dichiarato integrato o attivo sul target.

Proseguono i gate bookmark su publication-boundary e ricevuta esplicita/checkpoint di consultazione, distinti dai cursor e dai timestamp. SDK/hosting/HA target, sampler/circuiti e consegna alert reali restano OPEN. Nessun acknowledgement o consultazione registrato implicitamente; nessuna migrazione/deploy/riavvio/email/VPS o replay R9/R10.


### Percorso MCP snapshot/cursor qualificato; bookmark Gateway reference integrato

[MCP PR58](https://github.com/GioNob/ouf-mcp-server/pull/58) integrata (`22f23ae2a870b26a4b63d82e1995e6f1d03633a3`), candidato `4a3bffd1954b3fc243fd38cdd7c1a90219a10e09`:tutti14 gate push/PR PASS. Decoder/schema col client ufficiale, root Service/admission e forward semantico qualificati; HTTP race con revoca/current decision, principal fencing, replay e owner outage/modifica senza avanzamento. PostgreSQL reale HTTP+Service conta9 chiamate su3 letture(root+2 producer), anche su metadata store riaperto. Replay admission senza payload è errore esplicito e non NO_INCIDENTS. Il fixture ora allinea le prove alla stessa finestra del clock PostgreSQL, senza cambiare il rinnovo naturale del profilo control. Il Gateway associato PR65 è già qualificato con APISIX/OIDC reale.

[Gateway PR66](https://github.com/GioNob/ouf-api-gateway/pull/66) integrata (`cd805cc28dc0e14fc98b8098de790bcf13167e6d`), candidato `2de71da0df8ff04fe6b519f8794684c8dd47d4be`:327 test/2 skip, Authorization pairwise e APISIX PASS nelle run38127606679/38127609462.9 gruppi bookmark reference:nuove pubblicazioni con timestamp vecchio, resume dopo scadenza pagina/restart/login, catena completa e non redatta, replay, identità/policy/current revocation, scope immutabile e input chiuso, metadati immutabili/nessun payload, gap/expiry/floor monotono, capacità persistente finita con scritture incidenti indipendenti, risposta SDK sconosciuta non trattata come permesso. [Contratto](https://github.com/GioNob/ouf-api-gateway/blob/main/docs/OPERATIONAL_PUBLICATION_BOOKMARKS_REFERENCE.md).

[Evidenza strutturata](../evidence/operational-cursor-http-bookmark-qualified-20261011.json). Il bookmark Gateway è ancora una primitiva privata con port SDK host obbligatorio, senza nuova rotta o tool. I bookmark Ingestion devono usare la publication clock/pending ledger PostgreSQL, non il bigserial privato; implementazione successiva in corso. Vector/bookmark globale, ricevuta esplicita client/checkpoint/CAS, host/SDK/HA/history compactor e invio alert reali restano OPEN. Letture e bookmark mantengono consultationRecorded=false. Nessuna migrazione/deploy/VPS/email o replay R9/R10.


### Bookmark owner persistenti qualificati e integrati

[Ingestion PR38](https://github.com/GioNob/ouf-ingestion-runtime/pull/38) integrata (`a4cfd2a8454dc98cd5b4f686582b88cdafb5eaca`): tutti18 gate PASS,47 prove PostgreSQL mirate e163 test del modulo completo senza errori. Il boundary segue la publication clock tenant/pending ledger impegnata, non il bigserial privato: una transazione iniziata prima ma pubblicata dopo il bookmark viene recuperata. Verificati scadenza pagine/login/recreazione, catena completa senza redazioni, policy/identità/grant correnti, gap/retention, quote persistenti con scritture incidenti indipendenti, concorrenza e metadati immutabili. [Contratto owner](https://github.com/GioNob/ouf-ingestion-runtime/blob/main/docs/INCIDENT_PUBLICATION_BOOKMARKS.md).

[Gateway PR67](https://github.com/GioNob/ouf-api-gateway/pull/67) integrata (`c0eb82a2dfd02396d597517e2fc6adb648c68c86`):330 test Python/2 skip, pairwise Authorization e APISIX/OIDC reale PASS.12 gruppi bookmark reference includono ora frame immutabile verificato prima della progressione, migrazione dei vecchi scope senza attribuire retroattivamente un digest e riuso del bookmark se non vi sono pubblicazioni nuove. Anche Ingestion riusa il boundary equivalente: i polling senza novità non consumano indefinitamente posizioni persistenti.

[Evidenza strutturata](../evidence/operational-publication-bookmarks-qualified-20261011.json). Entrambi sono ancora primitive owner private: trasporto HTTP bookmark, vettore globale MCP e conferma client/checkpoint/CAS sono i passi successivi. Un bookmark è una posizione di lettura, non consegna, consultazione o acknowledgement. History compactor, SDK/hosting/HA target e alert reali restano OPEN. Nessuna migrazione/deploy/VPS/email o replay R9/R10; `consultationRecorded=false`.


### Trasporto HTTP bookmark owner qualificato

[Gateway PR68](https://github.com/GioNob/ouf-api-gateway/pull/68) integrata (`341488904a4382a73adb425e121db0cce499642c`):342 test Python/2 skip, Authorization pairwise e APISIX/OIDC reale PASS. Gli endpoint producer nascosti ammettono soltanto coverage snapshot, coverage cursor oppure resumeFrom canonico; summary e MCP globale rifiutano questi bookmark owner. Il reference adapter rivaluta collection/righe con viste di autorizzazione separate per richiesta; nessuna autorità condivisa mutabile.

[Ingestion PR39](https://github.com/GioNob/ouf-ingestion-runtime/pull/39) integrata (`30c69a777bbce53f3e9d5c1c53c709b0a908f4ad`):tutti18 gate PASS,50 prove PostgreSQL mirate e166 test completi. Spring collega il core qualificato all'endpoint incidents READ; resume eredita source/state e controlla grant correnti. Decoder streaming rifiuta duplicati/null/campi sconosciuti/mix/UUID non canonici prima di owner I/O. Verificati nuovo login, redazione pagina, revoca/policy e richieste malformate senza scritture. Contratti [Gateway](https://github.com/GioNob/ouf-api-gateway/blob/main/docs/OPERATIONAL_PUBLICATION_BOOKMARK_HTTP.md) e [Ingestion](https://github.com/GioNob/ouf-ingestion-runtime/blob/main/docs/INCIDENT_PUBLICATION_BOOKMARKS.md).

Vettore globale persistente MCP e conferma client/checkpoint sono ancora OPEN; le posizioni owner non sono ricevute di lettura. History compactor, host SDK/HA target e alert reali restano gate distinti. `consultationRecorded=false`; nessun deploy/migrazione/VPS/email o replay R9/R10.


### Vettore publication persistente MCP qualificato

[MCP PR59](https://github.com/GioNob/ouf-mcp-server/pull/59) integrata (`f3246806abeb504fa396793c615e98f227cff5a2`), candidato `26d2bc20d45f760fd801cf7c614409d71d2bf2b6`:tutti16 gate push/PR PASS.3 gruppi Go/race su identità stabile, metadati chiusi e lineage,5 gruppi PostgreSQL reali su riapertura/scoping/policy, concorrenza/replay/idle, immutabilità/capacità/cursor indipendenti, scadenza/gap/cleanup e hash salvati incoerenti. Full CI e pairwise con i candidati qualificati Gateway PR68/Ingestion PR39 PASS.

[Contratto](https://github.com/GioNob/ouf-mcp-server/blob/main/docs/OPERATIONAL_PUBLICATION_VECTOR.md):solo metadati opachi delle publication owner GATEWAY/INGESTION,4KiB,90 giorni massimi,quote512 principal/4.096 tenant/32.768 global; cleanup massimo1 posizione scaduta, nessuna sostituzione delle posizioni vive. Nuovi login non cambiano l'identità stabile; policy/manifest restano correnti. Lineage per uguaglianza dei parent owner, mai ordine UUID/timestamp. Una posizione invariata riusa il token precedente; nessun payload/grant/receipt/checkpoint.

Il core è ancora privato: composizione/public HTTP/tool del vettore, storia eventi MCP, client receipt/COMMAND/CAS e dimensionamento/compactor/hosting target restano OPEN. Capacità esaurita blocca nuove posizioni e lascia leggibili le posizioni esistenti e i cursor indipendenti. Nessuna consultazione implicita o migrazione/deploy/VPS/email/R9/R10.


### Composizione publication bounded e mediatore globale qualificati

[MCP PR60](https://github.com/GioNob/ouf-mcp-server/pull/60) integrata (`fe2929062004faa59265228ebfa37e67e7c8a0d5`), tutti18 gate PASS.5 gruppi nuovi Go/race verificano catena root completa/replay senza consultazione, resume con nuovo login e pagine temporanee scadute, token owner esatti/source SDK salvata, outage/modifiche/capacità senza avanzamento, filtri chiusi e parent/no-progress coerenti. PostgreSQL reale qualifica anche l'immutabilità del capture publication tra append; tutti i gate cursor/control/vector e full pairwise rimangono PASS. I filtri Unicode semanticamente equivalenti hanno ora una sola rappresentazione canonica.

[Gateway PR69](https://github.com/GioNob/ouf-api-gateway/pull/69) integrata (`fc8fdcfbfe9f758241aac3219ce9adecb688d40d`):342 test/2 skip, Authorization pairwise e APISIX/OIDC PASS. La rotta fissa MCP incidents media coverage snapshot/page/resume e conserva la delega verificata soltanto verso l'aggregate; token owner non diventano autorità globale. Il backend MCP deve qualificare separatamente lookup/vettore e HTTP/tool; fino a quel gate il suo rifiuto esplicito resta corretto.

[Contratto composizione](https://github.com/GioNob/ouf-mcp-server/blob/main/docs/OPERATIONAL_PUBLICATION_COMPOSITION.md):limite2,5 secondi e massimo3 letture owner per pagina, persistenti budget control, nessun payload/grant salvato e nessun nuovo ciclo retry. L'output distingue publicationModules GATEWAY/INGESTION, mcpSelfHistoryCovered=false e lettura corrente degli OPEN urgenti necessaria. Queste primitive non sono un report completo della storia dei sette moduli né una ricevuta operatore. HTTP/tool pubblico publication in sviluppo; client receipt/COMMAND/CAS, compactor/capacità e host/SDK/HA target restano OPEN. Nessuna migrazione/deploy/VPS/email/R9/R10.


### Accesso pubblico publication e budget end-to-end qualificati

[MCP PR61](https://github.com/GioNob/ouf-mcp-server/pull/61) integrata (`d300d3154f63014cc4462e503590d03f79287e87`), candidato `ee4691cfb0a68ae9da9eb4fc29bcc5a61a4dc727`:tutti20 gate push/PR PASS, incluse suite completa/race, vet, staticcheck, govulncheck senza vulnerabilità, PostgreSQL, migrazione/manutenzione CI e pairwise con Gateway PR69/Ingestion PR39.3 nuovi gruppi HTTP qualificano catene complete, handler ricreato, nuovo login/pagine scadute, revoca/principal, history gap/outage e input chiusi; il client MCP ufficiale verifica forwarding tipizzato e rifiuto prima dell'admission. La nuova prova PostgreSQL attraversa l'orchestrazione e il root HTTP:primo accesso e2 resume idle dopo riapertura/login consumano9 chiamate nello stesso window persistente, senza reservation pendenti e con un solo bookmark conservato.

[Contratto pubblico](https://github.com/GioNob/ouf-mcp-server/blob/main/docs/OPERATIONAL_PUBLICATION_HTTP.md), [evidence](../evidence/operational-publication-http-qualified-20261011.json). Modalità chiuse:snapshot+coverage con filtri tipizzati, cursor+coverage, resumeFrom+limit opzionale e filtri salvati ereditati. SDK source/collection/row corrente e delega restano obbligatori; indisponibilità, invalidazione, capacità e storia scaduta sono esplicite. Coverage storica GATEWAY/INGESTION; `mcpSelfHistoryCovered=false`, lettura corrente degli OPEN urgenti separata. Nessuna ricevuta client, consultazione/checkpoint/CAS, nuova autorità di recovery o copertura dei sette moduli. Compactor/hosting/SDK/HA target e alert reali restano OPEN. Nessuna migrazione/deploy/VPS/email/R9/R10.
