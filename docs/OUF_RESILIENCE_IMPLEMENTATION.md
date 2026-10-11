# Resilienza OUF: implementazione e chiusure residue

La [politica v1](OUF_RESILIENCE_POLICY.md) è il default di progetto dal11 ottobre2026. Gli AGENTS.md dei sette repository la richiamano; questo registra una regola di lavoro, non certifica ogni runtime esistente.

## Recupero finito delle lease qualificato

Sorgente587d436b972def56911c01d80d3bb1e0b5611035, [run38102725541](https://github.com/GioNob/ouf-deploy/actions/runs/38102725541), job114361821303 SUCCESS. [Evidenza](../evidence/bounded-resilient-lease-qualified-20261011.json).

- bounded_recovery.py: protocollo prospettico di recupero con deadline per tentativo, doppio budget tempo/tentativi, backoff/jitter/Retry-After, guardia locale durante la pausa, cancellazione, riconciliazione degli esiti incerti. ATTEMPTING/PUBLISHING persistiti prima degli effetti; nessun replay implicito.
- recovery_journal.py: checkpoint privato0700/0600, JSON limitato e senza chiavi duplicate, CAS/flock brevi, fsync e sostituzione atomica; nessun lock del journal durante callback/attese. Un journal già esistente o parzialmente inizializzato non viene ricreato.
- resilient_lease_adapter.py: revoca verificata degli unici set posseduti, nuove osservazioni DNS fuori dal lock condiviso, transazione atomica solo dopo nuova verifica di scope/configurazione/ownership, controllo TTL positivo e deadline in entrambe le famiglie. TTL troppo corto resta un'indisponibilità temporanea solo dopo revoca verificata; identità/integrità ignote bloccano.
-16 test significativi: outage virtuale4ore, limiti finiti, durata dei tentativi, Retry-After, jitter, revoca/cancellazione nella pausa, generazione/custodia/clock drift, esito ambiguo, journal POSIX riaperto, nessun lock sulle callback, errori storage prima del tentativo e dopo la pubblicazione, processo vivo a budget esaurito.
- Prova nativa: DNS UDP e nft effettivi in namespace CI isolato, quattro ore accelerate solo con set vuoti,21 tentativi, journal riaperto; DNS positivo ma finestra troppo corta mantiene la pausa; DNS fresco sufficiente apre entrambe le famiglie; revoca successiva blocca query. Scope, profilo CI e metadata sono sintetici. Vecchie fonti/claim sintetici invariati.

## Condizioni per collegare il prossimo worker

Il controller gestisce un episodio di recupero; ACTIVE restituisce il controllo al normale owner. Non è ancora il servizio di rinnovo target. L'entrypoint deve:

1. Verificare custodia di tutti gli antenati, file/moduli/comandi immutabili, fonte e complete OCI/peer/generazioni reali; costruire un nuovo scope finito per recupero e revoca. Il helper journal non concede questa autorità.
2. Legare policyHash, contextRef, generationRef e journal al nuovo claim proprio; nessun reset di budget, ricreazione automatica del journal o riuso della claim R10 consumata. Stato inflight dopo crash richiede riconciliazione.
3. Richiamare il recupero per guasti transitori nella supervisione di rinnovo; mantenere il loop locale osservabile nei parked state, liveness distinta dalla readiness, cancellazione/revoca verificata, incidentId e dedup persistenti. Nessun lock condiviso durante backoff/DNS.
4. Applicare le deadline nei trasporti e nei comandi: il controller fornisce la deadline ma non può interrompere callback Python arbitrarie. Qualificare guasti e latenze del nuovo servizio reale, non dedurre disponibilità dalla sola prova isolata.
5. Gestire RECOVERY_JOURNAL_OR_STATE_UNPROVEN e SAFE_PAUSE_AND_RECOVERY_STATE_UNPROVEN come blocchi osservabili senza nuovi effetti/retry: la prima prova la pausa; la seconda non la prova. Se la persistenza è inaffidabile non si inventa un checkpoint o un nuovo budget. Il wrapper tenta la revoca indipendente prima di segnalare l'errore.
6. Provare la nuova chiusura completa prima di qualsiasi apply target; il precedente preflight root è sospeso. Nessun R10 restart/enablement, nuova firma, grant HUMAN o cutover implicito.

## Adozione negli altri percorsi

| Owner | Criterio di chiusura per il proprio runtime |
|---|---|
| Ingestion | Ripresa dal checkpoint committed, stesso ingestionRunId/idempotency key, nessun lock/TX nelle attese; outage, dedup e catch-up OA persistenti. PET1.3 §15/§24/§46. |
| UDP/Lake | Pause delle dipendenze senza duplicare materializzazioni/ACK; conservare identità, lineage e budget di risoluzione; riconciliare scritture ambigue. PET1.3. |
| Semantic | Worker/job e dipendenze provider con checkpoint e budget finiti; recovery distinto da approve/publish e da salute applicativa. PET1.3. |
| Onboarding/THS | Conservare versioni ACTIVE e decisioni umane; retry delle sole operazioni sicure, mai duplicare approvazioni/proposte. PET1.6. |
| Gateway | Retry solo read-only/idempotenti o con dedup provata; default deny e allowlist DNS/lease, revoca senza estendere TTLzero. PET1.5 T11/T11.3. |
| MCP | Proiezioni owner/capability/readiness coerenti, OA con incidente deduplicato e catch-up autorizzato; nessun nuovo dominio di autorità. PET1.4. |
| Deploy | Custodia e combinazioni source-bound, prove native/fault della combinazione candidata; nessun retry cieco di apply monouso. Blueprint/Matrix1.7 e PET owner. |

Questi sono criteri da verificare e integrare nei percorsi esistenti, non dichiarazioni di conformità già raggiunta. R3, acceptance completa e residui F0–F11 rimangono aperti; Cinema e Teatri già acquisiti si conservano.


## 11 ottobre2026 — policy di piattaforma v2 e prima tranche HUMAN integrata

L'owner ha confermato quarantena persistente, isolamento dello scope indipendente, budget finiti, nuovi budget concessi da HUMAN, sessioni atomiche/fencing, capacità protetta e recupero graduale. [Policy v2](https://github.com/GioNob/ouf-deploy/blob/main/docs/OUF_RESILIENCE_POLICY.md) e AGENTS.md aggiornati nei sette repository; [registro di adozione](https://github.com/GioNob/ouf-deploy/blob/main/docs/OUF_RESILIENCE_ADOPTION.md). Riferimenti PET/AWS nominati nel documento, nessun nuovo broker/incident service o grant di dominio implicito.

[Ingestion PR34](https://github.com/GioNob/ouf-ingestion-runtime/pull/34) integrata in main, merge6f583ca6b226a63c4a9b55df19f28728c4fd9348. Candidato qualificato80bcb2f8c1f478c0b6d18c46b9eeff5cede5f68f: [PostgreSQL38104209271](https://github.com/GioNob/ouf-ingestion-runtime/actions/runs/38104209271), job114366142916,35 test PASS inclusi16 nuovi; [module38104209251](https://github.com/GioNob/ouf-ingestion-runtime/actions/runs/38104209251),134 test senza errori/failure e controlli supply-chain/nonroot/DR SUCCESS. Tutti gli altri gate owner/pairwise/serving/publication/GIS/continuity sullo stesso candidato sono SUCCESS. [Evidenza](https://github.com/GioNob/ouf-ingestion-runtime/blob/main/evidence/human-recovery-budget-qualified-20261011.json).

V15 additiva introduce un ledger di sessioni, non reset del budget storico. La ripresa originale del run PAUSED richiede HUMAN+capability+tenant+decisionRef e preflight baseline fuori dalla TX; grant/sessione e cambio stato atomici su control_version. Default versionato128 batch owner/24ore, limite100 record/45secondi del loop per batch, una batch recovery posseduta alla volta; limiti finiti personalizzabili. Non è il conteggio di tutti i retry HTTP. Budget verificato prima I/O e pubblicazione; risultato remoto tardivo non avanza handoff/checkpoint. Scheduler non crea nuovi run intorno all'incidente esaurito OPEN, vecchi claim e percorsi unclaimed non aggirano la sessione. Issue risolta soltanto dopo completamento reale e ACK/drain. Dati/checkpoint/lineage/idempotency e storico fallito preservati.

La prima prova38104025072 fallì soltanto per operatore JSON ? nella query di test con JdbcClient; correzione jsonb_exists, senza modificare quel comportamento produttivo, e riesecuzione PASS. La fixture legacy HUMAN_USER è stata allineata a HUMAN+capability del SDK, non rilassata l'autorizzazione.

Adozione completa ancora aperta: retry automatici del worker, budget iniziali/source/publication/dispatcher/replay storico, circuiti/quote multi-run, capacità/retention/backpressure della quarantena e superfici operatore THS/MCP. I rolling counter circuit esistenti non sono nuove concessioni di budget. Nessuna migration/apply sul VPS, cutover, firma o replay R9/R10; precedente root preflight sospeso. Cinema/Teatri e gap PET/F0–F11 preservati. La suite DR prova la fixture nominata, non il recupero dell'intera piattaforma o dei nuovi ledger popolati sul target.
