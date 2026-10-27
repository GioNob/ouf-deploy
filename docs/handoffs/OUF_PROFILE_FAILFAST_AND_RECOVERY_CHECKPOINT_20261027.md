# Policy56 e primo delta D4 qualificato — recovery Farmacie ancora aperta

27 ottobre2026, Europe/Rome. Policy56 pubblicata HUMAN e verificata: proposta b045ada2-f1d6-4e4e-9beb-acf85d6474f7 r1 PUBLISHED/finalPolicyRef ouf-lab-authorization:56. [Ricevuta](../../evidence/onboarding-structural-object-read-proposal-20261027.json), [handoff precedente](OUF_FARMACIE_STRUCTURAL_SERVICE_READ_20261027.md). Il permesso SERVICE di staging è ora strutturale, revocabile, fino15set2036; token breve, controlli Gateway e budget finiti restano distinti. Il vecchio grant scaduto resta conservato. Non riproporre la stessa modifica.

## Codice già qualificato e riusato

Onboarding draftPR53, source 11e579366c90ace6dd67c3fec5643559b556f7d0: [prove CI](../../evidence/profile-failfast-source-qualification-20261027.json). Permanenti typed401/403, input invalidi e cause sconosciute/ambigue fermano subito i retry; solo HTTP429/502/503/504 typed e read-only richiedono retry entro il vecchio massimo5, rispettando Retry-After valido. Il body non viene letto su403. Una nuova chiave chat/MCP restituisce lo stesso unico job dell'asset immutabile; il lock asset impedisce la doppia ammissione concorrente. Una storia legacy con più job non viene adottata con una chiave nuova. La release quarantena cambia la disposizione dell'asset, non azzera tentativi o autorizza una nuova sessione.

CI push40524005251/job122258450075 PASS:305test/0failure/0error/0skip, package, immagine, scansione e boot nonroot. Diagnostica40524005177/job122258449645 PASS9/0skip; browser40524005299/job122258449858 PASS4/0skip e2latenza. Log diretti letti. Le regressioni PostgreSQL provano FAILED5 immutato con nuove chiavi,403 terminale dopo un tentativo, release quarantena senza nuovo budget, concorrenza e storia ambigua. Nessuna migrazione aggiunta. Typed CSV, ASSETS/LATEST, readiness-session e diagnostica precedenti conservati. Java locale indisponibile: nessun PASS locale inventato. CI non è prova server.

## Stato target e divieti di replay

Installata soltanto diagnostica minima a5ed8b05c264a8221783a6e323ba00117aed891d, non PR53. Asset9c502da5-b5d8-405e-b3f5-60eb31ecb513; job677480c8-3d10-44fd-9dad-f72ddeed20a4 FAILED, attempts5, resultRefnull. La preview55 e il lettore SERVICE sono consumati; nessuna nuova richiesta file/Gateway/token dopo56. Permesso configurato corretto non prova lettura efficace o causalità esclusiva del403 storico. Tutte capture/preparazioni/APPLY/continuation precedenti consumate: non ripetere.

## Prossimo lavoro D4 concreto

Completare e qualificare la recovery del profiling riusando il modello V35 managed_readiness_budget_session e i suoi controlli expected-version/generation, senza copiare un motore generico. Nuova sessione HUMAN finita, stesso logical operation/job/incident, actor/reason/decisionRef, limiti e scadenza espliciti, cumulative attempts monotoni e storia delle sessioni. Sessione nuova distinta da release quarantena e da grant SERVICE. Workers precedenti devono essere esclusi con fencing persistente; niente transazione condivisa durante attesa/file-read. Definire profilo versionato di elapsed-time/backoff/jitter/Retry-After e classificazione network typed; gli esiti sconosciuti restano bloccati. La history legacy multipla richiede riconciliazione, mai un altro job per aggirarla.

Questo primo delta non completa D4: delay fisso legacy, elapsed-time/sessioni HUMAN/fencing e integrazione quarantena/capacità restano aperti. Non chiamare source.file.profile con una nuova chiave, non aggiornare a mano FAILED/attempts e non usare SQL di manutenzione come autorità applicativa. Nessuna nuova preview è autorizzata implicitamente. Solo dopo codice e prove completi preparare una coorte aggiornata e una nuova review concreta necessaria al runtime; non reinstallare ogni frammento separatamente.

M1/G4 acquisito. M2/G5/G6/G7 restano aperti: D5 vocabolari/relazioni, composizione D2/D6 e accettazione D7 da completare. No merge/release acceptance/subagenti/automazioni/Registryrestart/reinstall; Supervisor dopo E2E completo.
