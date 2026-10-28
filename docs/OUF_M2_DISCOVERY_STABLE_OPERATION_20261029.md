# M2 — Requisito vincolante: discovery stabilmente operativa

29 ottobre 2026, Europe/Rome. Estensione richiesta dall'owner al miniPET M2, versione1.3. Il prodotto deve eseguire il ciclo **chatbot → capability MCP OUF → Gateway → Registry → OntoPiA**. Una PR, un test isolato o una dimostrazione temporanea non chiudono questo obbligo.

## Criteri bloccanti

- **M2-DISC-STABLE-01 — OPEN.** Authorized chatbot clients discover and invoke request/status/candidates through the installed published MCP manifest; service/host/client restart does not silently remove the configured capability.
- **M2-DISC-STABLE-02 — OPEN.** Provider, Gateway binding, workload identity, scopes, policy, trust and secretRef custody are installation configuration with governed renewal/rotation; ordinary discovery does not require an ad hoc grant, terminal command or reconstructed identifier.
- **M2-DISC-STABLE-03 — OPEN.** One durable request and receipt survive interruption, lost response and restart; same intent/key is deduplicated, changed intent conflicts, and old generations cannot publish.
- **M2-DISC-STABLE-04 — OPEN.** Transient provider outages use finite persistent retry/backoff/jitter/Retry-After without holding locks; exhaustion, revocation, permanent/unknown errors and ambiguous effects remain visible and require governed reconciliation.
- **M2-DISC-STABLE-05 — OPEN.** Restart/reboot/rotation and recovery obtain current generation/admission and preserve cumulative history; no consumed authority, expired token or exhausted incident budget is reset or reused.
- **M2-DISC-STABLE-06 — OPEN.** A real OntoPiA request traverses chatbot/MCP/Gateway/Registry/provider with canonical URI/provenance and bounded parser-safe immutable snapshot; provider failure never becomes empty success.
- **M2-DISC-STABLE-07 — OPEN.** Candidate comparison, adoption, review/publication and pinned source mapping retain owner/HUMAN governance; manual web fetch/Turtle import and a new local ontology are not substitutes for the requested discovery.
- **M2-DISC-STABLE-08 — OPEN.** The same capability contract and recoverable context work on two independent real MCP clients, including one without embedded UI, with cross-tenant denial before serialization.

Questi criteri si aggiungono ai24AT,8UX e scenari canonici già obbligatori. Non sostituiscono o riducono il denominatore esistente. M2/G5/G6/G7 restano aperti finché le relative prove reali e la decisione finaleHUMAN non sono registrate.

## Separazione fra manutenzione e uso ordinario

Il percorso utente ordinario usa solo capability OUF e le superficiHUMAN previste. Installazione e manutenzione sono un percorso operatore distinto, circoscritto, qualificato e con concreta review/authority quando producono effetti. Non diventano passaggi da ripetere a ogni caricamento fonte.

“Stabile” non autorizza a trasformare revoche, scadenze o policy inALLOW, a tenere vecchi token attivi, ad azzerare budget o a riavviare worker su vecchie attestazioni. Le capability configurate devono persistere e mostrare uno stato operativo veritiero quando le dipendenze sono indisponibili.

Le prove devono distinguere: disponibilità del tool per l'utente autorizzato; readiness del percorso; ammissione della singola richiesta; completamento provider; candidatura semantica; adozione/pubblicazione. Nessuno di questi passaggi prova da solo il successivo.

## Stato reale al checkpoint

- Farmacie: stesso profiling completato,61righe/10colonne; policy59 e preview acquisite. Codice ministeriale stabile STRING e tutti10campi OPEN confermati.
- MCP PR81/09d1f521: composizione sorgente delle tre capability candidate e contratti qualificati; restano INACTIVE, non installate.
- Registry/file-only: il compilatore di quel profilo impone esplicitamente provider/worker discovery disabilitati. È un limite del profilo di installazione storico, non un risultato E2E accettabile per la nuova richiesta.
- Nuova cattura corrente: sorgente/delivery qualificate nella PR Deploy51. Legge solo metadata/Engine della coorte conservata; nessuna attivazione, credenziale, SQL o discovery. Non è ancora stata eseguita sul target.

## Prossimo tratto concreto

Eseguire una sola volta la [nuova cattura corrente](handoffs/OUF_M2_DISCOVERY_CURRENT_BINDINGS_20261029.md). Il risultato vincola i delta da comporre e qualificare per Registry/Gateway/provider. Le sole dichiarazioni Env non provano configurazione effettiva, readiness, custody o autorità.

Dopo le evidenze correnti: qualificare la coorte applicativa e la configurazione persistente, predisporre la concreta review della sola manutenzione necessaria, verificare readiness/ammissione e pubblicazione coordinata, quindi esercitare le vere capability dal chatbot. Nessuna attivazione di descrittori per far passare un test, nessun vecchio comando consumato, nessun aggiramento.
