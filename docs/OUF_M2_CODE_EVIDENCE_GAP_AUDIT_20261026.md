# OUF — Audit M2: codice, prove riusabili e lacune reali

26 ottobre 2026 · Europe/Rome · Base documentale `d0e06383c5ab700f266971a76e28ecda8d0f118b`.  
[Mini-PET 1.2](OUF_M2_MINIPET_v1_0_20261026.md) · [Roadmap](OUF_M2_ROADMAP_20261026.md) · [Inventario verificabile](../evidence/csv-m2-code-evidence-gap-audit-20261026.json).

## Esito

**Una parte sostanziale di quanto era descritto come lavoro M2 è già implementata e qualificata.** Oltre a M1 sul VPS, esistono tipi decimal/date composti fra tre owner, ripresa ASSETS/LATEST, riconciliazione di proprietà e recovery di Ingestion/UDP. Esiste anche una prova isolata di due acquisizioni con stessi file/configurazione senza nuova revisione canonica. Queste attività escono dal conteggio di nuovo sviluppo.

Il residuo verificato è: integrare branch già esistenti con gli hardening successivi; completare la discovery del job/lavoro; correggere la policy di errore/recovery del profiling; collegare vocabolari e relazioni al compilatore CSV gestito; comporre la UX e collaudare il percorso finale. **La causa del FAILED Farmacie resta ignota.** L'audit non la attribuisce a parser, storage o DB.

M1/G4 resta acquisito. M2/G5/G6/G7 restano aperti perché la prova completa di prodotto manca; questo non riapre lo sviluppo dei motori. Non si ricava una percentuale di avanzamento dal numero di file o test. Le 34–58 ore della prima revisione restano ritirate; l'inventario è ora fatto, ma causa Farmacie e composizione delle linee vanno risolte prima di una nuova stima attendibile.

## Metodo e limiti

Letti e confrontati **63 file fissati a commit** di sei repository owner, i due fixture di composizione Ingestion/UDP e documenti/evidenze deploy; riletti direttamente **8 log di job CI esistenti**. Confrontate le storie Git di cinque repository. Le sezioni seguenti distinguono codice, test di componente, composizione isolata e prova target. Nessuna nuova CI o prova Java locale: l'ambiente locale non avvia Java per libjli.so mancante. Non è un audit esaustivo di tutti i repository.

Nessuna chiamata runtime OUF, Engine, SQL o OAuth; nessuna acquisizione, pubblicazione di policy, riattivazione, deploy, reset o replay. L'unica modifica è documentale su GitHub. Nessuna autorità runtime, merge o release acceptance deriva dall'audit.

### Generazioni da non confondere

| Riferimento | Significato |
| --- | --- |
| Onboarding `194b586508c6661b40a74d9c7f99ed3b876f5fbc` | Source installed retained. Worker profiling, service e compiler riletti a questo SHA: identici ai corrispondenti tre file della candidata diagnostica |
| Onboarding `a5ed8b05c264a8221783a6e323ba00117aed891d`, PR52 | Candidata diagnostica CI, **non installata**; non è un fix causale Farmacie |
| MCP `9a374dd07745f059de3ad39757c68f02db6d29c3` | Source della sostituzione diagnostica installata nel dossier retained; manifest confrontato |
| Ingestion READ `7d85bfe0d1423bcb13e115f06c92d8a0baa1ebf7`; UDP READ `125510cf9d970aff7db66a0a8f27eb98b50bb6de` | Repliche **READ**; non vanno usate come attestazione del source dei worker |
| Branch M2 del 20 ottobre | Codice qualificato in CI da riusare; la presenza su GitHub non prova installazione VPS |

Non è stata riosservata la generazione corrente dei worker o del VPS. Il comportamento M1 resta provato dal dossier owner del 26 ottobre; non è dedotto dai branch candidate.

## Riuso concreto e lacune

| Area | Codice/prova già disponibile | Limite reale e lavoro residuo |
| --- | --- | --- |
| Pipeline e provenance | M1: due run Teatri, 26 join receipt/lineage/contenuto, 13 identità, 20 proprietà correnti per oggetto, 8 Cinema preservati | Nuovo percorso Farmacie e resoconto completo; nessuna terza acquisizione Teatri |
| Tipi decimal/date | Compiler Onboarding + transform Ingestion + materializer UDP; CI composta con valori e RAW verificati | Integrare le linee candidate conservando i fix successivi; non sviluppare di nuovo le trasformazioni |
| No revisione gratuita | CI composta: 2 acquisizioni, 1 oggetto, 1 revisione, 2 osservazioni | DS1R completo, retry distinto e coorte finale; M1 da solo usa configurazioni diverse |
| Ripresa chat | ASSETS, LATEST, tenant/subject e paginazione implementati su tre owner | Non integrati nel manifest selezionato; lista asset senza job fallito/in corso né etichetta lavoro |
| Proprietà/identità | Motori MATCH/NEW/REVIEW, complementi, conflitti, union, null/delete, provenance; 97 test mirati senza skip | Composizione con nuove fonti/review reale e casi finali non coperti; non un nuovo motore merge |
| Recovery downstream | Budget cumulativi, claim/fencing, HUMAN e storia già presenti in Ingestion/UDP | Profiling Onboarding ha policy più debole; fault finali ancora da comporre |
| Semantica e relazioni | Registry proposte/letture, motori UDP relazione presenti | Il compiler managed CSV rifiuta mapping vocabolari e relazioni non vuoti: collegamento mancante concreto |
| Search e review | Search tipizzata/related search, review source persistente e pacchetto UDP con hash/versioni esistono | Collegare lavoro→review→risultato e verificare mobile/desktop, senza sostituire HUMAN con MCP |
| Qualifica finale | Molti test riusabili; SDK multi-sessione presente | Due client esterni e percorso completo autoguidato non provati |

### F04 — Ripresa: esiste il codice, manca il job nella discovery

`ManagedFileService.ownedAssets` restituisce `items` con assetId/status/uploadedAt/mediaType/sizeBytes e, quando presenti, profileId/sourceId. Non restituisce jobId, stato del job fallito/in corso, causa/azione sicura o etichetta del lavoro. Una nuova chat può trovare l'asset candidato, ma quella risposta da sola non consente di ritrovare il FAILED esatto tramite la preview che richiede assetId+jobId. Non è necessario introdurre un altro datastore di workflow: occorre una proiezione owner limitata e autorizzata dello stato già persistente.

Il predicato della lista ammette solo prove durevoli tenant+soggetto da upload/review; gli asset legacy senza tali prove sono esclusi esplicitamente. L'upload delegato esistente scrive quelle prove. **Non è stato letto il record Farmacie: non è provato che sia incluso o escluso.** L'handoff browser a TTL/in memoria non sostituisce la discovery durevole.

Nel test MCP `TestOwnedAssetRecoveryAcrossIndependentSDKClients`, il mock owner restituisce `assets`, mentre l'owner reale restituisce `items`. È una discrepanza della fixture e una lacuna della prova di composizione; non dimostra un bug di parsing nel MCP, che inoltra il risultato. Allineare il test al contratto owner e provare anche FAILED/in corso e due chat sul vero owner.

### F05 — Lacuna specifica del profiling

Nel source retained installato, `ManagedFileProfileWorker` cattura insieme errori di object-read, integrità, parser e persistenza e chiama failProfile con codice generico e delay fisso (default 30 s). `ManagedFileService` mantiene stato, lease e contatori persistenti, ma ritenta tutte queste eccezioni fino a cinque tentativi per job; non classifica lì transitori e permanenti né applica un backoff distinto.

La release HUMAN della quarantena aggiorna lo stato dell'asset a STAGED; **non crea da sola una sessione finita di recupero che conserva il budget dell'incidente**. requestProfile deduplica asset+idempotencyKey: una chiave nuova non è dimostrata come vietata dal limite cumulativo dell'incidente. Queste sono lacune di questo percorso, non assenza di resilienza in tutto OUF. Riusare i modelli già qualificati di budget/storia/fencing degli owner downstream, mantenendo il FAILED originale. L'audit non autorizza a verificarlo creando un nuovo job.

### F06 — Confine preciso della semantica gestita

Nel compiler typed candidato `ManagedFileExecutionProposal`, righe 50–51, sono esplicitamente richiesti vuoti `semantic.vocabularyMappings` e `configuration.relationshipMappings`. Nel compiler retained le stesse condizioni sono alle righe 48–49. I tipi già supportati sono string/decimal/date e le trasformazioni finite IDENTITY, DECIMAL_DOT/COMMA, DATE_ISO/DMY.

Il delta è quindi collegare i mapping governati al percorso managed CSV: riferimento pubblicato/versionato, codice originale e concetto, unknown esplicito; relazione dichiarata con target presente/assente/ambiguo e provenance. Registry e UDP possiedono già primitive pertinenti. Non si deve conteggiare un nuovo Registry, parser o relationship engine.

### F03/F07/F08 — Prove più ampie del solo M1

La fixture [UdpPhase.java](../tests/fixtures/csv-typed-owner-composition/UdpPhase.java) verifica NEW_OBJECT alla prima acquisizione, MATCH alla seconda, materialChange solo alla prima, stesso objectId/revisionId, un oggetto e una revisione, due osservazioni e due lineage/RAW distinti. Verifica inoltre decimal 12.34 e date 2024-02-29. `CanonicalMaterializer` riusa la revisione se canonicalHash e authorityHash sono invariati.

La suite UDP di proprietà esercita complementi, conflitti per proprietà, omissioni/null, union con provenance, revisioni fonte/delete e decisioni HUMAN stale. Le suite recovery esercitano budget, concorrenza, idempotenza e storia. Queste prove si riusano per le asserzioni coperte: **non vanno dichiarate assenti solo perché AT12/15/17 sono ancora aperti nella coorte finale**.

La composizione typed usa owner reali e PostgreSQL isolato ma semantica/Lake sintetici: non prova IAM/Gateway/THS esterni né il ciclo outbox ACK. Due sessioni SDK con owner sintetico non valgono come due client reali.

## Linee di codice da comporre

I confronti sotto usano una linea successiva diagnostica/READ/route come base e la candidata typed/resume come head. “Ahead/behind” è il conteggio Git, non una stima di lavoro. Per Onboarding la base diagnostica è candidata, non installata. Per Ingestion/UDP la base è READ, non worker. Anche quando una classe è riusabile, l'immagine/coorte finale richiede una distinta verifica di compatibilità.

| Repository | Base → candidata | Git | Implicazione |
| --- | --- | --- | --- |
| ouf-source-onboarding | [a5ed8b05 → 7b04d36f](https://github.com/GioNob/ouf-source-onboarding/compare/a5ed8b05c264a8221783a6e323ba00117aed891d...7b04d36fd8462616514cca956fd973c9bd01c1e7) | diverged; +4/−10 | Comporre delta pertinenti; preservare gli hardening successivi, senza sostituzione integrale del branch |
| ouf-ingestion-runtime | [7d85bfe0 → bcc13544](https://github.com/GioNob/ouf-ingestion-runtime/compare/7d85bfe0d1423bcb13e115f06c92d8a0baa1ebf7...bcc13544afdea6f5d331292f93eef86726587e2b) | diverged; +4/−10 | Comporre delta pertinenti; preservare gli hardening successivi, senza sostituzione integrale del branch |
| ouf-mcp-server | [9a374dd0 → 0a76376a](https://github.com/GioNob/ouf-mcp-server/compare/9a374dd07745f059de3ad39757c68f02db6d29c3...0a76376a7c6a0f07597c1c3aaf447b29deed597f) | diverged; +9/−6 | Comporre delta pertinenti; preservare gli hardening successivi, senza sostituzione integrale del branch |
| ouf-api-gateway | [efe71dd9 → c22fbf7f](https://github.com/GioNob/ouf-api-gateway/compare/efe71dd9bef9d5ee70c0ef2acb11ea4169649baa...c22fbf7f5593f612aba7e318797c9459d0b871a7) | diverged; +2/−6 | Comporre delta pertinenti; preservare gli hardening successivi, senza sostituzione integrale del branch |
| ouf-udp-object-resolution | [125510cf → df1f4c38](https://github.com/GioNob/ouf-udp-object-resolution/compare/125510cf9d970aff7db66a0a8f27eb98b50bb6de...df1f4c38d31da8a8ac63d5a5cb2532f633778979) | diverged; +23/−7 | Comporre delta pertinenti; preservare gli hardening successivi, senza sostituzione integrale del branch |

Candidati di riuso: Onboarding PR49 `7b04d36f` (comprende typed PR48 `17a68aea`), Ingestion PR45 `bcc13544`, UDP PR47 `df1f4c38`, MCP PR77 `0a76376a`, Gateway PR82 `c22fbf7f`. Nessuno è stato fuso o distribuito da questo audit.

## Prove CI rilette direttamente

| ID | Job fissato | Prova riletta | Limite |
| --- | --- | --- | --- |
| CI-typed | [ouf-deploy / 118647330860](https://github.com/GioNob/ouf-deploy/actions/runs/39428578919/job/118647330860) | 3 owner reali + PostgreSQL isolato; 2 acquisizioni, 1 oggetto, 1 revisione, 2 osservazioni; decimal/date e RAW lineage | Semantica e Lake sintetici; nessun Gateway/IAM/THS reale né ACK outbox provato |
| CI-onboarding | [ouf-source-onboarding / 118662140934](https://github.com/GioNob/ouf-source-onboarding/actions/runs/39432864255/job/118662140934) | Modulo: 280 test, 0 failure/error/skip; recovery 2, execution proposal 9, review runtime 9 | Test di modulo; non due client reali né Farmacie VPS |
| CI-ingestion | [ouf-ingestion-runtime / 118630769185](https://github.com/GioNob/ouf-ingestion-runtime/actions/runs/39423697184/job/118630769185) | Modulo: 197 test, 2 skipped; adapter 11, transform 4 e recovery budget 16 tutti senza skip | Due skip nel totale: non attestato full PASS di tutti i criteri; moduli/build non percorso VPS |
| CI-udp | [ouf-udp-object-resolution / 118633474369](https://github.com/GioNob/ouf-udp-object-resolution/actions/runs/39424493890/job/118633474369) | Modulo: 267 test, 2 skipped; identity engine 11, linked properties 12, recovery 18 senza skip | Due skip nel totale: non attestato full PASS di tutti i criteri; nessun caso Farmacie |
| CI-udp_properties | [ouf-udp-object-resolution / 118633474339](https://github.com/GioNob/ouf-udp-object-resolution/actions/runs/39424493924/job/118633474339) | Suite mirata: 97 test, 0 failure/error/skip; proprietà, materializer, identità e temporalità | PG isolato; non la fixture DS1 completa sul target finale |
| CI-udp_recovery | [ouf-udp-object-resolution / 118633473770](https://github.com/GioNob/ouf-udp-object-resolution/actions/runs/39424493930/job/118633473770) | Suite mirata: 23 test, 0 failure/error/skip; recovery/reference gates | PG isolato; non qualificazione di profilazione Onboarding |
| CI-mcp_resume | [ouf-mcp-server / 118663281683](https://github.com/GioNob/ouf-mcp-server/actions/runs/39433193162/job/118663281683) | TestOwnedAssetRecoveryAcrossIndependentSDKClients e LatestReviewAuthorization PASS nei log | Due sessioni SDK con owner TLS sintetico; non due client esterni sul percorso reale |
| CI-gateway | [ouf-api-gateway / 118661806748](https://github.com/GioNob/ouf-api-gateway/actions/runs/39432768839/job/118661806748) | 554 passed, 3 skipped; job config-contract SUCCESS | Tre skip nel totale; non ACK/materializzazione o percorso umano reale |

I totali di modulo Ingestion/UDP e Gateway conservano gli skip effettivi. I job SUCCESS non vengono trasformati in “tutti i requisiti PASS”. I conteggi SDK/build ripetuti non si sommano ai totali di modulo come nuovi scenari. Non è stata rieseguita nessuna suite.

## Confronto dei 24 test originari

Tutti i criteri e i livelli di accettazione del mini-PET restano invariati. La colonna “residuo” specifica il lavoro: un test finale aperto non significa codice assente. AT16 resta la prova M1 acquisita; gli altri restano aperti per la coorte finale senza cancellare le prove parziali.

| Test | Già disponibile | Residuo concreto | Prove / delta |
| --- | --- | --- | --- |
| CSV-AT-01 | Manifest/scopes/route e deny già presenti; il catalogo non è un grant. | Coerenza della coorte composta e deny reali sul percorso finale. | CI-mcp_resume, CI-gateway, TARGET-M1; D2, D7 |
| CSV-AT-02 | Upload con ricevuta firmata, hash/size e dedup tenant+subject+key; profiling job persistente. | Coprire risposta persa del picker/restart e impedire nuovo job per aggirare FAILED; conservare asset Farmacie. | CI-onboarding, TARGET-FAILED; D3, D4, D7 |
| CSV-AT-03 | Parser/adapter supportano BOM, semicolon e quoting; 11 test adapter senza skip. | Causa Farmacie e limiti profiler→compiler; regressione dell'errore osservato, non un nuovo parser. | CI-ingestion, CI-DIAGNOSTIC, LOCAL-FARMACIE; D1, D2, D7 |
| CSV-AT-04 | Adapter con chiavi stabili, duplicati espliciti e resume; test già disponibili. | Riutilizzare test identità riga; provare configurazione finale e casi non coperti dalla fixture. | CI-ingestion; D2, D7 |
| CSV-AT-05 | Decimal/date fino a UDP e RAW originali già provati in composizione; vocab managed non collegato. | Implementare solo mapping a concetto/versione e unknown; qualificare DS3 e delta consumer. | CI-typed, CI-ingestion, CI-onboarding; D2, D5, D7 |
| CSV-AT-06 | Registry ProposalCommandService e SemanticReadService, review preparation già presenti; nessuna nuova CI Registry riletta qui. | Comporre gap semantico con ritorno sulla stessa fonte; test DRAFT→HUMAN→pubblicazione corrente. | CI-onboarding; D5, D6, D7 |
| CSV-AT-07 | Review persistente/versionata, stale e comando stabile già testati. | Verificare link esatto e ritorno UI reale mobile/desktop sulla coorte finale. | CI-onboarding, CI-mcp_resume; D2, D6, D7 |
| CSV-AT-08 | Preparazione separata da publish/activation, source revision e budget owner esistenti. | Prova composizione una intenzione→una acquisizione e riconciliazione risposta persa. | CI-onboarding, CI-ingestion; D6, D7 |
| CSV-AT-09 | Pipeline e bundle/run fissati; fixture typed usa configurazione unica. | Il solo typed non prova cambio ACTIVE durante run: riusare suite compatibile e coprire lo scenario completo mancante. | CI-ingestion, CI-typed; D2, D7 |
| CSV-AT-10 | ACK/intake/materializzazione target M1 e OutboxDispatcher/recovery presenti. | Fault prima/dopo ACK su composizione qualificata; non attribuire ACK outbox alla fixture typed. | TARGET-M1, CI-ingestion, CI-udp_recovery; D7 |
| CSV-AT-11 | Identity engine 11 test, scoped candidates/governance in suite mirata; pacchetto review owner. | DS1 e ambiguità attraverso review reale, senza rifare l'identity engine. | CI-udp, CI-udp_properties; D6, D7 |
| CSV-AT-12 | 12 test LinkedPropertyRuntime e suite 97 senza skip: complementi, conflitti, null, union, delete e provenance. | Riutilizzare matrice; provare combinazioni/autorità e nuova fonte finale non già coperte. | CI-udp_properties, TARGET-M1; D6, D7 |
| CSV-AT-13 | RelationshipReconciliation/Materializer presenti; compiler managed rifiuta relazioni non vuote. | Collegare dichiarazione CSV alla relazione governata; target presente/assente/ambiguo e retry. | CI-udp; D5, D7 |
| CSV-AT-14 | 26 join e letture owner disponibili; ACK distinto da materializzazione. | Comporre resoconto tutte le 61 righe, pending/review/error/redaction; no nuovi reader generici. | TARGET-M1, TARGET-READ; D6, D7 |
| CSV-AT-15 | Già provato isolatamente: 2 acquisizioni stesse config/file, 1 oggetto e revisione, 2 osservazioni. | Estendere a DS1R 4 oggetti, retry della stessa richiesta e livello finale richiesto; non riscrivere dedup. | CI-typed; D7 |
| CSV-AT-16 | PASS retained M1 sulle due run Teatri, inclusi 8 Cinema. | Sola analisi d'impatto e riuso. Nessuna terza acquisizione Teatri. | TARGET-M1; D7 |
| CSV-AT-17 | Recovery budget 16 e UDP recovery 23 test mirati senza skip; fencing e storia già presenti. | Lacuna specifica profiling e fault composizione; non ricreare tutti i recovery engine. | CI-ingestion, CI-udp_recovery, RETAINED-ROLLOUT; D4, D7 |
| CSV-AT-18 | Tenant/subject scope, label filtering, deny e redaction già qualificati nei rispettivi perimetri. | Test revoca e attraversamento Gateway→owner della coorte finale; dati/counts non autorizzati assenti. | CI-mcp_resume, CI-udp_properties, TARGET-READ, TARGET-M1; D2, D3, D7 |
| CSV-AT-19 | ASSETS/LATEST implementati e CI; risposta ASSETS senza jobId e mock assets/items discordante. | Discovery di failed/in-progress job e test owner reale con nuova chat, senza upload implicito. | CI-onboarding, CI-mcp_resume, CI-gateway; D2, D3, D7 |
| CSV-AT-20 | Due sessioni SDK con owner sintetico sono una prova parziale. | Due client esterni indipendenti, almeno uno solo tool/link web; traccia fino a UDP e ritorno THS. | CI-mcp_resume; D7 |
| CSV-AT-21 | Controller e casi retained riusabili; audit non prova ENV-A/B completo. | Secondo profilo isolato sul solo delta finale; non nuovo installer universale né reset ambiente. | RETAINED-ROLLOUT; D7 |
| CSV-AT-22 | Recovery di deployment conservate; operazioni originali non ripetute. | Scegliere executor già qualificato e coprire soltanto fault del nuovo delta non già provati. | RETAINED-ROLLOUT, TARGET-READ; D2, D7 |
| CSV-AT-23 | Readiness e generazioni retained; inventario storico non è quello da ripristinare. | Freeze della coorte corrente e preservazione route estranee; drift/deny/readiness per nuovo delta. | RETAINED-ROLLOUT, TARGET-READ; D2, D7 |
| CSV-AT-24 | M1 completo e dossier mantenuto; M2 aperto. | Comporre matrice finale, scenari canonici completi e HUMAN M2; nessun merge/release acceptance. | TARGET-M1; D7 |

## Confronto degli 8 criteri UX

| Criterio | Già disponibile / limite | Residuo | Delta |
| --- | --- | --- | --- |
| M2-UX-01 | Prove dei singoli passaggi non provano percorso autoguidato. | Comporre proposta/review/attesa/esito senza terminale, ID copiati o prosegui tecnico. | D2, D3, D6, D7 |
| M2-UX-02 | Asset/job persistenti; Farmacie FAILED conservato, causa sconosciuta. | Fix causale, idempotenza e recupero finito del profiling; errore safe e azione valida. | D1, D4, D7 |
| M2-UX-03 | Decisioni INCLUDE/EXCLUDE e transform typed già presenti. | Composizione di tutte le colonne, label e vocabolario/relazione dichiarati. | D2, D5, D6, D7 |
| M2-UX-04 | Owner review con hash/versioni già presente; picker non è diagnostica. | Link verificato per decisione esatta, ritorno da mobile/desktop e versioni scadute. | D6, D7 |
| M2-UX-05 | ASSETS/LATEST candidati, ma job/etichetta lavoro assenti dalla lista. | Ritrovare lavoro descrittivo e relativo job entro tenant/soggetto e paginazione. | D2, D3, D7 |
| M2-UX-06 | READ complete M1 e lineage per riga riusabili. | Rendiconto 61 righe e parzialità; oggetti distinti dal numero righe; nessun successo dal solo ACK. | D6, D7 |
| M2-UX-07 | Search canonica tipizzata e related search già nel manifest. | Collegare type/object ID prodotti e paginazione governata; niente motore search nuovo. | D6, D7 |
| M2-UX-08 | Stati e recovery downstream presenti; profiling catch-all a delay fisso. | Classificazione errori profiling, attesa bounded e dedup dipendenza nella composizione. | D3, D4, D6, D7 |

## Roadmap dei soli delta

| Delta | Natura | Dipendenze | Uscita verificabile |
| --- | --- | --- | --- |
| D1 — Causa e fix mirato Farmacie | DIAGNOSIS_THEN_CONDITIONAL_FIX | Nessuna; preparazione indipendente | Categoria/causa owner dello stesso FAILED, regressione causale e percorso di recovery qualificato |
| D2 — Composizione di typed, ASSETS/LATEST e review con hardening corrente | INTEGRATION_OF_EXISTING_CODE | Nessuna; preparazione indipendente | Coorte esatta che preserva readiness/diagnosi/READ e passa contratti owner/MCP/Gateway reali |
| D3 — Discovery durevole di lavoro e job, e contratto ASSETS coerente | BOUNDED_IMPLEMENTATION_AND_COMPOSITION_TEST | D2 | Nuova chat identifica lavoro/asset/job autorizzato senza copiare ID; paging/tenant/revoca provati |
| D4 — Policy finita di errore e recovery del profiling | BOUNDED_IMPLEMENTATION | D1 | Permanenti non ritentati; transitori finiti; recovery HUMAN conserva tentativi/storia e non duplica effetti |
| D5 — Vocabolario e relazione nel managed CSV | IMPLEMENTATION_AT_EXISTING_COMPONENT_BOUNDARIES | D2 | Valore→concetto/versione/RAW e relazione governata attraversano compiler/Ingestion/UDP; negativi espliciti |
| D6 — Composizione del percorso e resoconto verificato | INTEGRATION_AND_TARGETED_ACCEPTANCE | D1, D2, D3, D4, D5 | Farmacie con 61 righe contabilizzate, review corretta e risultati UDP/search leggibili, niente terminale ordinario |
| D7 — Collaudi residui e accettazione M2 | QUALIFICATION_NOT_ENGINE_REWRITE | D6 | AT/UX al livello richiesto, DS1R/fault/due client/secondo profilo/dossier, M1 preservato e HUMAN M2 |

D1 e la preparazione D2 sono indipendenti: il blocco Farmacie non impedisce di comporre e qualificare codice già esistente. D4 riusa i modelli di recupero esistenti; il fix causale dipende da D1. D7 riusa la qualifica compatibile e copre le asserzioni residue, senza rilanciare procedure consumate. Nessun nuovo totale ore è sostenuto da questo audit; non si riconta M1 né il codice già consegnato.

## Evidenze retained e fonti puntuali

- **TARGET-M1** — [csv-m1-f5-f6-owner-verification-20261026.json](../evidence/csv-m1-f5-f6-owner-verification-20261026.json): 26 join receipt/lineage/contenuto; 13 identità stabili; 20 proprietà correnti; 8 Cinema preservati; ACK/intake/materializzazione. Limite: Due configurazioni diverse; non stessa configurazione senza revisione; non Farmacie o due client.
- **TARGET-READ** — [acquisition-redaction-apply-target-20261026.json](../evidence/acquisition-redaction-apply-target-20261026.json): Due repliche READ aggiornate, originali preservati. Limite: Sorgenti READ non equivalgono alle generazioni dei worker.
- **TARGET-FAILED** — [new-csv-profile-terminal-failure-20261026.json](../evidence/new-csv-profile-terminal-failure-20261026.json): Unico job Farmacie FAILED, asset conservato. Limite: ONB_FILE_PROFILE_FAILED non distingue object store/integrità/parser/persistenza.
- **LOCAL-FARMACIE** — [farmacie-local-csv-analysis-20261026.json](../evidence/farmacie-local-csv-analysis-20261026.json): CSV Python strict valido, 61 righe, 10 colonne, BOM/semicolon. Limite: Hash server ed esatto Java installato non provati.
- **CI-DIAGNOSTIC** — [managed-profile-diagnostic-ci-checkpoint-20261026.json](../evidence/managed-profile-diagnostic-ci-checkpoint-20261026.json): PR52 categoria diagnostica safe, 283 test modulo senza skip. Limite: Non installata; non causa osservata né fix.
- **RETAINED-ROLLOUT** — [onboarding-v35-existing-create-target-20261024.json](../evidence/onboarding-v35-existing-create-target-20261024.json): Recovery candidato esistente completato con original request non ripetuta, storico preservato. Limite: Prova della specifica generazione/stadi; non installer universale né nuovo deployment autorizzato.

Gli identificativi S01…S63 rimandano a commit e blob nel registro JSON. La tabella permette di controllare il metodo o il contratto senza basarsi su nomi di feature.

| Fonte | Repository / selezione | File fissato |
| --- | --- | --- |
| S01 | ouf-source-onboarding / onboarding_selected | [ManagedFileMcpApi.java @ a5ed8b05](https://github.com/GioNob/ouf-source-onboarding/blob/a5ed8b05c264a8221783a6e323ba00117aed891d/src/main/java/it/comune/trieste/ouf/onboarding/api/ManagedFileMcpApi.java) |
| S02 | ouf-source-onboarding / onboarding_selected | [ManagedFileService.java @ a5ed8b05](https://github.com/GioNob/ouf-source-onboarding/blob/a5ed8b05c264a8221783a6e323ba00117aed891d/src/main/java/it/comune/trieste/ouf/onboarding/application/ManagedFileService.java) |
| S03 | ouf-source-onboarding / onboarding_selected | [ManagedFileExecutionProposal.java @ a5ed8b05](https://github.com/GioNob/ouf-source-onboarding/blob/a5ed8b05c264a8221783a6e323ba00117aed891d/src/main/java/it/comune/trieste/ouf/onboarding/application/ManagedFileExecutionProposal.java) |
| S04 | ouf-source-onboarding / onboarding_selected | [ConfigurationValidator.java @ a5ed8b05](https://github.com/GioNob/ouf-source-onboarding/blob/a5ed8b05c264a8221783a6e323ba00117aed891d/src/main/java/it/comune/trieste/ouf/onboarding/application/ConfigurationValidator.java) |
| S05 | ouf-source-onboarding / onboarding_selected | [ManagedFileProfileWorker.java @ a5ed8b05](https://github.com/GioNob/ouf-source-onboarding/blob/a5ed8b05c264a8221783a6e323ba00117aed891d/src/main/java/it/comune/trieste/ouf/onboarding/application/ManagedFileProfileWorker.java) |
| S06 | ouf-source-onboarding / onboarding_selected | [ManagedFileChatHandoff.java @ a5ed8b05](https://github.com/GioNob/ouf-source-onboarding/blob/a5ed8b05c264a8221783a6e323ba00117aed891d/src/main/java/it/comune/trieste/ouf/onboarding/application/ManagedFileChatHandoff.java) |
| S07 | ouf-source-onboarding / onboarding_selected | [ManagedFileQuarantineTrustedHumanApi.java @ a5ed8b05](https://github.com/GioNob/ouf-source-onboarding/blob/a5ed8b05c264a8221783a6e323ba00117aed891d/src/main/java/it/comune/trieste/ouf/onboarding/api/ManagedFileQuarantineTrustedHumanApi.java) |
| S08 | ouf-source-onboarding / onboarding_m2 | [ManagedFileMcpApi.java @ 7b04d36f](https://github.com/GioNob/ouf-source-onboarding/blob/7b04d36fd8462616514cca956fd973c9bd01c1e7/src/main/java/it/comune/trieste/ouf/onboarding/api/ManagedFileMcpApi.java) |
| S09 | ouf-source-onboarding / onboarding_m2 | [ManagedFileService.java @ 7b04d36f](https://github.com/GioNob/ouf-source-onboarding/blob/7b04d36fd8462616514cca956fd973c9bd01c1e7/src/main/java/it/comune/trieste/ouf/onboarding/application/ManagedFileService.java) |
| S10 | ouf-source-onboarding / onboarding_m2 | [ManagedFileExecutionProposal.java @ 7b04d36f](https://github.com/GioNob/ouf-source-onboarding/blob/7b04d36fd8462616514cca956fd973c9bd01c1e7/src/main/java/it/comune/trieste/ouf/onboarding/application/ManagedFileExecutionProposal.java) |
| S11 | ouf-source-onboarding / onboarding_m2 | [ConfigurationValidator.java @ 7b04d36f](https://github.com/GioNob/ouf-source-onboarding/blob/7b04d36fd8462616514cca956fd973c9bd01c1e7/src/main/java/it/comune/trieste/ouf/onboarding/application/ConfigurationValidator.java) |
| S12 | ouf-source-onboarding / onboarding_m2 | [ManagedOnboardingReviewService.java @ 7b04d36f](https://github.com/GioNob/ouf-source-onboarding/blob/7b04d36fd8462616514cca956fd973c9bd01c1e7/src/main/java/it/comune/trieste/ouf/onboarding/application/ManagedOnboardingReviewService.java) |
| S13 | ouf-source-onboarding / onboarding_m2 | [SourceRevisionService.java @ 7b04d36f](https://github.com/GioNob/ouf-source-onboarding/blob/7b04d36fd8462616514cca956fd973c9bd01c1e7/src/main/java/it/comune/trieste/ouf/onboarding/application/SourceRevisionService.java) |
| S14 | ouf-source-onboarding / onboarding_m2 | [ManagedFileRecoveryRuntimeTest.java @ 7b04d36f](https://github.com/GioNob/ouf-source-onboarding/blob/7b04d36fd8462616514cca956fd973c9bd01c1e7/src/test/java/it/comune/trieste/ouf/onboarding/ManagedFileRecoveryRuntimeTest.java) |
| S15 | ouf-source-onboarding / onboarding_m2 | [ManagedFileExecutionProposalTest.java @ 7b04d36f](https://github.com/GioNob/ouf-source-onboarding/blob/7b04d36fd8462616514cca956fd973c9bd01c1e7/src/test/java/it/comune/trieste/ouf/onboarding/application/ManagedFileExecutionProposalTest.java) |
| S16 | ouf-source-onboarding / onboarding_m2 | [ManagedOnboardingReviewRuntimeTest.java @ 7b04d36f](https://github.com/GioNob/ouf-source-onboarding/blob/7b04d36fd8462616514cca956fd973c9bd01c1e7/src/test/java/it/comune/trieste/ouf/onboarding/ManagedOnboardingReviewRuntimeTest.java) |
| S17 | ouf-source-onboarding / onboarding_m2 | [SourceRevisionRuntimeTest.java @ 7b04d36f](https://github.com/GioNob/ouf-source-onboarding/blob/7b04d36fd8462616514cca956fd973c9bd01c1e7/src/test/java/it/comune/trieste/ouf/onboarding/SourceRevisionRuntimeTest.java) |
| S18 | ouf-source-onboarding / onboarding_m2 | [CSV_CHAT_RECOVERY_DELTA_20261020.md @ 7b04d36f](https://github.com/GioNob/ouf-source-onboarding/blob/7b04d36fd8462616514cca956fd973c9bd01c1e7/docs/CSV_CHAT_RECOVERY_DELTA_20261020.md) |
| S19 | ouf-ingestion-runtime / ingestion_read | [CanonicalRecordPipeline.java @ 7d85bfe0](https://github.com/GioNob/ouf-ingestion-runtime/blob/7d85bfe0d1423bcb13e115f06c92d8a0baa1ebf7/src/main/java/it/comune/trieste/ouf/ingestion/CanonicalRecordPipeline.java) |
| S20 | ouf-ingestion-runtime / ingestion_m2 | [ConfiguredValueTransform.java @ bcc13544](https://github.com/GioNob/ouf-ingestion-runtime/blob/bcc13544afdea6f5d331292f93eef86726587e2b/src/main/java/it/comune/trieste/ouf/ingestion/ConfiguredValueTransform.java) |
| S21 | ouf-ingestion-runtime / ingestion_m2 | [CanonicalRecordPipeline.java @ bcc13544](https://github.com/GioNob/ouf-ingestion-runtime/blob/bcc13544afdea6f5d331292f93eef86726587e2b/src/main/java/it/comune/trieste/ouf/ingestion/CanonicalRecordPipeline.java) |
| S22 | ouf-ingestion-runtime / ingestion_m2 | [ManagedTabularAdapter.java @ bcc13544](https://github.com/GioNob/ouf-ingestion-runtime/blob/bcc13544afdea6f5d331292f93eef86726587e2b/src/main/java/it/comune/trieste/ouf/ingestion/ManagedTabularAdapter.java) |
| S23 | ouf-ingestion-runtime / ingestion_m2 | [RunExecutionWorker.java @ bcc13544](https://github.com/GioNob/ouf-ingestion-runtime/blob/bcc13544afdea6f5d331292f93eef86726587e2b/src/main/java/it/comune/trieste/ouf/ingestion/RunExecutionWorker.java) |
| S24 | ouf-ingestion-runtime / ingestion_m2 | [OutboxDispatcher.java @ bcc13544](https://github.com/GioNob/ouf-ingestion-runtime/blob/bcc13544afdea6f5d331292f93eef86726587e2b/src/main/java/it/comune/trieste/ouf/ingestion/OutboxDispatcher.java) |
| S25 | ouf-ingestion-runtime / ingestion_m2 | [RunRecoveryBudget.java @ bcc13544](https://github.com/GioNob/ouf-ingestion-runtime/blob/bcc13544afdea6f5d331292f93eef86726587e2b/src/main/java/it/comune/trieste/ouf/ingestion/RunRecoveryBudget.java) |
| S26 | ouf-ingestion-runtime / ingestion_m2 | [ConfiguredValueTransformTest.java @ bcc13544](https://github.com/GioNob/ouf-ingestion-runtime/blob/bcc13544afdea6f5d331292f93eef86726587e2b/src/test/java/it/comune/trieste/ouf/ingestion/ConfiguredValueTransformTest.java) |
| S27 | ouf-ingestion-runtime / ingestion_m2 | [ManagedTabularAdapterTest.java @ bcc13544](https://github.com/GioNob/ouf-ingestion-runtime/blob/bcc13544afdea6f5d331292f93eef86726587e2b/src/test/java/it/comune/trieste/ouf/ingestion/ManagedTabularAdapterTest.java) |
| S28 | ouf-ingestion-runtime / ingestion_m2 | [CanonicalRecordPipelineRuntimeTest.java @ bcc13544](https://github.com/GioNob/ouf-ingestion-runtime/blob/bcc13544afdea6f5d331292f93eef86726587e2b/src/test/java/it/comune/trieste/ouf/ingestion/CanonicalRecordPipelineRuntimeTest.java) |
| S29 | ouf-ingestion-runtime / ingestion_m2 | [HumanRecoveryBudgetRuntimeTest.java @ bcc13544](https://github.com/GioNob/ouf-ingestion-runtime/blob/bcc13544afdea6f5d331292f93eef86726587e2b/src/test/java/it/comune/trieste/ouf/ingestion/HumanRecoveryBudgetRuntimeTest.java) |
| S30 | ouf-ingestion-runtime / ingestion_m2 | [RunExecutionWorkerRuntimeTest.java @ bcc13544](https://github.com/GioNob/ouf-ingestion-runtime/blob/bcc13544afdea6f5d331292f93eef86726587e2b/src/test/java/it/comune/trieste/ouf/ingestion/RunExecutionWorkerRuntimeTest.java) |
| S31 | ouf-ingestion-runtime / ingestion_m2 | [CSV_GENERAL_PROFILE_DELTA_20261020.md @ bcc13544](https://github.com/GioNob/ouf-ingestion-runtime/blob/bcc13544afdea6f5d331292f93eef86726587e2b/docs/CSV_GENERAL_PROFILE_DELTA_20261020.md) |
| S32 | ouf-udp-object-resolution / udp_m2 | [LinkedPropertyReconciler.java @ df1f4c38](https://github.com/GioNob/ouf-udp-object-resolution/blob/df1f4c38d31da8a8ac63d5a5cb2532f633778979/src/main/java/it/comune/trieste/ouf/udp/LinkedPropertyReconciler.java) |
| S33 | ouf-udp-object-resolution / udp_m2 | [LinkedPropertyRuntimeTest.java @ df1f4c38](https://github.com/GioNob/ouf-udp-object-resolution/blob/df1f4c38d31da8a8ac63d5a5cb2532f633778979/src/test/java/it/comune/trieste/ouf/udp/LinkedPropertyRuntimeTest.java) |
| S34 | ouf-udp-object-resolution / udp_m2 | [MaterializationRecoveryService.java @ df1f4c38](https://github.com/GioNob/ouf-udp-object-resolution/blob/df1f4c38d31da8a8ac63d5a5cb2532f633778979/src/main/java/it/comune/trieste/ouf/udp/MaterializationRecoveryService.java) |
| S35 | ouf-udp-object-resolution / udp_m2 | [MaterializationRecoveryRuntimeTest.java @ df1f4c38](https://github.com/GioNob/ouf-udp-object-resolution/blob/df1f4c38d31da8a8ac63d5a5cb2532f633778979/src/test/java/it/comune/trieste/ouf/udp/MaterializationRecoveryRuntimeTest.java) |
| S36 | ouf-udp-object-resolution / udp_m2 | [ObjectResolutionService.java @ df1f4c38](https://github.com/GioNob/ouf-udp-object-resolution/blob/df1f4c38d31da8a8ac63d5a5cb2532f633778979/src/main/java/it/comune/trieste/ouf/udp/ObjectResolutionService.java) |
| S37 | ouf-udp-object-resolution / udp_m2 | [PublishedResolutionLoop.java @ df1f4c38](https://github.com/GioNob/ouf-udp-object-resolution/blob/df1f4c38d31da8a8ac63d5a5cb2532f633778979/src/main/java/it/comune/trieste/ouf/udp/PublishedResolutionLoop.java) |
| S38 | ouf-udp-object-resolution / udp_m2 | [CanonicalMaterializer.java @ df1f4c38](https://github.com/GioNob/ouf-udp-object-resolution/blob/df1f4c38d31da8a8ac63d5a5cb2532f633778979/src/main/java/it/comune/trieste/ouf/udp/CanonicalMaterializer.java) |
| S39 | ouf-udp-object-resolution / udp_m2 | [RelationshipReconciliation.java @ df1f4c38](https://github.com/GioNob/ouf-udp-object-resolution/blob/df1f4c38d31da8a8ac63d5a5cb2532f633778979/src/main/java/it/comune/trieste/ouf/udp/RelationshipReconciliation.java) |
| S40 | ouf-udp-object-resolution / udp_m2 | [RelationshipMaterializer.java @ df1f4c38](https://github.com/GioNob/ouf-udp-object-resolution/blob/df1f4c38d31da8a8ac63d5a5cb2532f633778979/src/main/java/it/comune/trieste/ouf/udp/RelationshipMaterializer.java) |
| S41 | ouf-udp-object-resolution / udp_m2 | [GovernedIdentityEngineTest.java @ df1f4c38](https://github.com/GioNob/ouf-udp-object-resolution/blob/df1f4c38d31da8a8ac63d5a5cb2532f633778979/src/test/java/it/comune/trieste/ouf/udp/GovernedIdentityEngineTest.java) |
| S42 | ouf-mcp-server / mcp_selected | [capabilities.json @ 9a374dd0](https://github.com/GioNob/ouf-mcp-server/blob/9a374dd07745f059de3ad39757c68f02db6d29c3/internal/manifest/capabilities.json) |
| S43 | ouf-mcp-server / mcp_m2 | [capabilities.json @ 0a76376a](https://github.com/GioNob/ouf-mcp-server/blob/0a76376a7c6a0f07597c1c3aaf447b29deed597f/internal/manifest/capabilities.json) |
| S44 | ouf-mcp-server / mcp_m2 | [source_review_authorization.go @ 0a76376a](https://github.com/GioNob/ouf-mcp-server/blob/0a76376a7c6a0f07597c1c3aaf447b29deed597f/internal/kernel/source_review_authorization.go) |
| S45 | ouf-mcp-server / mcp_m2 | [managed_file_recovery_test.go @ 0a76376a](https://github.com/GioNob/ouf-mcp-server/blob/0a76376a7c6a0f07597c1c3aaf447b29deed597f/internal/kernel/managed_file_recovery_test.go) |
| S46 | ouf-mcp-server / mcp_m2 | [source_recovery_authorization_test.go @ 0a76376a](https://github.com/GioNob/ouf-mcp-server/blob/0a76376a7c6a0f07597c1c3aaf447b29deed597f/internal/kernel/source_recovery_authorization_test.go) |
| S47 | ouf-mcp-server / mcp_m2 | [CSV_CHAT_RECOVERY_DELTA_20261020.md @ 0a76376a](https://github.com/GioNob/ouf-mcp-server/blob/0a76376a7c6a0f07597c1c3aaf447b29deed597f/docs/CSV_CHAT_RECOVERY_DELTA_20261020.md) |
| S48 | ouf-api-gateway / gateway_m2 | [mcp-gateway-managed-file-dispatch-v1.json @ c22fbf7f](https://github.com/GioNob/ouf-api-gateway/blob/c22fbf7f5593f612aba7e318797c9459d0b871a7/schemas/mcp-gateway-managed-file-dispatch-v1.json) |
| S49 | ouf-api-gateway / gateway_m2 | [mcp-gateway-onboarding-review-read-dispatch-v1.json @ c22fbf7f](https://github.com/GioNob/ouf-api-gateway/blob/c22fbf7f5593f612aba7e318797c9459d0b871a7/schemas/mcp-gateway-onboarding-review-read-dispatch-v1.json) |
| S50 | ouf-api-gateway / gateway_m2 | [test_csv_chat_recovery_schemas.py @ c22fbf7f](https://github.com/GioNob/ouf-api-gateway/blob/c22fbf7f5593f612aba7e318797c9459d0b871a7/tests/test_csv_chat_recovery_schemas.py) |
| S51 | ouf-api-gateway / gateway_m2 | [CSV_CHAT_RECOVERY_CONTRACT_DELTA_20261020.md @ c22fbf7f](https://github.com/GioNob/ouf-api-gateway/blob/c22fbf7f5593f612aba7e318797c9459d0b871a7/docs/CSV_CHAT_RECOVERY_CONTRACT_DELTA_20261020.md) |
| S52 | ouf-semantic-registry / semantic_selected | [ProposalCommandService.java @ eccef11a](https://github.com/GioNob/ouf-semantic-registry/blob/eccef11a97367f20e278db40b9ed6f45dd980c37/src/main/java/it/comune/trieste/ouf/semantic/application/ProposalCommandService.java) |
| S53 | ouf-semantic-registry / semantic_selected | [SemanticReadService.java @ eccef11a](https://github.com/GioNob/ouf-semantic-registry/blob/eccef11a97367f20e278db40b9ed6f45dd980c37/src/main/java/it/comune/trieste/ouf/semantic/application/SemanticReadService.java) |
| S54 | ouf-semantic-registry / semantic_selected | [ProposalCommandRuntimeTest.java @ eccef11a](https://github.com/GioNob/ouf-semantic-registry/blob/eccef11a97367f20e278db40b9ed6f45dd980c37/src/test/java/it/comune/trieste/ouf/semantic/ProposalCommandRuntimeTest.java) |
| S55 | ouf-source-onboarding / onboarding_selected | [ManagedFileProfilerBomTest.java @ a5ed8b05](https://github.com/GioNob/ouf-source-onboarding/blob/a5ed8b05c264a8221783a6e323ba00117aed891d/src/test/java/it/comune/trieste/ouf/onboarding/ManagedFileProfilerBomTest.java) |
| S56 | ouf-source-onboarding / onboarding_selected | [ManagedFileDelegatedUploadApi.java @ a5ed8b05](https://github.com/GioNob/ouf-source-onboarding/blob/a5ed8b05c264a8221783a6e323ba00117aed891d/src/main/java/it/comune/trieste/ouf/onboarding/api/ManagedFileDelegatedUploadApi.java) |
| S57 | ouf-source-onboarding / onboarding_selected | [ManagedFileProfiler.java @ a5ed8b05](https://github.com/GioNob/ouf-source-onboarding/blob/a5ed8b05c264a8221783a6e323ba00117aed891d/src/main/java/it/comune/trieste/ouf/onboarding/application/ManagedFileProfiler.java) |
| S58 | ouf-udp-object-resolution / udp_m2 | [RelatedSearchService.java @ df1f4c38](https://github.com/GioNob/ouf-udp-object-resolution/blob/df1f4c38d31da8a8ac63d5a5cb2532f633778979/src/main/java/it/comune/trieste/ouf/udp/RelatedSearchService.java) |
| S59 | ouf-udp-object-resolution / udp_m2 | [ResolutionReviewPackageService.java @ df1f4c38](https://github.com/GioNob/ouf-udp-object-resolution/blob/df1f4c38d31da8a8ac63d5a5cb2532f633778979/src/main/java/it/comune/trieste/ouf/udp/ResolutionReviewPackageService.java) |
| S60 | ouf-udp-object-resolution / udp_m2 | [RelatedSearchRuntimeTest.java @ df1f4c38](https://github.com/GioNob/ouf-udp-object-resolution/blob/df1f4c38d31da8a8ac63d5a5cb2532f633778979/src/test/java/it/comune/trieste/ouf/udp/RelatedSearchRuntimeTest.java) |
| S61 | ouf-source-onboarding / onboarding_retained_installed | [ManagedFileExecutionProposal.java @ 194b5865](https://github.com/GioNob/ouf-source-onboarding/blob/194b586508c6661b40a74d9c7f99ed3b876f5fbc/src/main/java/it/comune/trieste/ouf/onboarding/application/ManagedFileExecutionProposal.java) |
| S62 | ouf-source-onboarding / onboarding_retained_installed | [ManagedFileService.java @ 194b5865](https://github.com/GioNob/ouf-source-onboarding/blob/194b586508c6661b40a74d9c7f99ed3b876f5fbc/src/main/java/it/comune/trieste/ouf/onboarding/application/ManagedFileService.java) |
| S63 | ouf-source-onboarding / onboarding_retained_installed | [ManagedFileProfileWorker.java @ 194b5865](https://github.com/GioNob/ouf-source-onboarding/blob/194b586508c6661b40a74d9c7f99ed3b876f5fbc/src/main/java/it/comune/trieste/ouf/onboarding/application/ManagedFileProfileWorker.java) |

Il mapping finding→fonti→prove→delta e la comparazione completa dei 32 criteri sono anche nel [registro JSON dell'audit](../evidence/csv-m2-code-evidence-gap-audit-20261026.json). Questo audit sostituisce le formulazioni generiche “da censire” della revisione 1.1; non è una nuova accettazione di prodotto.
