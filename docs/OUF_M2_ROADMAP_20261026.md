# OUF — Roadmap M2 dei soli delta verificati, revisione 1.2

26 ottobre 2026 · Europe/Rome. [Mini-PET](OUF_M2_MINIPET_v1_0_20261026.md) · [Audit puntuale](OUF_M2_CODE_EVIDENCE_GAP_AUDIT_20261026.md) · [Registro](../releases/csv-m2-plan-20261026.json).

**M1 resta acquisito. Anche tipi decimal/date, ASSETS/LATEST, riconciliazione UDP, recovery downstream e no-revision isolato hanno già codice/prove da riusare.** L'audit è completato: 63 file fissati, cinque storie Git confrontate, otto log CI riletti e 32 criteri mappati. Il residuo non è una riscrittura dei motori.

## Percorso concreto

| Delta | Lavoro | Riuso | Uscita / dipendenze |
| --- | --- | --- | --- |
| D1 | Osservare causa e correggere il FAILED Farmacie | Stesso asset/job, diagnostica PR52 CI | Causa owner provata, regressione mirata; nessun nuovo upload/job/reset |
| D2 | Comporre typed, ASSETS/LATEST e review con i fix successivi | Onboarding PR49/48, Ingestion PR45, UDP PR47, MCP PR77, Gateway PR82 | Coorte qualificata che preserva readiness/diagnostica/READ; preparazione indipendente da D1 |
| D3 | Completare discovery di job e lavoro | Lista asset e stato job già persistenti | FAILED/in corso e lavoro identificabili da nuova chat; tenant/paging; correggere mock assets/items e testare owner reale |
| D4 | Completare policy profiling e recovery HUMAN | Modelli di budget/fencing/storia già presenti downstream | Transitori/permanenti distinti, budget cumulativo e nessun effetto doppio; fix causale dipende da D1 |
| D5 | Collegare vocabolario e relazione al managed CSV | Registry e motori UDP; decimal/date già provati | Compiler/runtime accettano solo mapping governati, unknown/target ambiguo espliciti; dopo D2 |
| D6 | Comporre UX, review e resoconto Farmacie | Capability, review/READ/search e pipeline esistenti | 61 righe contabilizzate fino a UDP, decisioni reali e nessun terminale ordinario; dopo D1–D5 |
| D7 | Qualificare solo il residuo | M1, CI di modulo e composizione già positive | DS1R completo, fault composti, due client esterni, secondo profilo isolato e dossier; G5/G6/G7 + HUMAN M2 |

Non serve attendere la diagnosi per preparare D2. Durante attese si prosegue lavoro indipendente senza superare gate. I branch candidati divergono dalle linee successive: integrare delta pertinenti, preservare gli hardening, non sostituire intere linee o fonderle senza autorizzazione.

## Prove già acquisite

- **VPS M1:** due acquisizioni Teatri, ACK/intake/materializzazione, 26 join, 13 identità, 20 proprietà correnti per oggetto e 8 Cinema. Configurazioni diverse; nessuna terza acquisizione.
- **CI composta typed:** due acquisizioni con stessi file/configurazione, un oggetto e una revisione, due osservazioni e lineage/RAW distinti. Decimal/date provati; semantica/Lake sintetici, nessun ACK outbox o THS reale implicito.
- **CI UDP:** suite mirata proprietà/identità/temporalità 97 test e recovery 23, zero failure/error/skip. Il totale modulo UDP ha due skip e non equivale a tutto M2 PASS.
- **Ripresa:** ASSETS/LATEST e sessioni SDK già implementate/testate. Non prova due client esterni né ritrovamento di job fallito: la lista owner non restituisce jobId/etichetta.

Il dettaglio requisito→source/commit→prova→limite→delta è nell'audit. I 24 AT e gli 8 criteri UX restano obbligatori; prove compatibili non si rifanno, prove impattate si riqualificano motivando l'impatto. Non si conta un test mancante come nuovo sviluppo.

## Stima

Le 34–58 ore, centrale 46, e la riserva 8–16 della v1.0 restano ritirate. Le 40–70 ore della baseline comprendevano M1. L'inventario è completato e circoscrive lo sviluppo nuovo a D3/D4/D5 e all'eventuale fix causale D1; D2/D6 sono soprattutto integrazione, D7 qualifica.

Le ore residue restano non determinate finché causa Farmacie e composizione esatta non consentono una stima sostenibile. Nessuna percentuale oraria inventata e nessun calendario derivato dalle vecchie cifre.

## Arrivo e confini

File caricato una volta, proposta comprensibile, sole scelte di dominio/HUMAN necessarie, stato owner recuperabile, esito UDP e search verificati su due client reali. Zero terminale/SQL/copia di ID nel percorso ordinario. Riconciliazione multi-fonte e ricerca tipizzata minima incluse; fusione di due oggetti canonici già esistenti, search avanzata e Supervisor separati.

Prossima attività: D1 diagnosi minimizzata dello stesso FAILED e preparazione D2 della composizione già identificata. Nessun vecchio APPLY o profiling da ripetere, nessun nuovo runtime/grant/merge/release acceptance da questo documento.
