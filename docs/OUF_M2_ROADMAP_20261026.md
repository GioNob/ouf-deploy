# OUF — Roadmap verso M2

26 ottobre 2026 · Europe/Rome · Piano residuo, nessuna autorità runtime.  
Riferimento: [mini-PET M2 completo](OUF_M2_MINIPET_v1_0_20261026.md) · [registro strutturato](../releases/csv-m2-plan-20261026.json).

**Destinazione:** un utente carica un CSV, verifica una proposta comprensibile, decide le vere ambiguità e ottiene oggetti UDP con esito verificato. Il sistema gestisce i passaggi tecnici, le attese ammesse e la ripresa. Il percorso normale non richiede terminale, log o ricostruzione di identificativi.

**Partenza:** M1 completo sul caso Teatri conservato. Farmacie è caricato, ma il solo profiling job è FAILED e la causa owner non è ancora provata. La patch diagnostica Onboarding #52 supera la CI; non è installata. M2/G5/G6/G7 restano aperti.

## Sequenza di lavoro

Le finestre seguenti sono ore tecniche attive cumulative dalla ripartenza M2, scenario centrale. Escludono attese e riserva; non sono appuntamenti o finestre di autorità.

| Tappa | Ore centrali | Cumulativo | Risultato visibile | Prova di uscita |
| --- | ---: | ---: | --- | --- |
| 1. Capire e rimuovere il blocco Farmacie | 6 | H+6 | Il file conservato è analizzabile; un errore spiega causa e azione | Causa owner, fix mirato, recupero governato; nessun reupload o reset per aggirare il FAILED |
| 2. Rendere il percorso autoguidato | 10 | H+16 | L'utente non deve chiedere «prosegui» per ogni fase; può riprendere il lavoro | Stato/prossimo passo owner, link corretti, contesto durevole, mobile/desktop |
| 3. Completare significato e configurazione | 8 | H+24 | Proposta classe/campi/identità/tipi/vocabolari chiara e verificabile | G5: mapping eseguibile, unknown/gap gestiti, relazione semplice e riferimenti fissati |
| 4. Portare Farmacie in UDP | 6 | H+30 | Riepilogo di tutte le 61 righe e oggetti consultabili | Run/ACK/intake/materializzazione/provenienza; MATCH/NEW/REVIEW e riconciliazione provati |
| 5. Provare ripetibilità e recupero | 8 | H+38 | Ripetere o interrompere il percorso non duplica e non perde lavoro | Reimport invariato, fault/revoca/budget e nuova chat, contatori/storia preservati |
| 6. Collaudare e accettare M2 | 8 | H+46 | Stesso percorso riuscito su due client reali | G6/G7: coorte finale, tutti i test obbligatori e decisione HUMAN sul dossier |

Tappe 1–2 eliminano l'attrito principale; tappa 4 è il primo risultato Farmacie completo. M2 si chiude soltanto alla tappa 6. Durante un'attesa si può anticipare lavoro indipendente di progettazione o test; non si superano gate, non si contano ore due volte e non si avviano automazioni operative.

## Pianificazione e confronto con il preventivo

| Riferimento | Ore tecniche | Significato |
| --- | ---: | --- |
| Baseline 20 ottobre, M1 + M2 | 40–70, centrale 55 | Preventivo storico complessivo, non residuo di oggi |
| Quota originaria WP5–7 | 22–40, centrale 31 | Residuo teorico del vecchio piano; non forecast aggiornato dopo Farmacie |
| Nuovo residuo M2 | **34–58, centrale 46** | Sei WP stimati dal punto corrente; lavoro già completato escluso |
| Riserva separata | 8–16, riferimento 12 | Per causa runtime e lacune owner ancora da osservare |
| Pianificazione prudenziale | 42–74, riferimento 58 | Base più riserva; nessuna garanzia di tetto o data |

Con 6 ore tecniche effettive/giorno: circa 6–10 giornate attive, centrale 8; con riserva 7–13. Disponibilità HUMAN, due client e ambiente isolato possono allungare il calendario. Partecipazione HUMAN distinta stimata 2–4 ore distribuite fra scelte, review necessarie, prova client e accettazione.

La prima ristima avviene appena identificata la causa Farmacie; le successive dopo inventario del recupero in tappa 2 e prova UDP in tappa 4. Il consuntivo storico è incompleto: non viene pubblicata una percentuale oraria o un totale già speso inventato.

## I quattro obiettivi e il confine M2

| Obiettivo | Dentro M2 | Dopo M2 |
| --- | --- | --- |
| E2E CSV completo | Nuovo file, semantica/review, acquisizione, UDP e resoconto; Farmacie + fixture generale | Altri formati e verticali |
| Ripetibilità / resilienza | No duplicati o revisioni gratuite, retry finito, recupero, scadenza/revoca, cambio chat, contesto durevole | Estensione sistemica completa, Supervisor e ulteriori scenari operativi |
| Riconciliazione UDP | MATCH/NEW/REVIEW, due fonti sullo stesso oggetto, proprietà/conflitti/provenance | Fusione HUMAN di due oggetti canonici già esistenti, survivor/alias/relazioni/storia |
| Search per chatbot | Discovery semantica e ricerca autorizzata per tipo/paginazione; relazione semplice con tool disponibili | Filtri nome/indirizzo, spatial, grafi o altre capability da inventariare e qualificare separatamente |

La ricerca minima non va rimandata: l'utente deve ritrovare i risultati di M2. La search oggi esposta non offre filtri arbitrari; il piano non li promette come esistenti. La sequenza delle estensioni successive sarà scelta su un inventario aggiornato, senza gonfiare il perimetro M2 né cancellare requisiti PET più ampi.

## Regole per ogni checkpoint

- Registrare risultato verificato, prove, ore effettive note, attese e residuo aggiornato; distinguere codice, CI, installato e accettato.
- Conservare stesso asset/job Farmacie e tutte le prove M1. Nessuna nuova profilazione, terza acquisizione Teatri o reset per saltare un blocco.
- Test di crash/restart/revoca su ambiente isolato. Nuovi effetti target solo dopo ammissione e review concrete; nessuna approvazione simulata.
- Interventi tecnici di manutenzione separati dall'esperienza utente. Un errore che richiede terminale nel percorso ordinario fa fallire il criterio di fluidità.
- Nessun merge, release acceptance o intervento Registry implicito. La documentazione non conferisce grant o autorità runtime.

**Prossima azione:** diagnosi owner minimizzata dello stesso FAILED Farmacie. Se serve il candidato Onboarding #52, qualificare prima il nuovo delta operativo e la sua review; la CI verde non è un comando APPLY pronto. Dopo la causa, fissare il recupero e aggiornare la stima, poi seguire le tappe qui definite.
