# OUF — allineamento operativo della resilienza v3

[Policy canonica](OUF_RESILIENCE_POLICY.md) · [adozione e prove](OUF_RESILIENCE_ADOPTION.md)

## Confini e componenti

Ogni modulo mantiene incidenti, progressi e decisioni di propria ownership nel datastore PET esistente. Gateway media l'accesso; MCP aggrega proiezioni autorizzate. Incidenti tecnici correlati possono essere presentati insieme senza trasferire ownership o permessi. Metriche/log/tracing e osservazione esterna restano distinti dalla proiezione conversazionale. Nessun nuovo deployable centrale, broker o grant nasce da questo piano.

## Sequenza di implementazione e accettazione

| Ordine | Intervento | Prova necessaria |
|---|---|---|
| 1 | Priorità owner e MCP prima dei limiti; conteggi non derivati dalla pagina; recuperi di issue vecchie nel catch-up | Vecchio incidente importante non scompare tra eventi recenti; tenant/visibility preservati; suite owner e pairwise |
| 2 | Contratto pagine/cursor e coverage tra producer | Dataset oltre limite, autorizzazioni parziali, producer assente, pagine concorrenti senza perdita, errori espliciti |
| 3 | Correlazione dipendenza/job e contatori di impatto |5.000 oggetti in attesa, un incidente, nessun retry storm, cause indipendenti separate |
| 4 | Checkpoint accesso/consultazione e riepilogo operatore | Disconnessione durante pagina non marca letto; update di vecchio incidente compare; critical OPEN già noto resta visibile |
| 5 | Circuiti/quote/capacità e crisi su finestre attuali | Un mese di assenza non causa crisi da conteggio; una dipendenza condivisa può causarla; backlog/storage produce backpressure reale |
| 6 | Outbox notifiche, destinatari/canali e presa in carico | Dedup, invio ambiguo/crash, budget esaurito, escalation finita, nessun blocco del lavoro indipendente |
| 7 | Qualifica end-to-end/target e controllo esterno | Decisioni vere, tutti i producer previsti, outage ore, ripresa graduale, piano spento rilevato da percorso indipendente |

Gli ordini sono dipendenze di accettazione, non permesso di saltare work già autorizzato o motivo per chiedere nuovi assensi allo sviluppo. Configurazioni/autorità runtime non verificate restano gate reali.

## Contratto di lettura e memoria operatore

Riutilizzare summary/incidents/explain: evitare capability parallele con la stessa semantica. Lo stato del checkpoint operatore è metadato di consultazione, non un database MCP di incidenti. Identità: principal, tenant, scope/versione di visibilità, tipo checkpoint. L'accesso e la consultazione hanno checkpoint distinti. La sessione conversazionale da sola non è identità durevole.

Una pagina deve avere limite, priorità versionata, copertura/producer disponibili, troncamento o continuation, finestra/high-watermark e timestamp dell'evidence. Il cursor può contenere una mappa opaca delle posizioni owner per comporre fonti indipendenti; deve essere integro, versionato e vincolato al principal/scope autorizzato. Non usare soltanto wall-clock o memoria LLM. Cambi di permessi richiedono rivalutazione; un cursor non concede accesso a dati divenuti invisibili.

Il checkpoint avanzato è una ricevuta esplicita dell'intervallo effettivamente consegnato, con compare-and-set e merge monotono tra sessioni concorrenti; non avanza per richiesta fallita, pagina non consegnata o tool annullato. Nessun ACK di consultazione risolve un incidente. Il protocollo client deve dimostrare la consegna prevista; se tale prova non esiste, mantenere il checkpoint precedente con possibilità di ripetizione del riepilogo.

Una finestra di eventi non è la salute corrente: mostrare separatamente incidenti urgenti attualmente aperti e cambiamenti dall'ultimo checkpoint. Nella prima tranche alcune summary legacy conservano semantica della finestra richiesta; non certificare una piattaforma sana da quella sola risposta. Producer non interrogato, errore e NOT_AUTHORIZED sono condizioni distinguibili secondo policy senza rivelare dettagli protetti.

Retention/cursor scaduto: dichiarare l'intervallo non più ricostruibile e offrire snapshot corrente; mai dichiarare assenza di problemi da storia assente. Minimum30giorni Ingestion non garantisce ricostruzione integrale dopo qualsiasi assenza mensile: configurare un margine coerente con gli operatori previsti.

## Correlazione e crisi

Chiave incidente owner-local: versione, tenant/scope, dipendenza, classe di causa e episodio. Input/link/checkpoint dei job restano nei rispettivi owner. Aggiornamenti e occurrenceCount sono distinti dal numero di job colpiti; aggiornare contatori in modo idempotente e atomico quando possibile. Le quarantene per errori dei singoli dati non sono equivalenti a una sorgente non raggiungibile.

Correlazione deterministica e auditata, non fusione basata su testo LLM o sola prossimità temporale. Un riepilogo può esporre un gruppo correlato con incidentRef dei diversi owner soltanto per riferimenti autorizzati. I dettagli personali/protetti non entrano negli alert o nella proiezione globale.

Profili crisi versionati definiscono finestre, rapporto failure/attempt, min sample, durata, breadth e soglie risorse/età code; segnali a basso volume richiedono interpretazione prudente, non ignorare un guasto critico perché mancano campioni. Conteggio issue storiche non è un tasso. Storage/backlog vicino alla capacità è un segnale attuale anche senza nuovi fault. Hysteresis, cooldown e probe finiti non rinnovano budget incidenti esauriti.

## Consegna e gestione umana

Notifica asincrona derivata da incidente/transizione persistente. Identità delivery: owner incidentRef, transitionVersion, destinationRef, channel e policyVersion. Payload minimo redatto; link esige autenticazione corrente. Preferire recipientRef governati, mantenendo configurazione email fuori dai payload conversazionali; secret del trasporto via custody.

Outbox e incidente nella stessa transazione o riconciliazione durevole equivalente; lease corta/fencing del dispatcher, timeout per invio, retry/backoff finiti e dead-letter di consegna entro capacità. Crash dopo SMTP/provider acceptance può duplicare email: dedup del trasporto dove provata, otherwise almeno-una-volta documentata. La conferma del provider non è lettura umana. Nessun ciclo infinito di alert sul fallimento dell'alert.

Presa in carico HUMAN assegna owner/responsabile e tempo di verifica; non chiude il guasto. Promemoria/escalation finiti e aggiornamenti significativi soltanto. Rientro provato genera una transizione e una notifica di recupero. Decisione di retry concede nuova sessione/budget nel modulo owner, non rinnova automaticamente dal clic sull'email.

Destinatari reali, canali, finestre/manutenzione e soglie devono essere configurati e qualificati prima dell'attivazione. Lo sviluppo non invia messaggi di prova a persone senza istruzione esplicita. Il monitoring esterno del piano di controllo deve essere individuato nella configurazione operativa esistente; una piattaforma spenta non può basarsi soltanto sul proprio dispatcher.

## Stato corrente dei gate — 11 ottobre 2026

| Componente | Stato verificato nel repository | Limite aperto |
|---|---|---|
| Priorità e proiezioni owner/MCP | Integrate e qualificate | Copertura dei sette moduli sul target |
| Pagine stabili e composizione MCP | HTTP/tool qualificati, budget control persistente | Hosting/SDK/network/HA target |
| Bookmark e vettore persistenti | Ingestion PR38–39; Gateway PR66–69; MCP PR59–60 qualificati; HTTP/tool globale PR61 qualificati | Storia degli altri owner, compactor e hosting target |
| Memoria di consultazione | Contratto separato definito | Prova client, capability COMMAND, CAS |
| Pressione e alert | Reference Gateway con budget/capacità finiti | Sampler/dispatcher/trasporto e configurazione reali |

Le sezioni seguenti conservano lo storico delle prime tranche; non rappresentano lo stato più recente dei gate. [Adozione e prove correnti](OUF_RESILIENCE_ADOPTION.md).

## Stato e limiti delle prime tranche

Questo documento è un piano verificabile, non evidence runtime. La prima tranche corregge la priorità/selezione in MCP/Ingestion e nel reference adapter Gateway e il catch-up dei recuperi supportato dalle proiezioni esistenti. Non prova incident dedup condiviso, transizioni complete, cursor, checkpoint operatore, detector sistemico, consegna email o copertura dei sette moduli sul target. R9/R10 restano consumati; nessun preflight/apply sospeso viene riattivato.


## Fondazione di lettura e progettazione cursor — 11 October 2026

[Decisione tecnica cursor/consultazione](OUF_OPERATIONAL_CURSOR_DESIGN.md): revisione di pubblicazione commit-ordered, snapshot immutabili, autorizzazione fresca, limiti di scansione/sessione e ricevute CAS. Un normale sequence o wall-clock non prova il catch-up completo; lock counter dopo row lock può introdurre deadlock. Stato DESIGN/OPEN, senza nuovo deployable centrale.

Integrate e qualificate [MCP PR52](https://github.com/GioNob/ouf-mcp-server/pull/52) per autorizzazione owner/proiezione/coverage/budget e [Ingestion PR36](https://github.com/GioNob/ouf-ingestion-runtime/pull/36) per osservazione persistente di tutte le modifiche e distinzione first-seen/nuova osservazione. [Evidenza finale](../evidence/operational-read-catchup-qualified-20261011.json):20 race operational MCP,28 focused/144 full Ingestion,6/18 gate candidato SUCCESS. Timestamp-only catch-up e summary di finestra non certificano completezza globale o salute corrente; cursor e checkpoint restano OPEN.


## Gate successivo: storia degli incidenti propri MCP

La lettura attuale `SystemStatus` proietta tentativi UNKNOWN/UNRESOLVED, debito attivo, backlog di evidence e un massimo di20 security incident recenti. Questa fotografia non certifica una storia completa: il vettore publication GATEWAY/INGESTION deve continuare a dichiarare `mcpSelfHistoryCovered=false`.

Prima di estendere la coverage, inventariare tutte le transizioni owner di admission, UNKNOWN/UNRESOLVED, riconciliazione/late recovery e security incident. Qualificare una proiezione immutabile persistita insieme alla transizione e un ordine di pubblicazione dei soli commit; non costruire un checkpoint da timestamp o dal massimo sequence privato. Preservare l'ordine lock normativo del PET MCP (claim/admission → window → guard → attempt/reservation/debt/evidence) senza aggiungere lock tenant globali davanti all'admission né mantenere transazioni durante I/O. La soluzione di pubblicazione va qualificata separatamente prima di dichiararne la coverage.

Prove richieste: commit tardivo con identificatore precedente, crash/restart e recupero della proiezione, transizioni auto-risolte durante disconnessione, autorizzazione owner e isolamento tenant, retention/gap/quote, concurrency e assenza di reset dei budget. L'estensione non conferisce autorità di chiudere security incident, cancellare debito, rinnovare quarantene o trasformare una lettura in una ricevuta umana. Le altre storie owner e il contratto client rimangono gate distinti.


Inventario iniziale owner MCP verificato nel codice corrente (proiezione storica ancora OPEN):

| Sorgente | Mutazione da coprire | Vincolo da conservare |
|---|---|---|
| `Store.Reconcile`, `Maintain`, `MarkStaleAndClaim` | Outcome persistenti, RUNNING → UNKNOWN, leases scadute e debito | Admission/claim/guard/window e fencing persistenti; distinguere anche il percorso legacy senza admission context |
| `Store.ApplyOwnerEvidence` | Recupero owner provato di UNKNOWN e riconciliazione di reservation/claim | Evidence dell'owner corrente; nessun perdono locale del debito |
| `ExpireUnknown` | UNKNOWN → UNRESOLVED per max hold | Incidente e blocker restano aperti; la scadenza non è una soluzione |
| `LateCompensate`, `quarantineEvidence`, funzioni SQL di compensazione | Recupero tardivo, mismatch di scope/integrità e security incident deduplicato | CAS, evidence consumata una volta, append-only/audit e isolamento tenant |
| `ReconcileDebtCaches` | Riparazione cache distinta dalla risoluzione del debito | Somma autoritativa del ledger; nessuna nuova autorità di recovery |

Prima dell'implementazione includere anche le mutazioni nelle funzioni SQL e qualificare rollback/trigger/ruoli di migrazione: l'inventario dei soli metodi Go non prova copertura completa. Nessuna nuova storia è dichiarata disponibile da questa revisione.
