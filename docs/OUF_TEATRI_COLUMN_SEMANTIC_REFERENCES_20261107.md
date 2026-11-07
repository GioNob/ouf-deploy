# Teatri — significato delle colonne e proprietà condivise

7 novembre 2026. Richiesta dell'owner: associare ogni colonna alla proprietà di un vocabolario/ontologia condiviso, identificata da URI stabile, per confrontare dati di oggetti diversi. **Il lavoro riguarda il significato della colonna, non l'enumerazione dei suoi valori.** Classificazione scelta: **OPEN per tutte le 20 colonne**; la futura review HUMAN resta distinta dall'analisi.

## Risultato verificato tramite MCP

`semantic.search(q=Teatri)` trova Teatri 1.0.0 ACTIVE. `semantic.get` legge la revisione `a1db3912-2b72-42eb-af88-a775fcd0e2ab`, publication set `9fe7d1ee-9e13-40bc-ad50-53e36ea0076b`: 105 statement, snapshot completo. La risposta è identica a quella conservata nel [commit precedente](https://github.com/GioNob/ouf-deploy/blob/39c646e4d2a34639a5648f9596e0330485db3cc0/evidence/semantic-recovery-functional-read-20261107.json).

Lo snapshot contiene due proprietà con URI schema.org e 18 proprietà locali con dominio `schema:PerformingArtsTheater` e range `xsd:string`. La presenza delle proprietà locali non dimostra che siano i riferimenti condivisi migliori per oggetti di altri tipi. Per i due termini schema.org lo snapshot dichiara rdf:Property ed etichetta, ma non definizione completa, range o dominio esterni.

La ricerca PROPERTY `nome` e le ricerche `indirizzo`/`coordinate` restituiscono liste vuote. Questo non prova l'assenza dei termini: alcuni sono presenti nello snapshot dell'ontologia già letto. Le ricerche iniziali sui vocabolari di valori sono conservate nell'evidenza, ma non costituiscono più l'obiettivo dopo il chiarimento dell'owner.

## Tabella delle 20 colonne

Prefissi: `schema:` = `https://schema.org/`; `teatri:` = `https://api.ouf-lab.it/semantic/teatri#`.

**Confermato:** riferimento condiviso utilizzabile per il significato della colonna sulla base della lettura disponibile. **Candidato:** riferimento presente ma definizione esterna da verificare. **Locale:** proprietà già pubblicata nel profilo Teatri; allineamento a una proprietà più generale ancora aperto.

| Colonna CSV | Significato da rappresentare | Riferimento attuale letto via MCP | Esito |
| --- | --- | --- | --- |
| `nome_teatro` | Nome del luogo | `schema:name` | Confermato |
| `tipologia` | Classificazione aggiuntiva del luogo | `schema:additionalType` | Candidato |
| `toponimo` | Tipo di elemento stradale | `teatri:toponimo` | Locale; allineamento aperto |
| `nome_indirizzo` | Denominazione della strada | `teatri:nome_indirizzo` | Locale; allineamento aperto |
| `civico` | Numero civico | `teatri:civico` | Locale; allineamento aperto |
| `cap` | Codice postale | `teatri:cap` | Locale; allineamento aperto |
| `citta` | Località dell'indirizzo | `teatri:citta` | Locale; allineamento aperto |
| `provincia` | Riferimento provinciale dell'indirizzo | `teatri:provincia` | Locale; allineamento aperto |
| `latitudine` | Latitudine della posizione dichiarata | `teatri:latitudine` | Locale; allineamento aperto |
| `longitudine` | Longitudine della posizione dichiarata | `teatri:longitudine` | Locale; allineamento aperto |
| `sistema_riferimento` | Sistema di riferimento delle coordinate | `teatri:sistema_riferimento` | Locale; allineamento aperto |
| `precisione_coordinate` | Precisione e riferimento geometrico dichiarati | `teatri:precisione_coordinate` | Locale; allineamento aperto |
| `capienza_posti` | Capienza in posti della struttura o sala indicata | `teatri:capienza_posti` | Locale; allineamento aperto |
| `spettacoli_stagione` | Numero di spettacoli nel periodo indicato | `teatri:spettacoli_stagione` | Locale; allineamento aperto |
| `stagione_riferimento` | Periodo della misura relativa agli spettacoli | `teatri:stagione_riferimento` | Locale; allineamento aperto |
| `note` | Annotazioni della fonte sul record | `teatri:note` | Locale; allineamento aperto |
| `fonte_indirizzo` | Provenienza delle informazioni di indirizzo | `teatri:fonte_indirizzo` | Locale; allineamento aperto |
| `fonte_coordinate` | Provenienza delle coordinate | `teatri:fonte_coordinate` | Locale; allineamento aperto |
| `fonte_altri_dati` | Provenienza degli altri dati | `teatri:fonte_altri_dati` | Locale; allineamento aperto |
| `data_verifica` | Data della verifica dichiarata dalla fonte | `teatri:data_verifica` | Locale; allineamento aperto |

## Criterio per il mapping condiviso

Conservare il nome originale del CSV e la provenienza. Nel mapping associare una proprietà canonica con URI, etichetta leggibile, definizione, revisione/pubblicazione e vincoli verificati. Il confronto fra dataset deve partire dall'identità semantica, non dalla semplice uguaglianza del nome di colonna. Una stessa proprietà è condizione utile, ma unità, periodo e ambito devono essere compatibili per confrontare i valori.

Per `tipologia`, `schema:additionalType` è il candidato già pubblicato. Non basta chiamare due campi “tipologia”: possono classificare dimensioni diverse. Non viene introdotto un vocabolario di categorie né una conversione automatica in classi.

## Distinzioni da preservare

- `toponimo` contiene nel campione Via/Viale/Piazza/Riva: tipo di elemento stradale, distinto da `nome_indirizzo`. Un termine standard con dominio Address o range risorsa può richiedere un nodo indirizzo e non una semplice sostituzione dell'URI sulla risorsa teatro.
- `civico` e `cap` sono identificativi lessicali. `citta` non prova da sola l'identità di un comune; `provincia` è il riferimento riportato dalla fonte, senza risoluzione amministrativa.
- Latitudine/longitudine hanno formati ambigui (`4.565.094`/`1.376.850`): riferimento di proprietà e validità del valore sono verifiche distinte. Nessuna conversione geografica automatica. `precisione_coordinate` combina accuratezza e oggetto geometrico e può richiedere due proprietà.
- `capienza_posti` può riguardare una sala secondo le note. `spettacoli_stagione` è un conteggio qualificato dalla stagione; non è un elenco di eventi.
- Le tre `fonte_*` esprimono provenienza di informazioni diverse; non sono automaticamente il sito ufficiale del teatro. `data_verifica` non equivale alla data di modifica o ingestione.
- `note` conserva annotazioni della fonte. La preview è parziale (5 righe su 13, con redazioni): nessuna lettura integrale delle celle è dichiarata.

## Limite concreto degli strumenti

La connessione corrente espone ricerca/lettura del catalogo locale e proposta/review Semantic; **non espone discovery.request/status/candidates verso OntoPiA/schema.gov.it**. Non si afferma che manchino vocabolari nazionali: manca il percorso per consultarli attraverso l'MCP richiesto.

Il codice candidato già esiste: [MCP PR81](https://github.com/GioNob/ouf-mcp-server/pull/81), [Gateway PR84](https://github.com/GioNob/ouf-api-gateway/pull/84), [Registry PR41](https://github.com/GioNob/ouf-semantic-registry/pull/41). Le PR lette sono aperte/non merged; MCP descrive i tre descrittori INACTIVE. La lettura dei sorgenti non dimostra che quelle versioni siano installate. Prima di preparare il delta runtime occorre riconciliare i binding attuali con i candidati già qualificati, preservando il percorso file/SeaweedFS funzionante. Non riusare comandi di manutenzione consumati.

L'ultima ricerca `Cinema` è stata rifiutata: `orchestration budget exhausted`, `retryable:false`. Non è una risposta vuota, non è stata ripetuta e non sono stati cambiati account o budget.

## Prossimo passo

Completare il percorso funzionale di discovery già previsto, poi cercare proprietà esterne e leggerne definizioni/domain/range con riferimenti esatti. Confrontare quei risultati con la tabella sopra e preparare il mapping finale per la bozza e review THS. Non sostituire la ricerca governata con URI ricordati a memoria, import manuali o nuove ontologie locali per simulare la copertura.

[Proposta aggiornata OPEN](../releases/TEATRI_SEAWEEDFS_MAPPING_REVIEW_20261107.json) · [Risposte MCP ed evidenze](../evidence/teatri-column-semantic-reference-review-20261107.json) · [Stato](STATE.md). Nessuna bozza, approvazione, ingestion, pubblicazione semantica o modifica runtime effettuata da questo aggiornamento.
