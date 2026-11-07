# Budget dell'analisi semantica proporzionato al profilo

Decisione dell'owner, 7 novembre 2026: il lavoro deve poter trattare oggetti di 50, 100, 200 colonne e oltre. Il budget dell'analisi deve seguire le dimensioni effettive. Stato: requisito acquisito; implementazione dinamica non ancora presente.

## Fatti verificati

Nel sorgente MCP conservato `d2454f3c`, il limite corrente è una finestra di un minuto con capacità predefinita di tre chiamate, oltre a byte e unità oggetto/debito. Non è un budget totale già associato all'analisi di un file. La risposta generica dell'ultima ricerca Cinema non identifica quale dimensione abbia esaurito quella finestra.

La preview Onboarding già acquisita espone `metadata.columns=20`, venti descrittori di colonna, assetId, profileId e profileVersion. Non occorre un nuovo upload o una nuova profilazione.

I contratti attuali di `semantic.search` e `semantic.get` non contengono un riferimento al profilo sorgente. L'ammissione corrente conosce identità, capacità e finestra, ma non l'oggetto che si sta mappando. Il collegamento profilo→analisi→lettura è quindi da implementare: non basta rendere variabile una costante.

## Decisione operativa

Separare tre quantità:

| Quantità | Criterio |
| --- | --- |
| Lavoro complessivo dell'analisi | Dimensionato dal profilo effettivo e dalle operazioni pianificate per le colonne; tener conto delle alternative necessarie e del riuso di definizioni già lette. |
| Ritmo e concorrenza delle richieste | Proteggono MCP e dipendenze; un oggetto grande attraversa più finestre se necessario. Nessuna equivalenza automatica tra 200 colonne e 200 richieste simultanee. |
| Tentativi equivalenti dopo un errore | Restano distinti dal lavoro utile su colonne diverse. Un budget maggiore per l'oggetto non autorizza un ciclo di retry senza fine. |

Il numero di colonne è l'ingresso iniziale, non una misura completa della complessità semantica. Una lettura di ontologia può coprire più colonne; una colonna ambigua può richiedere più ricerche. La funzione iniziale sarà deterministica e configurata dal servizio, con una quota comune e una quota per colonna; coefficienti, eventuali fasce e riserva per approfondimenti non sono ancora scelti né qualificati. Non spacciare una formula arbitraria per dimensionamento misurato.

Il conteggio proviene dal profilo autorevole autorizzato, non da un `columnCount` libero inviato dal chatbot. L'identità dell'analisi deve conservare tenant, soggetto, asset e profilo/versione verificati; il contratto deve definire come legare uno schema immutabile e riconoscere un profilo cambiato. La stessa analisi ripresa conserva consumo, risposte e avanzamento. Un nuovo correlation ID o un riavvio non deve duplicare la quota né ripetere colonne completate.

Alla saturazione della sola finestra temporale, il lavoro resta in attesa con motivo e tempo di ripresa. L'attesa non trattiene transazioni/lock condivisi. La ripresa ricontrolla l'autorizzazione. Esaurimento del lavoro pianificato, errore permanente e ambiguità restano condizioni diverse ed esplicite.

## Due interventi verificabili

1. **Profilo e dimensionamento:** associare le letture a una specifica analisi del profilo posseduto; calcolare la quota dal numero reale di colonne e dal piano; conservare identità e consumo. Verificare 20, 50, 100 e 200 colonne, conteggi alterati, profilo non posseduto, cambio di versione e ripresa della stessa analisi. Non riaprire l'intero programma di industrializzazione.
2. **Avanzamento e ripresa:** conservare per colonna stato, riferimenti semantici esatti già letti e motivo degli irrisolti; attendere la successiva finestra senza nuovi tentativi equivalenti inutili. Provare interruzione/ripresa e completamento dell'oggetto di 200 colonne attraverso più finestre. Stato finale: colonne risolte oppure irrisolte con motivo, mai completamento silenzioso di una parte.

Il primo intervento richiede definire il collegamento applicativo oggi assente; non viene dichiarato già implementato da questa nota. Il secondo non è dimostrato dai test del limite fisso.

## Candidato già prodotto, non da distribuire come soluzione finale

[MCP PR82](https://github.com/GioNob/ouf-mcp-server/pull/82), commit `cdfb850b26d8d2e1c1481071c8a281a55a553bac`, separa le letture semantiche e porta la finestra a 60 chiamate/minuto. Introduce errore esplicito con dimensione e tempo di ripresa. Questo è un limite fisso, quindi **non soddisfa il requisito dinamico dell'owner**. Nessun rollout di questa soluzione fissa.

[Qualifica mirata](https://github.com/GioNob/ouf-mcp-server/actions/runs/42413075158) e [CI esistente completa](https://github.com/GioNob/ouf-mcp-server/actions/runs/42413075174) riuscite: test Go/race e PostgreSQL, build immagine, staticcheck, govulncheck. Nove sorgenti Go coincidono con il readback gofmt nativo. La prima versione falliva solo la formattazione, corretta prima di questi run. Artefatto immagine `13590830257`, digest archivio `070020326c9125c615cf42055a945fe47ce776d8d4039c0968e374703676c14e`; il digest dell'archivio non è l'ID dell'immagine Docker.

Riusare diagnostica e verifiche pertinenti nella soluzione proporzionale. Non confondere questi pass con prove su 50/100/200 colonne o con aggiornamento VPS. Il lettore runtime `scripts/ouf-mcp-budget-runtime-read-20261107.py` è stato conservato nel commit deploy `51125a9b719c1f6952680af19b691712f862893b` prima della precisazione; non eseguito e non richiesto ora all'operatore.

## Continuità del percorso SeaweedFS → E2E

F1 resta riuscito. File, profilo e mapping OPEN sono conservati. Nessun cambiamento VPS, policy, storage, SQL reset, upload o Ingestion in questo intervento.

La discovery esterna OntoPiA/schema.gov.it non esposta nella connessione resta distinta: più budget non aggiunge strumenti mancanti. Dopo collegamento e dimensionamento, riprendere i candidati esistenti e il mapping delle proprietà delle colonne, quindi bozza/review THS/Ingestion→UDP→grafo. Non introdurre la classificazione dei singoli valori come nuovo requisito.

[Evidenza e limiti](../evidence/semantic-analysis-budget-review-20261107.json).
