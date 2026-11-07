# Mapping del CSV Teatri già caricato su SeaweedFS

**Classificazione OPEN acquisita per tutte le 20 colonne.** Giovanni ha affidato all'agente l'analisi semantica e chiarito che richiede proprietà condivise per il significato delle colonne, non enumerazioni dei valori.

Asset `c51745c5-1fc0-4d36-bdcf-1e9a8a049c94`, profilo `da3f17a2-5cbc-4d7d-9ed8-7f4b39a00342`: 13 righe, 20 colonne, CSV UTF-8 separato da `;`. Preview letta via MCP. Non ricaricare o riprofilare.

## Stato della proposta

[Tabella completa dei riferimenti delle 20 colonne](OUF_TEATRI_COLUMN_SEMANTIC_REFERENCES_20261107.md).

La revisione Teatri pubblicata è stata riletta: `schema:name` è il riferimento condiviso per il nome; `schema:additionalType` è il candidato già presente per la tipologia, da verificare nella definizione esterna. Le altre 18 proprietà sono locali con dominio PerformingArtsTheater: non vengono dichiarate automaticamente generiche per oggetti diversi.

Il [payload di lavoro](../releases/TEATRI_SEAWEEDFS_MAPPING_REVIEW_20261107.json) contiene tutte le colonne OPEN/INCLUDE/IDENTITY e la chiave proposta `nome_teatro`; conserva temporaneamente gli URI del mapping precedente. **Non è il mapping finale validato per interoperabilità tra tipi diversi**, non è stato inviato e non rappresenta una bozza applicativa.

Celle CSV lessicali, CAP con zeri iniziali e coordinate originali conservati. Le coordinate ambigue non sono convertite automaticamente. Nome originale della colonna e provenienza restano conservati; il riferimento canonico si applica nel mapping.

## Impedimento e continuazione

La connessione MCP non espone la discovery esterna OntoPiA/schema.gov.it; ricerca locale e lettura esatta funzionano, ma non dimostrano copertura nazionale. L'ultima ricerca Cinema è stata rifiutata per budget di orchestrazione con retryable:false, senza retry o reset.

Il prossimo lavoro è completare il percorso di discovery già candidato, verificare le definizioni delle proprietà condivise e chiudere il mapping. Poi creare una bozza idempotente `teatri-seaweedfs-c51745c5`, leggere versione/hash e preparare la review nativa THS. L'approvazione HUMAN resta nella THS; nessuna nuova scelta generica OPEN/RESTRICTED è richiesta.

La sorgente storica `teatri-csv-6609b245` è invariata e non riacquisita. Nessuna nuova ontologia, bozza, approvazione o Ingestion inviata.

[Evidenze MCP](../evidence/teatri-column-semantic-reference-review-20261107.json) · [Stato operativo](STATE.md).
