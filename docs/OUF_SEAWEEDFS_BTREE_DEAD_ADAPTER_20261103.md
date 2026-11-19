# Eliminazione dell'adattatore B-tree inutilizzato

La generazione29 includeva google/btree v1.1.3 nel grafo compilato solamente per la firma esportata `NeedleValue.Less(btree.Item)` in `weed/storage/needle_map/needle_value.go`. L'ispezione di 3434 file Go trova un solo import del modulo e nessun utilizzo del metodo nel codice applicativo. Il package non costruisce B-tree: l'indice normale usa `CompactMap` e la sua ricerca binaria; il supporto temporaneo `MemDb` usa LevelDB. La rimozione non introduce un altro algoritmo né una nuova dipendenza.

La patch sorgente elimina import e metodo, sei righe in totale. Una patch separata aggiorna esclusivamente il commento `// indirect` di go.mod come richiesto da `go mod tidy`; versione, h1 e go.sum restano invariati. Il modulo continua a comparire nel grafo root per la dipendenza di `github.com/tikv/client-go/v2@v2.0.7`: non viene dichiarata la sua assenza dal modulo root intero.

Il riferimento primario [google/btree](https://github.com/google/btree) risulta archived. Il tag [v1.1.3](https://github.com/google/btree/commit/aeba20f7a1e1315badec4eca4fdc9f754f5f880a) è associato al commit `aeba20f7a1e1315badec4eca4fdc9f754f5f880a`; il checksum modulo conservato è `h1:CVpQJjYgC4VbzxeGVHfvZrv1ctoYCAI8vbl07Fcxlyg=`. Non è stato selezionato né qualificato un fork alternativo: conservare un'interfaccia non utilizzata non richiede una libreria sostitutiva.

Verifiche effettive sulla base29 tree `574ad42543851ffe58cc025e14b1011609ff83de`:

- `./weed/storage/needle_map/...`: 34 test PASS, 2 package PASS.
- `./weed/storage` con filtro `Test.*(Compact|Compaction|NeedleMap|NeedleIndex|Idx)`: 54 test PASS, 2 skip, 1 package PASS.
- Gli skip sono ambientali: enumerazione dei descrittori non disponibile e permessi directory ignorati dall'utente root. Non sono conteggiati come PASS.
- Grafo di produzione: 1811 → 1810 package; unico rimosso `github.com/google/btree`, nessuna aggiunta. Hash del nuovo grafo `9f86744b14271b7bee9b75470c87aa8f78a73998f7b3555fb92cbef4e8b6e41d`.
- Entrambe le patch si riapplicano alla base29 e producono file identici; `go mod tidy -diff` termina con successo e diff vuoto dopo il solo aggiornamento del commento indirect.

Il metodo esportato viene rimosso dall'API Go del fork: consumatori esterni che importassero NeedleValue e chiamassero Less non sono qualificati da questa prova. Nessuna API del server o codifica dei file viene modificata. Le suite esistenti esercitano l'indice e la compattazione; non è stato aggiunto un test che replichi il semplice edit.

Questa è una prova locale di rimozione sorgente e chiusura compilata. Binario, inventario moduli e OCI della generazione30 devono essere ricostruiti e qualificati cumulativamente. Nessun gate, AT, rilascio, autorità runtime o operazione target è emesso da questo stage.
