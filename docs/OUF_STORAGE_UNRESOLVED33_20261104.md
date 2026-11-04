# Esito irrisolto: assenza e corruzione — fixture33, 2026-11-04

## Contratto e perimetro

Due stati sintetici distinti con intento PostgreSQL persistente: oggetto assente (nessun PUT dell'oggetto ambiguo) e contenuto alterato della stessa lunghezza (un PUT di 45 byte, metadata con hash atteso). Il precedente ACK resta valido. Sono stati costruiti per la qualifica negativa della riconciliazione; non viene iniettata una nuova perdita HTTP né simulata una cancellazione di dati target.

Si riusa il verificatore S3 del common cut positivo. Il caso assente richiede LIST completo con il solo oggetto ACKED, GET404 NoSuchKey e HEAD404; lista incompleta, bucket assente, diniego IAM e trasporto in errore non equivalgono all'esito atteso. La corruzione richiede LIST esatto, GET/HEAD e confronto dei byte effettivi: lunghezza e metadata apparentemente validi non autorizzano la riconciliazione. La funzione PostgreSQL rifiuta con CONFLICT l'hash effettivo del contenuto alterato; per l'oggetto assente non viene inventata un'identità da riconciliare.

Dopo il drain e il fermo/riavvio S3 della sola identità fixture in Read/List, lo stesso intento restituisce EXISTING_PENDING, la pubblicazione tardiva FENCED e il freeze RECONCILE_REQUIRED. Le stesse verifiche sono ripetute dopo un PostgreSQL immediate restart: controllo DRAINING epoch2/version1, ACK, intento PENDING e quattro eventi devono essere identici. Non si generano common-cut.json, dump o restore di uno stato irrisolto; nessun PUT di recupero.

## Qualifica

54 test locali: 43 common-cut/crash/perdita risposta/controlli negativi, sette writer fence e quattro restore. Workflow dedicato con i tre percorsi positivi di regressione e due nuovi percorsi negativi in radici separate. Prova nativa e rilettura archivio originale PENDING.

## Limiti e avanzamento

Fixture OCI33 esatta e PostgreSQL17.11, bucket non versionato, una sola identità S3. Il blocco atteso è il risultato positivo del test negativo; non è un restore riuscito dei dati assenti o corrotti. Non prova quarantena/incidente runtime, recupero governato HUMAN, RPO/RTO o PITR coordinato. Nessun dato reale, operazione VPS, merge/deploy, grant o replay. Nessun criterio target chiuso. MiniPET invariato 18,3/46, circa40% ±10; 0/8 gate, 0/21 AT, 0/120 oggetti reali.

Policy applicata: OUF_RESILIENCE_POLICY.md regole4–6, §§quarantena/recupero; PET Ingestion1.3 §§7.3 e20.1/21; Matrix1.7 preservata. I checkpoint avanzano soltanto su evidence valida e stato durevole, senza reinvio mutativo alla cieca o reset di storico.
