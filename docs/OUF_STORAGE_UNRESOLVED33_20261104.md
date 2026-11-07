# Esito irrisolto: assenza e corruzione — fixture33, 2026-11-04

## Contratto e perimetro

Due stati sintetici distinti con intento PostgreSQL persistente: oggetto assente (nessun PUT dell'oggetto ambiguo) e contenuto alterato della stessa lunghezza (un PUT di 45 byte, metadata con hash atteso). Il precedente ACK resta valido. Sono stati costruiti per la qualifica negativa della riconciliazione; non viene iniettata una nuova perdita HTTP né simulata una cancellazione di dati target.

Si riusa il verificatore S3 del common cut positivo. Il caso assente richiede LIST completo con il solo oggetto ACKED, GET404 NoSuchKey e HEAD404; lista incompleta, bucket assente, diniego IAM e trasporto in errore non equivalgono all'esito atteso. La corruzione richiede LIST esatto, GET/HEAD e confronto dei byte effettivi: lunghezza e metadata apparentemente validi non autorizzano la riconciliazione. La funzione PostgreSQL rifiuta con CONFLICT l'hash effettivo del contenuto alterato; per l'oggetto assente non viene inventata un'identità da riconciliare.

Dopo il drain e il fermo/riavvio S3 della sola identità fixture in Read/List, lo stesso intento restituisce EXISTING_PENDING, la pubblicazione tardiva FENCED e il freeze RECONCILE_REQUIRED. Le stesse verifiche sono ripetute dopo un PostgreSQL immediate restart: controllo DRAINING epoch2/version1, ACK, intento PENDING e quattro eventi devono essere identici. Non si generano common-cut.json, dump o restore di uno stato irrisolto; nessun PUT di recupero.

## Qualifica

54 test locali e hosted PASS: 43 common-cut/crash/perdita risposta/controlli negativi, sette writer fence e quattro restore. Workflow dedicato con i tre percorsi positivi di regressione e due nuovi percorsi negativi in radici separate. Tutti e cinque i percorsi nativi PASS; archivio originale verificato.

## Esito nativo e verifica delle evidenze

- Producer `2d3d8a41121751abad9da9ab4849fa1112dd1676`; [run 41809311981](https://github.com/GioNob/ouf-deploy/actions/runs/41809311981), job `126504250931` SUCCESS, artifact `13311672444`.
- Caso assente: LIST completo del solo ACK, GET 404 NoSuchKey e HEAD 404; nessun PUT dell'oggetto ambiguo e nessuna identità inventata per la riconciliazione.
- Caso corrotto: un PUT fixture da 45 byte, lunghezza e metadata hash atteso conservati ma corpo alterato; il verificatore common cut rifiuta i byte e PostgreSQL restituisce CONFLICT per l'hash effettivo, due volte.
- In entrambi: due risposte EXISTING_PENDING, due FENCED e due RECONCILE_REQUIRED, prima/dopo immediate restart. Ledger identico, DRAINING epoch 2/version 1, ACK e PENDING originali, esattamente quattro eventi. Hash ledger prima/dopo `a010f085104fd341357d75ec071d5b226d6b5016b8e4bf5450c1b7f66291c0c7`; nessun evento RECONCILED/FROZEN e nessun common cut, dump o restore dei casi negativi.
- Sei dinieghi S3 per caso negativo e otto container distinti arrestati pulitamente per caso. Conservate le tre regressioni positive con restore completo; totale cinque percorsi e 52 ID container distinti. Zero PUT di recupero in tutti i percorsi.
- ZIP originale [storage-unresolved33-41809311981.zip](../evidence/artifacts/storage-unresolved33-41809311981.zip), 376528 byte, SHA256 `d58d2926ef111345a3048f94f706e27b84c1cf70432cac1aeb0f60e61886dfb8`. Verificati 616 membri, 615 checksum e 28 sorgenti/input esatti. [Receipt di rilettura](../evidence/storage-unresolved33-readback-20261104.json).
- Rilettura locale di ZIP, SQL, ledger e report nativi; i corpi S3/cold non sono esportati, non è stato eseguito un secondo restore locale e non si dichiara verifica crittografica locale della firma publisher. La coorte è verificata hosted con l'esatto source commit.

## Prossimo singolo passo

Qualificare la rotazione delle credenziali S3 nella fixture: nuova chiave valida, vecchia chiave revocata, letture coerenti e dinieghi delle credenziali superate. Segue SW-WP3 del MiniPET; nessuna rotazione di credenziali target è autorizzata da questa prova. Non eseguito in questo checkpoint.

## Limiti e avanzamento

Fixture OCI33 esatta e PostgreSQL17.11, bucket non versionato, una sola identità S3. Il blocco atteso è il risultato positivo del test negativo; non è un restore riuscito dei dati assenti o corrotti. Non prova quarantena/incidente runtime, recupero governato HUMAN, RPO/RTO o PITR coordinato. Nessun dato reale, operazione VPS, merge/deploy, grant o replay. Nessun criterio target chiuso. MiniPET invariato 18,3/46, circa40% ±10; 0/8 gate, 0/21 AT, 0/120 oggetti reali.

Policy applicata: OUF_RESILIENCE_POLICY.md regole4–6, §§quarantena/recupero; PET Ingestion1.3 §§7.3 e20.1/21; Matrix1.7 preservata. I checkpoint avanzano soltanto su evidence valida e stato durevole, senza reinvio mutativo alla cieca o reset di storico.
