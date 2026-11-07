# Perdita risposta HTTP dopo PUT — fixture33, 2026-11-04

## Perimetro e contratto

Il relay monouso loopback inoltra la richiesta firmata byte per byte una sola volta, riceve HTTP200 completo da SeaweedFS33 e chiude la connessione al client senza consegnare alcun byte della risposta. Il client deve osservare RemoteDisconnected: timeout, risposta upstream assente/troncata o errore S3 non sono PASS. Limiti di dimensione e timeout, solo loopback, nessun header di autenticazione nei report.

L'intento PostgreSQL17.11 è persistito prima dell'I/O e resta PENDING dopo la disconnessione. Ripresentare la stessa chiave deve restituire EXISTING_PENDING senza modificare ledger/storico né autorizzare un secondo PUT. La ricevuta del relay è solo diagnostica: la riconciliazione usa GET/HEAD/LIST reali dopo il drain e il fencing della sola identità fixture. Segue il punto comune quiescente e il restore in cluster PostgreSQL e radici S3 indipendenti, con ACK/storico, oggetti/hash/MIME e dinieghi conservati.

## Verifica

42 test locali e hosted PASS: 31 common-cut/crash/response-loss, sette writer fence e quattro restore. Il workflow mantiene i percorsi normale e SIGKILL in radici separate e aggiunge response-loss-lab. Tutti e tre i percorsi nativi PASS; archivio originale verificato.

## Esito nativo e rilettura indipendente

- Producer `0bd31c7507571f6a0538130805d546ced624292d`; [run41807405448](https://github.com/GioNob/ouf-deploy/actions/runs/41807405448), job126497752202 SUCCESS, artifact13309409739.
- Relay: un PUT da 45 byte inoltrato, HTTP200 upstream, zero byte di risposta downstream, client RemoteDisconnected, thread terminato. PostgreSQL conserva PENDING e l'ACK precedente; stessa chiave EXISTING_PENDING, ledger prima/dopo identico, zero PUT in ripresa. La riconciliazione usa il contenuto osservato in S3 e precede FROZEN.
- Percorsi normale/crash/perdita risposta in tre radici indipendenti: ciascuno due oggetti/77 byte, sei dinieghi S3 prima/dopo restore, due cluster PostgreSQL distinti e12 container arrestati pulitamente. Totale36 container con ID distinti; dump/ledger/storico e manifest confrontati, prefisso eventi invariato; diagnostica SQL restored conservata.
- ZIP originale [storage-response-loss33-41807405448.zip](../evidence/artifacts/storage-response-loss33-41807405448.zip), 278361 byte, SHA256 `3b18c3d6788928e7533517ba60d0038283af206fb736cefc01cea6f368951116`. Rilettura:423 membri/422 checksum,26 sorgenti e input confrontati con i byte esatti del producer. [Receipt](../evidence/storage-response-loss33-readback-20261104.json).
- La rilettura locale verifica l'archivio e i risultati nativi; payload S3/cold non esportati, nessun secondo restore locale o verifica crittografica locale della firma publisher dichiarati. La verifica del publisher della coorte è eseguita hosted; non sostituisce l'accettazione target.

## Prossimo singolo passo

Controllo negativo dell'esito incerto: se la rilettura non trova un oggetto valido, il sistema deve mantenere l'intento irrisolto e impedire il freeze, senza reinvio automatico. Non eseguito in questo checkpoint.

## Limiti

Due oggetti sintetici/77 byte per percorso; bucket non versionato, un PUT completo, nessuno streaming/multipart o crash host. Il relay dimostra una risposta HTTP200 osservata upstream e persa downstream, non una garanzia generica di durabilità a qualsiasi guasto. Nessun resend alla cieca; non è una prova di exactly-once generale. Nessun cambiamento target/VPS, gate o AT chiuso, PITR coordinato o RPO/RTO produttivo. MiniPET invariato: 18,3/46, circa 40% ±10; 0/8 gate, 0/21 AT, 0/120 oggetti reali.
