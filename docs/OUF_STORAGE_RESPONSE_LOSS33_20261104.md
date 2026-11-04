# Perdita risposta HTTP dopo PUT — fixture33, 2026-11-04

## Perimetro e contratto

Il relay monouso loopback inoltra la richiesta firmata byte per byte una sola volta, riceve HTTP200 completo da SeaweedFS33 e chiude la connessione al client senza consegnare alcun byte della risposta. Il client deve osservare RemoteDisconnected: timeout, risposta upstream assente/troncata o errore S3 non sono PASS. Limiti di dimensione e timeout, solo loopback, nessun header di autenticazione nei report.

L'intento PostgreSQL17.11 è persistito prima dell'I/O e resta PENDING dopo la disconnessione. Ripresentare la stessa chiave deve restituire EXISTING_PENDING senza modificare ledger/storico né autorizzare un secondo PUT. La ricevuta del relay è solo diagnostica: la riconciliazione usa GET/HEAD/LIST reali dopo il drain e il fencing della sola identità fixture. Segue il punto comune quiescente e il restore in cluster PostgreSQL e radici S3 indipendenti, con ACK/storico, oggetti/hash/MIME e dinieghi conservati.

## Verifica

42 test locali previsti: 31 common-cut/crash/response-loss, sette writer fence e quattro restore. Il workflow mantiene i percorsi normale e SIGKILL in radici separate e aggiunge response-loss-lab. Esito nativo PENDING fino a esecuzione e verifica dell'archivio originale.

## Limiti

Due oggetti sintetici/77 byte per percorso; bucket non versionato, un PUT completo, nessuno streaming/multipart o crash host. Il relay dimostra una risposta HTTP200 osservata upstream e persa downstream, non una garanzia generica di durabilità a qualsiasi guasto. Nessun resend alla cieca; non è una prova di exactly-once generale. Nessun cambiamento target/VPS, gate o AT chiuso, PITR coordinato o RPO/RTO produttivo. MiniPET invariato: 18,3/46, circa40% ±10; 0/8 gate, 0/21 AT, 0/120 oggetti reali.
