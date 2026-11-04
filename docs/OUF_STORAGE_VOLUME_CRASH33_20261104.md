# SIGKILL volume e ripresa con rete isolata — fixture33, 2026-11-04

## Contratto della prova

Dopo un singolo PUT S3 concluso HTTP200, il controller invia SIGKILL al solo volume. L'oggetto binario deterministico è di 8 MiB +257 byte; il seed non effettua GET del corpo per non popolare la cache di lettura. Il container terminato deve mantenere lo stesso ID, exit137, Running=false, OOMKilled=false e nessun errore Docker; stato e log originali sono conservati.

A volume fermo si acquisisce un inventario bounded dei file .dat (nomi, dimensioni, hash), con dimensione complessiva almeno pari al payload. Il sostituto usa lo stesso mount dati, la stessa immagine e IP, ma un nuovo container, nuovo namespace non host e una directory gate vuota. Prima dell'exec weed vengono reinstallate le regole nft; i due listener volume devono essere ancora chiusi. Gli altri quattro container conservano ID, StartedAt e RestartCount.

La prima rilettura S3 successiva deve coincidere per bytes/hash/MIME e LIST completo. Un contatore nft sulla risposta HTTP del volume, collocato prima dell'accept established, deve aumentare di almeno la lunghezza del payload: la prova non può passare con un corpo servito soltanto dalla cache. I prefissi dei file .dat registrati a volume fermo devono restare identici; sono ammessi append di log di servizio. Nessun PUT di recupero o reseed. Solo HTTP500/502/503/504 espliciti autorizzano fino a sei tentativi di lettura; errori d'integrità, IAM, trasporto non classificato o timeout bloccano la prova. Tentativi e risposte sono conservati separatamente; nessuna promessa RTO.

Segue l'intera matrice rete, 10 collegamenti ammessi,22 dinieghi tra ruoli e15 DNS/host gateway con contatori, e una seconda lettura del corpo. Cinque arresti finali puliti, oltre al volume terminato intenzionalmente, e rimozione bridge. Il percorso normale precedente viene rieseguito in una radice separata nello stesso workflow.

## Stato

42 test locali PASS: 10 nuovi,10 isolamento e22 regressioni credential/TLS. Prova nativa richiesta, esito PENDING. Il workflow conserva anche gli esiti falliti e distingue SIGKILL intenzionale da cleanup non riuscito.

## Limiti

Crash di processo su filesystem dello stesso host, non power loss, reboot host, perdita del disco, fault in-flight o ripristino da backup. Il page cache dell'host resta disponibile: nessuna garanzia di durabilità su alimentazione persa, RPO/RTO produttivi o accettazione target. Topologia singola per ruolo e credenziali sintetiche pubbliche; limiti di isolamento IPv4 e autorizzazione delle API interne invariati. Nessuna operazione VPS, migrazione, merge/deploy, reset/replay/grant. MiniPET invariato18,3/46, circa40% ±10;0/8 gate,0/21 AT,0/120 oggetti reali.
