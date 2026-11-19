# SIGKILL volume e ripresa con rete isolata — fixture33, 2026-11-04

## Contratto della prova

Dopo un singolo PUT S3 concluso HTTP200, il controller invia SIGKILL al solo volume. L'oggetto binario deterministico è di 8 MiB +257 byte; il seed non effettua GET del corpo per non popolare la cache di lettura. Il container terminato deve mantenere lo stesso ID, exit137, Running=false, OOMKilled=false e nessun errore Docker; stato e log originali sono conservati.

A volume fermo si acquisisce un inventario bounded dei file .dat (nomi, dimensioni, hash), con dimensione complessiva almeno pari al payload. Il sostituto usa lo stesso mount dati, la stessa immagine e IP, ma un nuovo container, nuovo namespace non host e una directory gate vuota. Prima dell'exec weed vengono reinstallate le regole nft; i due listener volume devono essere ancora chiusi. Gli altri quattro container conservano ID, StartedAt e RestartCount.

La prima rilettura S3 successiva deve coincidere per bytes/hash/MIME e LIST completo. Un contatore nft sulla risposta HTTP del volume, collocato prima dell'accept established, deve aumentare di almeno la lunghezza del payload: la prova non può passare con un corpo servito soltanto dalla cache. I prefissi dei file .dat registrati a volume fermo devono restare identici; sono ammessi append di log di servizio. Nessun PUT di recupero o reseed. Solo HTTP500/502/503/504 espliciti autorizzano fino a sei tentativi di lettura; errori d'integrità, IAM, trasporto non classificato o timeout bloccano la prova. Tentativi e risposte sono conservati separatamente; nessuna promessa RTO.

Segue l'intera matrice rete, 10 collegamenti ammessi,22 dinieghi tra ruoli e15 DNS/host gateway con contatori, e una seconda lettura del corpo. Cinque arresti finali puliti, oltre al volume terminato intenzionalmente, e rimozione bridge. Il percorso normale precedente viene rieseguito in una radice separata nello stesso workflow.

## Stato

42 test locali PASS: 10 nuovi,10 isolamento e22 regressioni credential/TLS. Prova nativa PASS per percorso normale e crash, archivio originale verificato. Il workflow conserva anche gli esiti falliti e distingue SIGKILL intenzionale da cleanup non riuscito.

## Esito nativo e rilettura

- Producer `c3eb9b8d267463557c872ad278713321ae8a1dc8`; [run 41814532710](https://github.com/GioNob/ouf-deploy/actions/runs/41814532710), job `126521953635` SUCCESS, artifact `13312894925`. Tutti i 42 test hosted PASS; percorso normale e percorso SIGKILL in radici separate PASS.
- PUT HTTP200 e nessun GET del corpo prima del guasto. Volume originale terminato con SIGKILL, exit137/non-OOM; nuovo container e namespace, stesso mount dati e IP. Master, filer, S3 e client mantengono ID, StartedAt e RestartCount. Due listener ancora chiusi dopo l'installazione nft e prima della nuova apertura gate.
- Oggetto di **8388865 byte**, SHA256 `25809f4ef8ae5e9ab82c2688effb8da2ae66bb0b320befd55350dcb2cda9569d`, recuperato al primo tentativo con GET/HEAD/LIST completo e MIME corretto. Zero PUT di recupero. Contatore della risposta HTTP volume da0 a **8398214 byte** durante la prima rilettura (byte di traffico TCP, inclusi header, non una misura prestazionale). È superiore al payload e dimostra traffico dal volume ripristinato oltre alla parità del corpo S3.
- Sette file .dat, complessivamente **8389064 byte** a volume fermo; tutti i prefissi/hash originali conservati dopo la rilettura. I file dati non sono esportati nello ZIP.
- 10 collegamenti ammessi e37 dinieghi con contatori per percorso; other_denied zero nei cinque ruoli, sia normale sia crash. Undici ID container distinti complessivi: dieci arresti puliti più una morte SIGKILL intenzionale. Entrambi i bridge rimossi.
- ZIP originale [storage-volume-crash33-41814532710.zip](../evidence/artifacts/storage-volume-crash33-41814532710.zip), **102167 byte**, SHA256 `e2b199194551a53ecae60a308d3b042c6cdb2e1c647792657b95378d1cdd29c1`; verificati **101 membri /100 checksum /19 sorgenti esatte**. [Receipt di rilettura](../evidence/storage-volume-crash33-readback-20261104.json).
- La rilettura locale verifica originali, source hash, stato SIGKILL, gate/namespace/regole, hash dei prefissi .dat e report nativi di rete/TLS/S3. Nessuna seconda esecuzione nativa locale o verifica crittografica locale della firma publisher dichiarata; publisher della coorte verificato hosted con source commit esatto. Nessuna chiave privata TLS nell'archivio.

## Prossimo singolo passo

Arresto forzato del filer nel laboratorio isolato, con recupero dei metadati e rilettura dell'oggetto già confermato, senza reseed e con regole di rete applicate prima del servizio. Non eseguito in questo checkpoint.

## Limiti

Crash di processo su filesystem dello stesso host, non power loss, reboot host, perdita del disco, fault in-flight o ripristino da backup. Il page cache dell'host resta disponibile: nessuna garanzia di durabilità su alimentazione persa, RPO/RTO produttivi o accettazione target. Topologia singola per ruolo e credenziali sintetiche pubbliche; limiti di isolamento IPv4 e autorizzazione delle API interne invariati. Nessuna operazione VPS, migrazione, merge/deploy, reset/replay/grant. MiniPET invariato18,3/46, circa40% ±10;0/8 gate,0/21 AT,0/120 oggetti reali.
