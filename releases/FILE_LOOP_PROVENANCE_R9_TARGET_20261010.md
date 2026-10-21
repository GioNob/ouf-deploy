# Pacchetti verificati sul target e diagnosi R9 — 10 ottobre 2026

Ricevute operatore ricevute alle 19:49 Europe/Rome. [JSON originale strutturato](../evidence/file-loop-provenance-trust-r9-target-20261010.json). Launcher 8226af642d7f020bff4a345a0fa605c301d82443, exit0; directory /home/oufadmin/ouf-file-loop-provenance-read.2bXiyaeB.

## Esiti acquisiti

Le firme publisher dei tre ZIP già staged sono verificate sul VPS. Sorgenti e immagini corrispondono ai candidati Semantic 622614b0/e826bd97, Ingestion 8b908554/98af9d77, UDP bc336208/7a979792; migrazioni 10/14/34. Non sono firme di installazione, import o autorizzazione al cutover.

Sei file protetti confermano baseline pubblica, CA, manifest e truststore preparato. Baseline 98d34a90…, CA b1bda8d7…, PKCS12 dcfb221c… sono integri. Restano i 118 certificati iniziali e 119 nel merge pubblico già verificato. I bytes possono essere conservati per la nuova immagine Semantic, senza rigenerazione e senza trasferire la precedente autorità d'installazione. Nessun mount realizzato.

R9 termina alle 11:30:02 CEST con NFT_SET_TTL_UNPROVEN, dopo 795 rinnovi; stessa InvocationID ba95ba7239664789ac68430107ac6dc8. È failed, PID0, Restart=no. Il journal è QUIESCED, leaseAuthorized=false, startAuthorized=false, entrambi i set vuoti, struttura native e membership coerenti. Il claim consumato non è replayabile. Non è una nuova diagnosi DNS: il record restituito identifica il rifiuto della scadenza nft. Non conserva il valore rifiutato, quindi non distingue TTL zero, tipo inatteso o duplicato, tutti respinti dalla vecchia stessa guardia. Nessuna causa più specifica è promossa a fatto.

## Miglioramento di componente in qualifica

Il supervisore storico usa il poll configurato (15 secondi) rispetto al ceiling di lease (30), non la durata effettiva DNS/kernel. Il compilatore riduce correttamente la durata per DNS, tempo trascorso e budget apply: una durata reale inferiore al poll può portare a scadenza prima del ciclo successivo. È una debolezza riproducibile del progetto, compatibile con il guasto, non la prova della sua singola causa storica.

Il nuovo supervisore candidato in tools/semantic_lease_recovery/adaptive_supervisor.py calcola un limite conservativo dalle durate dei due set dopo ownership/membership/journal, sottrae tutta la finestra di lettura e attende al massimo metà del tempo residuo e il poll configurato. Ogni ciclo richiede nuove risposte DNS attraverso il coordinatore esistente. TTL zero, negativo, non numerico, infinito, bool e maggiore del ceiling restano rifiutati. Se il risveglio arriva oltre il limite, revoca invece di tentare un rinnovo tardivo. Arresto ed errori sigillano QUIESCED; non crea consenso o nuova autorità.

La qualifica 587455fee0342d8aa603aa587b916fae4f27517a, run38073961963, passa 15 test deterministici e la prova native: DNS TTL8 contro poll15, sei cicli, nft inet/bridge reali, flock/journal protetti, revoca e divieto di riarmo. L'aggiornamento è soltanto sorgente candidato: non modifica il VPS, non sostituisce la chiusura hash dell'owner installato e non riattiva R9. Un futuro owner deve essere installato con nuova chiusura e transizione governata.

## Gate applicativi ancora aperti

Complete replacement OCI e peer reciproco, nuova transizione HUMAN/transport firmato, readiness e recovery migration-aware restano richiesti dal read corrente. Le firme publisher e il trust non sono una nuova autorità. Cinema già riuscito e Search8/8 sono preservati; Teatri non va riacquisito. Il giro file precede pull API v2.3. F1/F10/F11 restano non accettati; nessuno dei gap PET cambia stato per questo solo incremento.


## Difetto di unità riprodotto e consegna operatore

Le prime run38073622638 e38073690078 rifiutano la finestra di scheduling. Il campione native mostra expires4 trattato dal backend storico come0,004 secondi; non si amplia il gate per far passare il test. La nuova variante nft_seconds_backend.py usa interi JSON in secondi, bounded dal ceiling, mantenendo il rifiuto di zero/duplicati/tipo errato. Non inferisce l'unità dalla grandezza. La run38073791056 passa sei cicli con questa correzione; le successive38073929734 e38073961963 qualificano anche un probe separato: timeout30, expires29→28 dopo1,2 secondi, in entrambi i family.

Questa è prova del difetto nel sorgente e nell'ambiente CI. La risposta R9 attuale non conserva il valore rifiutato; la conferma sull'eseguibile nft del VPS è pendente. Il launcher releases/nft-json-units-isolated-probe-20261010.sh fissato a ae8e53d445bb117bf4e422f95af8847457386db9, SHA256 00dbc0374921b2572567f83d565ac5389ae8a8f6ddcd18a29a9101ab5232a8e0, usa soltanto l'eseguibile hash-bound del vecchio owner in un nuovo namespace. Sono due batch nft isolati (creazione e cleanup), zero tabelle/regole host, nessun hook, traffico, DNS, provider, riavvio, chiave o lease grant. Richiede sudo per unshare e leggere il binding root; dura pochi secondi e scarica solo il piccolo sorgente.

La run38074016804 fallisce il solo controllo checksum di consegna per una terminazione newline letterale nella workflow; ae8e53d445bb117bf4e422f95af8847457386db9 corregge la riga CI, senza modificare launcher/source o la qualifica native già riuscita. Non promuovere una run fallita a PASS.

Il codice corretto è candidato e non installato. Nessuna autorità R9 è riutilizzata; il ripristino richiederà nuova chiusura source e transizione esplicita, coordinata con i gate del cutover. Non richiedere ripetizione di trust/firme/staging/Cinema.

Consegna corretta qualificata: [run38074084847](https://github.com/GioNob/ouf-deploy/actions/runs/38074084847), commit ae8e53d445bb117bf4e422f95af8847457386db9, PASS inclusi checksum/sintassi, 15 test, sei cicli native e probe JSON isolato. L'esecuzione target resta pendente.
