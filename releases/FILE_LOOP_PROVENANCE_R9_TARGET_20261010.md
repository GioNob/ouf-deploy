# Pacchetti verificati sul target e diagnosi R9 — 10 ottobre 2026

Ricevute operatore ricevute alle 19:49 Europe/Rome. [JSON originale strutturato](../evidence/file-loop-provenance-trust-r9-target-20261010.json). Launcher 8226af642d7f020bff4a345a0fa605c301d82443, exit0; directory /home/oufadmin/ouf-file-loop-provenance-read.2bXiyaeB.

## Esiti acquisiti

Le firme publisher dei tre ZIP già staged sono verificate sul VPS. Sorgenti e immagini corrispondono ai candidati Semantic 622614b0/e826bd97, Ingestion 8b908554/98af9d77, UDP bc336208/7a979792; migrazioni 10/14/34. Non sono firme di installazione, import o autorizzazione al cutover.

Sei file protetti confermano baseline pubblica, CA, manifest e truststore preparato. Baseline 98d34a90…, CA b1bda8d7…, PKCS12 dcfb221c… sono integri. Restano i 118 certificati iniziali e 119 nel merge pubblico già verificato. I bytes possono essere conservati per la nuova immagine Semantic, senza rigenerazione e senza trasferire la precedente autorità d'installazione. Nessun mount realizzato.

R9 termina alle 11:30:02 CEST con NFT_SET_TTL_UNPROVEN, dopo 795 rinnovi; stessa InvocationID ba95ba7239664789ac68430107ac6dc8. È failed, PID0, Restart=no. Il journal è QUIESCED, leaseAuthorized=false, startAuthorized=false, entrambi i set vuoti, struttura native e membership coerenti. Il claim consumato non è replayabile. Non è una nuova diagnosi DNS: il record restituito identifica il rifiuto della scadenza nft. Non conserva il valore rifiutato, quindi non distingue TTL zero, tipo inatteso o duplicato, tutti respinti dalla vecchia stessa guardia. Nessuna causa più specifica è promossa a fatto.

## Miglioramento di componente in qualifica

Il supervisore storico usa il poll configurato (15 secondi) rispetto al ceiling di lease (30), non la durata effettiva DNS/kernel. Il compilatore riduce correttamente la durata per DNS, tempo trascorso e budget apply: una durata reale inferiore al poll può portare a scadenza prima del ciclo successivo. È una debolezza riproducibile del progetto, compatibile con il guasto, non la prova della sua singola causa storica.

Il nuovo supervisore candidato in tools/semantic_lease_recovery/adaptive_supervisor.py calcola un limite conservativo dalle durate dei due set dopo ownership/membership/journal, sottrae tutta la finestra di lettura e attende al massimo metà del tempo residuo e il poll configurato. Ogni ciclo richiede nuove risposte DNS attraverso il coordinatore esistente. TTL zero, negativo, non numerico, infinito, bool e maggiore del ceiling restano rifiutati. Se il risveglio arriva oltre il limite, revoca invece di tentare un rinnovo tardivo. Arresto ed errori sigillano QUIESCED; non crea consenso o nuova autorità.

Sette test deterministici PASS localmente; la prova native CI è pendente al commit iniziale di questo report: DNS TTL8 contro poll15, sei cicli, nft inet/bridge reali, flock/journal protetti, revoca e divieto di riarmo. L'aggiornamento è soltanto sorgente candidato: non modifica il VPS, non sostituisce la chiusura hash dell'owner installato e non riattiva R9. Un futuro owner deve essere installato con nuova chiusura e transizione governata.

## Gate applicativi ancora aperti

Complete replacement OCI e peer reciproco, nuova transizione HUMAN/transport firmato, readiness e recovery migration-aware restano richiesti dal read corrente. Le firme publisher e il trust non sono una nuova autorità. Cinema già riuscito e Search8/8 sono preservati; Teatri non va riacquisito. Il giro file precede pull API v2.3. F1/F10/F11 restano non accettati; nessuno dei gap PET cambia stato per questo solo incremento.
