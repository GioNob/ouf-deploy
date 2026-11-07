# Allineamento dei file correnti di Onboarding

Il [confronto sul VPS](../evidence/storage-client-comparison-success-operator-20261107.json) è riuscito: curl e MinIO Java 8.6.0 dell'immagine Onboarding installata hanno scritto e riletto su SeaweedFS con TLS e hash coincidente. Non ha cambiato il backend dell'applicazione e non spiega retroattivamente il vecchio 502 su un'altra configurazione.

Per il primo percorso applicativo si mantiene l'immagine `7b9d3e91…`, corrispondente al sorgente conservato 73498c17. Non si installa d515 né si eseguono nuove migrazioni DB per il solo cambio storage.

## Passo corrente

[Script](../scripts/sync-current-onboarding-objects-20261107.py), SHA-256 `679895bff166d8f7aa256113398ef88f40f90811cd4a72c711199832ef63e5ed`.

Legge gli oggetti correnti del solo bucket `ouf-managed-files` su MinIO usando le credenziali già configurate per Onboarding. Sulla destinazione usa la stessa identità SeaweedFS già provata; verifica TLS con la CA esistente. Il trasferimento avviene dal VPS tramite gli IP privati letti da Docker, mantenendo hostname HTTP e SNI corretti.

- Confronta corpo SHA-256, dimensione e metadati applicativi degli oggetti già presenti; non li riscrive.
- Copia soltanto le chiavi mancanti, con `If-None-Match: *`, poi rilegge corpo e metadati.
- Non cancella oggetti, non amplia permessi, non modifica database, reti o binding e non ferma servizi.
- Conserva manifest e intenti in una directory privata nuova; il JSON pubblico riporta conteggi ed esiti.
- Rilegge l'elenco MinIO e verifica che runtime e snapshot della sorgente non siano cambiati durante la copia.

La copia storica di 120 oggetti comprendeva due bucket e precede gli upload recenti. Questo passo lavora sul numero reale del bucket Onboarding attuale; non presume che sia ancora quello storico.

## Limiti espliciti

Non è ancora il cambio dell'endpoint. Onboarding continua a usare MinIO. Prima del cambio occorre una breve pausa del writer Onboarding, controllo dello snapshot e copia dell'eventuale delta successivo; non è necessario rifare restore o copia storica.

Gli oggetti storici già identici restano intatti. La nuova identità applicativa target non amministra tag: il comando non dichiara una nuova verifica dei tag target e rifiuta un oggetto mancante con tag sorgente non vuoti. Non li elimina silenziosamente né modifica i grant.

I limiti tecnici sono 512 oggetti, 64 MiB complessivi, 10 MiB per oggetto e 600 secondi. Se un limite, una differenza o un errore impedisce il completamento, preservare il risultato; non eseguire il cambio dell'endpoint. Nessun retry automatico dei PUT.

## Dopo l'esito

Con lo snapshot allineato si prepara il cambio del solo Onboarding: stesso JAR/configurazione applicativa, rete privata aggiunta, endpoint e credenziali SeaweedFS, CA aggiunta ai certificati pubblici già presenti nella JVM. Nomi/alias/IP necessari al Gateway devono essere preservati. Lettura governata e profilo continueranno a passare dal Gateway; un nuovo upload deve avere asset, corpo e hash coerenti su SeaweedFS.

Il bucket UDP e il suo client AWS Java sono il passo successivo. Questo successo non chiude F1/F2 finché manca il percorso applicativo reale.

[Validazione locale](../evidence/onboarding-current-copy-prepared-20261107.json) · [Fixture HTTP mirata](../tests/check_onboarding_current_copy.py).
