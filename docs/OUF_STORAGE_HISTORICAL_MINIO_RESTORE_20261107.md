# Ripristino isolato della copia storica MinIO

Decisione proposta `GIOVANNI-NONPROD-ISOLATED-MINIO-RESTORE-20261107-01`. La [prova PostgreSQL](../evidence/storage-historical-postgres-restored-operator-20261107.json) è riuscita con 7 database aperti e 7 letture campione. La prova MinIO è il prossimo passo distinto.

## Operazione

- Ricostruire il manifest Windows dai tar già presenti sul VPS e conservare gli hash verificati per il confronto successivo. Selezionare l'immagine MinIO registrata e il volume indicato dal comando server conservato. Estrarre la sola sorgente MinIO in `/var/lib/ouf-storage-migration/historical-minio-restore-20261107-v1`.
- Avviare un solo container temporaneo con l'immagine locale esatta, credenziali effimere, rete `none` e nessuna porta pubblicata. Il volume scrivibile è la copia estratta. L'accesso S3 avviene solo sul loopback del namespace del container.
- Enumerare i bucket e le versioni senza accettare una lista troncata. Leggere i corpi tramite GET, verificare le dimensioni e calcolare SHA-256. Conservare l'inventario privato per la parità SeaweedFS. Il JSON riporta conteggi e l'eventuale corrispondenza al riferimento storico di 120 corpi.
- Limiti: 600 secondi per la prova, un avvio, 320 GET locali, 256 versioni o marker, 64 MiB per corpo, 512 MiB complessivi. Chiusura e rimozione riguardano soltanto il container temporaneo. I dati e i log della prova restano nello scope privato.
- Esito atteso `ISOLATED_HISTORICAL_MINIO_RESTORED`. È una prova storica di lettura dei corpi. Copertura eventi, migrazione e parità SeaweedFS restano passi distinti. MiniPET **39,78%**.

## Programmi da approvare

[Driver MinIO](../scripts/restore-retained-minio.py), 13.529 byte e SHA-256 `2b8636d90e9950237f92d6c3d29a8cf3e51ca3e1a6638d1afff219c7b9f9d4b3`.

Il driver riusa la verifica manifest di [PostgreSQL](../scripts/restore-retained-postgres.py) al commit `5ae47689adeaf39f241527c9364a2c0c9e9b0b9b`, 19.046 byte e SHA-256 `3ff2281f380dcab555d22966f78622a4f4bd00798e5e623e5db8fb95dee2513d`. Il comando VPS carica entrambe le versioni fissate, con Python isolato e `--decision-reference GIOVANNI-NONPROD-ISOLATED-MINIO-RESTORE-20261107-01`.

Verificate localmente la sintassi e la lettura GET di un membro versionato. La prima prova effettiva con il materiale storico sarà sul VPS.
