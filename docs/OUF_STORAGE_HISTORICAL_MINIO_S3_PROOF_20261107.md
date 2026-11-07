# Completamento della prova S3 sulla copia MinIO

Decisione proposta `GIOVANNI-NONPROD-ISOLATED-MINIO-S3-20261107-02`.

Il [log redatto](../evidence/storage-historical-minio-startup-log-operator-20261107.json) riporta API su 127.0.0.1:9000 e la chiusura del container. La GET S3 firmata del primo tentativo è fallita. Il log non identifica la causa della GET.

La ripresa lega la copia già estratta al manifest conservato e verifica che il container precedente sia stato rimosso. Usa una sottodirectory privata `s3-proof-v1` e un nuovo container isolato con rete `none`. La prova HTTP di disponibilità precede le richieste firmate. Eventuali errori distinguono entrata nel namespace, uscita curl, stato HTTP e categorie S3 consentite. Le credenziali effimere rimangono in file privati. Root access esplicito vale soltanto per il container temporaneo.

Limiti: un solo nuovo avvio sulla stessa copia, **300 secondi**, massimo 320 GET complessive. L'inventario legge i corpi, confronta le dimensioni e conserva gli hash per la parità SeaweedFS. La rimozione finale riguarda il solo container temporaneo.

[Driver](../scripts/restore-retained-minio.py) · 18.758 byte · SHA-256 `176560b12ea0d112f95cc4cfe320de7edc5edd83d0246dc3caacf0f904ef88ec`. Usa lo stesso supporto PostgreSQL fissato a `5ae47689adeaf39f241527c9364a2c0c9e9b0b9b`. Modalità `--finish-s3-proof --decision-reference GIOVANNI-NONPROD-ISOLATED-MINIO-S3-20261107-02`. Sintassi verificata. La prima esecuzione di questo percorso sarà sul VPS. MiniPET **39,78%**.
