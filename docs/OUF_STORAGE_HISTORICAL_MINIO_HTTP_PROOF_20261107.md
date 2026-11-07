# Riscontro MinIO S3 con client HTTP Python

Decisione proposta `GIOVANNI-NONPROD-ISOLATED-MINIO-S3-20261107-03`. Il [secondo tentativo](../evidence/storage-historical-minio-s3-curl-held-operator-20261107.json) ha restituito l'errore client curl 43. Con curl 8.5 locale, le opzioni precedenti funzionano su loopback. La causa sul VPS e la fase della richiesta restano sconosciute.

La ripresa usa la copia MinIO già estratta e i claim conservati, verifica che entrambi i container precedenti siano stati rimossi e usa una nuova sottodirectory `s3-proof-v2`. Il driver mantiene la separazione tra sonda HTTP, lista bucket, lista versioni e lettura dei corpi. Il client usa la libreria standard Python con SigV4 per le sole richieste GET al loopback del namespace isolato. Firma validata col [vettore AWS Get Bucket Lifecycle](https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sig-v4-header-based-auth.html) e scambio locale binario verificato. La prossima esecuzione sul VPS prova il driver sul servizio reale.

Perimetro: **un solo avvio isolato, 15 minuti e fino a 320 GET locali complessive**. La copia estratta rimane l'unico volume montato. Gli errori indicano la fase e una causa consentita, senza risposte o credenziali. Risultato positivo atteso `ISOLATED_HISTORICAL_MINIO_RESTORED`, inventario e hash privati. G3 e MiniPET **39,78%** invariati.

[Programma](../scripts/restore-retained-minio.py), 21.823 byte, SHA-256 `c363c38e6a1a9b5768e40ae0c21ba7aef9b74a06a85914b890a6a84afb15bb93`. Stesso supporto PostgreSQL fissato a `5ae47689adeaf39f241527c9364a2c0c9e9b0b9b`. Invocazione Python isolata con `--finish-s3-proof --decision-reference GIOVANNI-NONPROD-ISOLATED-MINIO-S3-20261107-03`.
