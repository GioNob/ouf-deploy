# SeaweedFS 4.52 — test S3 normal su SDK v2

Il lotto migra cinque importatori del package `test/s3/normal`, conserva il
client IAM separato in `iam_test.go` e non modifica `go.mod`, `go.sum` o codice
produttivo. La qualifica locale usa il sorgente 4.52 esatto e i 21 patch
precedenti; la coorte OCI qualificata a 15 patch resta invariata.

## Risultati locali

- Compilazione dell'intero package riuscita con i pin esatti e `-mod=readonly`.
- Quattro test deterministici PASS, oltre a tre sottocasi HTTP 200/400/503.
- Riapplicazione del patch e confronto byte-per-byte di tutti gli otto file del package riusciti.
- Importatori diretti repository: 20→15 nello stack isolato; il parent integrerà gli altri lotti indipendenti.
- Grafo test normal: 1.841 pacchetti, dei quali 42 SDK v1 ancora richiesti dal client IAM. Nessuna falsa dichiarazione di grafo privo di v1.

Le regressioni esercitano serializzazione, firma e deserializzazione SDK reali
su trasporto sintetico: PUT path-style, corpo e Content-MD5 anche errato,
SSE-C, errori tipizzati 400/503 e un solo tentativo, complete multipart,
cancellazione e golden della firma raw precedente con percorso escaped.

SDK v2 trasmette direttamente il valore della chiave SSE-C: la fixture ora
codifica esplicitamente in base64 i 32 byte e mantiene il relativo MD5,
preservando il wire che SDK v1 codificava automaticamente. Non rimuove
validatori TLS o di integrità. Gli input dei test checksum negativi arrivano
inalterati al trasporto. Il client S3 ha timeout HTTP 30 secondi, context del
test e un solo tentativo SDK.

## Limiti

La CI dedicata è predisposta ma il risultato hosted è da verificare. Non sono
stati avviati cluster o roundtrip live S3/SSE. Il package conserva il client
IAM v1; il grafo produttivo/binario del candidato non cambia. MinIO resta
attivo; nessuna operazione target, grant, reset, replay, deploy o ammissione.
Gate 0/8 e AT 0/21 non cambiano. Scope17/52, Teatri/M1 e Farmacie preservati.
