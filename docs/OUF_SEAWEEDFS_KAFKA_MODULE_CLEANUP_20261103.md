# SeaweedFS 4.52 — pulizia del modulo di test Kafka

Data: 2026-11-03. Stato: `LOCAL_VERIFIED_HOSTED_PENDING`.

La patch `4.52-kafka-test-module-remove-sdk-v1.patch` modifica soltanto
`test/kafka/go.mod` e `test/kafka/go.sum`, dopo le 21 patch esistenti. Un
`go mod tidy` completo, offline con cache disponibile, ha dimostrato che le
richieste indirette AWS SDK Go v1 e jmespath sono residue. Vengono rimosse
insieme ai checksum non più necessari. Il modulo annidato registra inoltre
le versioni x/net e x/crypto già selezionate dal modulo radice con la patch 15:
non viene introdotto un nuovo aggiornamento del server.

## Prove locali

- Go 1.27.3 linux/amd64, `GOPROXY=off`, pin esatti senza sostituzioni locali.
- Secondo `go mod tidy -diff`: exit 0, diff vuoto.
- `go test -mod=readonly -run '^$' -count=1 ./...`: compilazione riuscita dei
  sei package del modulo, senza eseguire test di rete.
- `go list -mod=readonly -deps -test ./...`: 763 package, zero AWS SDK v1 e
  zero `feature/s3/manager` deprecato.
- Riapplicazione della patch sui due lockfile originali: stessi byte testati.
- `go.mod` e `go.sum` radice invariati byte per byte.

SHA256 patch: `11a1ed01867dcba555389ec82e2f65d6b188dc23a97419ed5bfcfbccb2cc27a7`.
Il workflow `storage-kafka-module-cleanup.yml` ripete queste prove dal sorgente
upstream esatto e attesta il manifest bounded. L'esito hosted resta pendente.

Questa prova non esegue roundtrip Kafka, broker, Docker o carichi. Non include
i quattro moduli ulteriormente annidati `simple-publisher`, `simple-consumer`,
`kafka-client-loadtest` e `kafka-client-loadtest/tools`, esclusi per definizione
da `./...` nel modulo padre. Non viene dichiarata eradicazione nel grafo dei
moduli intero: il modulo Kafka sostituisce SeaweedFS con la radice locale, il
cui go.mod conserva ancora gli archi opzionali descritti sotto.

## Archi opzionali ancora aperti

| Ingresso | Dipendenza dichiarata | Perimetro |
|---|---|---|
| `github.com/olivere/elastic/v7 v7.0.32` | `github.com/aws/aws-sdk-go v1.43.21` | Store e meta-tail con tag `elastic` |
| `github.com/rclone/rclone v1.75.1` | `github.com/aws/aws-sdk-go-v2/feature/s3/manager v1.22.34` | Backend con tag `rclone`, incluso import `backend/all` |

I moduli sono fissati dal go.mod della generazione candidata. Rimuovere i soli
importatori diretti dei test non elimina questi archi dichiarati. Eliminare
le integrazioni o sostituire i client richiede una scelta esplicita del profilo
e nuove prove dei backend; un cambio di versione senza tali prove non è stato
effettuato. Non si dichiara verificata l'esistenza di un drop-in mantenuto.

Il binario standard qualificato non attiva i due tag e resta vincolato alla
coorte OCI esatta a 15 patch. Questa pulizia non modifica quel binario né il
numero degli importatori Go diretti. Restano zero operazioni target, nessun
release/deploy/merge, G1 e accettazioni aperti; MinIO resta attivo e Scope17/52,
Teatri/M1 e Farmacie restano invariati.
