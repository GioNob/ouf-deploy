# SeaweedFS 4.52 — test volume/gRPC S3 su AWS SDK Go v2

Data: 3 novembre 2026  
Ambito: sorgente pubblico e laboratorio locale, nessuna operazione target

## Risultato

La patch `patches/seaweedfs/4.52-volume-grpc-s3-test-sdk-v2.patch` migra `test/volume_server/grpc/fetch_remote_s3_test.go` da AWS SDK Go v1 ai componenti mantenuti SDK v2. Restano invariati endpoint locale, credenziali fixture, regione `us-east-1` e path-style.

Le chiamate CreateBucket e PutObject ricevono ora un `context.Context`; gli errori prima ignorati vengono verificati. Il retry implicito dell'SDK è limitato a un tentativo, così il test non acquisisce mutazioni ripetute invisibili.

## Prove locali

- sorgente upstream esatto: `984eac6a790be89e2a11de175a7413e1e3e32dd3`;
- applicazione ordinata delle diciassette patch precedenti e della nuova patch: PASS;
- `git diff --check`: PASS;
- test non-network `TestNewS3ClientUsesBoundedLocalConfiguration`: PASS;
- grafo `go list -mod=readonly -deps -test ./test/volume_server/grpc`: 580 pacchetti, zero AWS SDK Go v1;
- importatori diretti SDK v1 nel sorgente candidato esteso: 24 → 23;
- SHA256 patch: `743687801734174592e8ac5e48c0b8d8be64ea33d187d51cff8069d0f0e5fac7`.

Il workflow `.github/workflows/storage-volume-grpc-s3-test-sdk-v2.yml`, con azioni pin-nate a commit, ripete la sequenza a 18 patch, vincola i 23 importatori residui e trattiene un manifest attestato con dipendenze, hash e log.

## Esito hosted

La [CI 41643462164](https://github.com/GioNob/ouf-deploy/actions/runs/41643462164) è PASS sul commit `54c31f323440aacc4d199ee895730f0b0c14f17c`. Tutti gli otto step principali sono riusciti, inclusi applicazione delle diciotto patch, controllo del perimetro residuo, test non-network, attestazione e retention.

L'artifact `13233557928` contiene sette file e scade il 1 febbraio 2027. Lo ZIP di 6.280 byte ha SHA256 `9b238c2c81d6e9c9c07801e1416dc644b885b593886e6f7ae6c7d48ee4fd0534`; tutti i sei membri elencati in `SHA256SUMS` sono stati riletti e verificati. Il readback conferma 580 pacchetti nel grafo del test, zero pacchetti SDK v1 e l'elenco esatto dei 23 importatori diretti residui.

## Confini

Questo lotto modifica un test d'integrazione, non il server standard già qualificato con quindici patch. Non sostituisce la coorte OCI esatta, non ammette una release e non chiude SW-G1. Review licenze e custodia durevole dell'immagine restano OPEN.

Restano 23 importatori diretti: 13 nel package `test/s3/iam` e 10 negli altri test non qualificati. MinIO resta in esercizio. Stato di acceptance invariato: 0/8 gate, 0/21 AT e 0/120 oggetti reali. Scope17/52 Engine GET, Teatri/M1 8/8 tecnici e 6/6 funzionali, e Farmacie 61 righe/10 OPEN/STRING sono preservati; autorità runtime e operazioni target sono zero.
