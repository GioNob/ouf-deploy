# SeaweedFS 4.52 — signer S3Tables su AWS SDK Go v2

Data: 3 novembre 2026  
Ambito: sorgente pubblico e laboratorio locale, nessuna operazione target

## Risultato

La patch `patches/seaweedfs/4.52-s3tables-signer-sdk-v2.patch` migra il signer SigV4 di `test/s3tables/catalog/iceberg_catalog_test.go` da AWS SDK Go v1 ai componenti mantenuti SDK v2. Restano invariati credenziali fixture, regione `us-east-1`, servizio `s3tables` e payload firmato.

Il payload hash SHA256 è ora esplicito e il signer usa il contesto della richiesta. Il test deterministico non-network verifica la credential scope `s3tables` e la data SigV4 congelata.

## Prove locali

- sorgente upstream esatto: `984eac6a790be89e2a11de175a7413e1e3e32dd3`;
- applicazione ordinata delle diciotto patch precedenti e della nuova patch: PASS;
- `git diff --check`: PASS;
- test non-network `TestSignS3TablesRequestUsesS3TablesScope`: PASS;
- grafo `go list -mod=readonly -deps -test ./test/s3tables/catalog`: 639 pacchetti, zero AWS SDK Go v1;
- importatori diretti SDK v1 nel sorgente candidato esteso: 23 → 22;
- SHA256 patch: `aeeb5ceeb6cbeb2f176f3d4ae40561a7b7e70ddbd702598e7d097114cbfbd398`.

Il workflow `.github/workflows/storage-s3tables-signer-sdk-v2.yml`, con azioni pin-nate a commit, ripete la sequenza a 19 patch, vincola i 22 importatori residui e trattiene un manifest attestato con dipendenze, hash e log.

## Esito hosted

La [CI 41649313494](https://github.com/GioNob/ouf-deploy/actions/runs/41649313494) è PASS sul commit `8fa05cb181c8816c8b6ae429822e9ea5b7170e96`. Tutti gli otto step principali sono riusciti, inclusi applicazione delle diciannove patch, controllo del perimetro residuo, test non-network, attestazione e retention.

L'artifact `13235454773` contiene sette file e scade il 1 febbraio 2027. Lo ZIP di 6.627 byte ha SHA256 `7c0587f35a79f306912250b0e71dc5e5364f8232d021e0ea6cf52d5c935fb440`; tutti i sei membri elencati in `SHA256SUMS` sono stati riletti e verificati. Il readback conferma 639 pacchetti nel grafo del test, zero pacchetti SDK v1 e l'elenco esatto dei 22 importatori diretti residui.

## Confini

Questo lotto modifica un test d'integrazione, non il server standard già qualificato con quindici patch. Non sostituisce la coorte OCI esatta, non ammette una release e non chiude SW-G1. Review licenze e custodia durevole dell'immagine restano OPEN.

Restano 22 importatori diretti: 13 nel package `test/s3/iam` e 9 negli altri test non qualificati. MinIO resta in esercizio. Stato di acceptance invariato: 0/8 gate, 0/21 AT e 0/120 oggetti reali. Scope17/52 Engine GET, Teatri/M1 8/8 tecnici e 6/6 funzionali, e Farmacie 61 righe/10 OPEN/STRING sono preservati; autorità runtime e operazioni target sono zero.
