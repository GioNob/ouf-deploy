# SeaweedFS 4.52 — test SSE su AWS SDK Go v2

Data: 3 novembre 2026  
Ambito: sorgente pubblico e laboratorio locale, nessuna operazione target

## Risultato

La patch `patches/seaweedfs/4.52-sse-tests-sdk-v2.patch` migra `test/s3/sse/s3_volume_encryption_test.go` da AWS SDK Go v1 ai componenti mantenuti SDK v2. Restano invariati endpoint HTTP locale, credenziali fixture, regione `us-east-1`, path-style e casi funzionali di upload, range, multichunk e copia.

Le chiamate SDK ricevono ora il contesto del test. Il retry implicito dell'SDK è limitato a un tentativo; il cleanup usa un contesto distinto con timeout di 30 secondi. La suite live richiede ancora un server SeaweedFS avviato con cifratura volume: la prova bounded non pretende di sostituirla.

## Prove locali

- sorgente upstream esatto: `984eac6a790be89e2a11de175a7413e1e3e32dd3`;
- applicazione ordinata delle diciannove patch precedenti e della nuova patch: PASS;
- `git diff --check`: PASS;
- compilazione con build tag `integration` e zero test eseguiti: PASS;
- test non-network `TestGetS3ClientUsesBoundedLocalConfiguration`: PASS;
- grafo `go list -mod=readonly -tags integration -deps -test ./test/s3/sse`: 331 pacchetti, zero AWS SDK Go v1;
- importatori diretti SDK v1 nel sorgente candidato esteso: 22 → 21;
- SHA256 patch: `53ea30a77b924f78832bd424ae9bde65315c587a845c5c98884bbfefd4bc259c`.

Il workflow `.github/workflows/storage-sse-tests-sdk-v2.yml`, con azioni pin-nate a commit, ripete la sequenza a 20 patch, vincola i 21 importatori residui e trattiene un manifest attestato con dipendenze, hash e log.

## Esito hosted

La [CI 41656007239](https://github.com/GioNob/ouf-deploy/actions/runs/41656007239) è PASS sul commit `e98c774733e78b6c7a2d687aff510a464cc802f1`. Tutti gli otto step principali sono riusciti, inclusi applicazione delle venti patch, controllo del perimetro residuo, compilazione con tag `integration`, test non-network, attestazione e retention.

L'artifact `13239852878` contiene otto file e scade il 1 febbraio 2027. Lo ZIP di 4.777 byte ha SHA256 `eff1b81794da7702e29f4b9349ef57ccd1707a4cb3d25e6f4f2b9ff5a59eac18`; tutti i sette membri elencati in `SHA256SUMS` sono stati riletti e verificati. Il readback conferma 331 pacchetti nel grafo del test, zero pacchetti SDK v1 e l'elenco esatto dei 21 importatori diretti residui.

## Confini

Questo lotto modifica test d'integrazione, non il server standard già qualificato con quindici patch. Non sostituisce la coorte OCI esatta, non ammette una release e non chiude SW-G1. Review licenze e custodia durevole dell'immagine restano OPEN.

Restano 21 importatori diretti: 13 nel package `test/s3/iam` e 8 negli altri test non qualificati. MinIO resta in esercizio. Stato di acceptance invariato: 0/8 gate, 0/21 AT e 0/120 oggetti reali. Scope17/52 Engine GET, Teatri/M1 8/8 tecnici e 6/6 funzionali, e Farmacie 61 righe/10 OPEN/STRING sono preservati; autorità runtime e operazioni target sono zero.
