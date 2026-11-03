# SeaweedFS 4.52 — strumento multipart su AWS SDK Go v2

Data: 3 novembre 2026  
Ambito: sorgente pubblico e laboratorio locale, nessuna operazione target

## Risultato

La patch `patches/seaweedfs/4.52-multipart-tool-sdk-v2.patch` migra lo strumento standalone `test/s3/multipart/aws_upload.go` da AWS SDK Go v1 ai componenti mantenuti SDK v2. Il client conserva endpoint HTTP locale `localhost:8333`, credenziali fixture, regione `us-west-1` e path-style.

Le API multipart ricevono ora un `context.Context` e usano i tipi SDK v2. Il retry implicito dell'SDK è limitato a un tentativo. Il loop esplicito conserva tre tentativi per `UploadPart` sullo stesso upload ID e part number: il tentativo successivo sostituisce la parte, senza creare una seconda mutazione logica. Create, complete, list e abort non acquisiscono retry applicativi nuovi.

## Prove locali

- sorgente upstream esatto: `984eac6a790be89e2a11de175a7413e1e3e32dd3`;
- applicazione ordinata delle sedici patch precedenti e della nuova patch: PASS;
- `git diff --check`: PASS;
- test non-network `TestNewS3ClientUsesBoundedLocalConfiguration`: PASS;
- grafo `go list -mod=readonly -deps -test ./test/s3/multipart`: zero pacchetti AWS SDK Go v1;
- importatori diretti SDK v1 nel sorgente candidato esteso: 25 → 24;
- SHA256 patch: `3477b4233312670e5e6174e9e734d1590b9f38445fe0991f0bf2f63c89ea7cf8`.

Il workflow `.github/workflows/storage-multipart-tool-sdk-v2.yml`, con azioni pin-nate a commit, ripete la sequenza a 17 patch, vincola i 24 importatori residui e trattiene un manifest attestato con dipendenze, hash e log.

## Confini

Questo lotto modifica uno strumento di test, non il server standard già qualificato con quindici patch. Non sostituisce la coorte OCI esatta, non ammette una release e non chiude SW-G1. Review licenze e custodia durevole dell'immagine restano OPEN.

Restano 24 importatori diretti: 13 nel package `test/s3/iam` e 11 negli altri test non qualificati. MinIO resta in esercizio. Stato di acceptance invariato: 0/8 gate, 0/21 AT e 0/120 oggetti reali. Scope17/52 Engine GET, Teatri/M1 e Farmacie sono preservati; autorità runtime e operazioni target sono zero.
