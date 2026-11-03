# SeaweedFS 4.52 — test S3 basic su AWS SDK Go v2

Data: 3 novembre 2026  
Ambito: sorgente pubblico e laboratorio locale, nessuna operazione target

## Risultato

La patch `patches/seaweedfs/4.52-basic-tests-sdk-v2.patch` migra i tre file del package `test/s3/basic` da AWS SDK Go v1 ai componenti mantenuti SDK v2:

- `test/s3/basic/basic_test.go`;
- `test/s3/basic/delimiter_test.go`;
- `test/s3/basic/object_tagging_test.go`.

Il client conserva endpoint locale HTTP `localhost:8333`, regione `us-west-2`, credenziali dalla catena configurata e indirizzamento path-style. Le chiamate ricevono ora un `context.Context`; ACL e tagging usano i tipi SDK v2. La classificazione degli errori di creazione bucket usa i tipi errore v2 senza ricreare codici locali.

## Prove locali

- sorgente upstream esatto: `984eac6a790be89e2a11de175a7413e1e3e32dd3`;
- applicazione ordinata delle quindici patch già qualificate e della nuova patch: PASS;
- `git diff --check`: PASS;
- test non-network `TestClientUsesLocalPathStyle`: PASS;
- grafo `go list -mod=readonly -deps -test ./test/s3/basic`: zero pacchetti AWS SDK Go v1;
- importatori diretti SDK v1 nel sorgente candidato esteso: 28 → 25;
- SHA256 patch: `ee5fd114aff8f2cb527740171b07ba460fba83c1b33a96ccac807b869aa79a40`.

Il workflow `.github/workflows/storage-basic-tests-sdk-v2.yml`, con azioni pin-nate a commit, ripete la prova sul runner GitHub e trattiene un manifest attestato con dipendenze, importatori residui, hash e log.

## Confini

Questo lotto estende la pulizia dei test e non modifica il server standard già qualificato con quindici patch. Non sostituisce la coorte OCI esatta, non ammette una release e non chiude SW-G1. Review licenze e custodia durevole dell'immagine restano OPEN.

Restano 25 importatori diretti: 13 nel package `test/s3/iam` e 12 negli altri test/strumenti non qualificati. MinIO resta in esercizio. Stato di acceptance invariato: 0/8 gate, 0/21 AT e 0/120 oggetti reali. Scope17/52 Engine GET, Teatri/M1 e Farmacie sono preservati; autorità runtime e operazioni target sono zero.
