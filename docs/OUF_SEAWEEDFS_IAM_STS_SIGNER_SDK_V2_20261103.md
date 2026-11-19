# SeaweedFS 4.52 — signer STS IAM su AWS SDK Go v2

Data: 3 novembre 2026  
Ambito: sorgente pubblico e test deterministici locali, nessuna operazione target

## Risultato

La patch `patches/seaweedfs/4.52-iam-sts-signer-sdk-v2.patch` migra soltanto il signer usato da `test/s3/iam/s3_sts_assume_role_test.go` da AWS SDK Go v1 al signer mantenuto SDK v2. Il trasporto STS resta intenzionalmente HTTP/XML raw: `POST /`, form URL-encoded, servizio `sts`, regione `us-east-1`, endpoint e timeout di 30 secondi sono invariati. La request riceve il contesto del test.

L'helper v2 calcola esplicitamente SHA256 sui byte effettivamente inviati. Due test senza rete vincolano firma golden, scope, timestamp, host singolo, conservazione del body e credenziali temporanee. Nessun client STS tipizzato viene introdotto, perché i test verificano anche estensioni SeaweedFS non rappresentate dalla validazione client AWS.

## Prove locali e hosted

- base upstream esatta: `984eac6a790be89e2a11de175a7413e1e3e32dd3`, con le venti patch precedenti applicate;
- `git apply --check` della patch 21: PASS;
- `git diff --check`: PASS;
- test deterministici del nuovo helper: 2 PASS;
- compilazione dell'intero modulo IAM con `-run '^$'`: PASS in una verifica locale con versioni compatibili già in cache per le dipendenze v1 residue;
- importatori diretti SDK v1: 21 → 20, di cui IAM 13 → 12 e altri test invariati a 8;
- SHA256 patch: `cf755f4046011666806b538b1835abf5188c648066f2c1f4d106598355bcf44b`.

La verifica locale completa non disponeva in cache degli esatti pin storici AWS SDK v1 `v1.44.0`, JWT `v5.3.0` e testify `v1.8.4`; ha quindi usato soltanto per il compile check dipendenze API-compatibili già custodite. La [CI 41665635452](https://github.com/GioNob/ouf-deploy/actions/runs/41665635452) ha poi applicato in ordine tutte le 21 patch, compilato l'intero modulo IAM con `-mod=readonly` sugli esatti `go.mod`/`go.sum` e superato i due test deterministici. Tutti gli otto step principali, inclusi manifest, attestazione e upload, sono PASS.

L'artifact `13245451582` è di 5.038 byte, ha digest GitHub `sha256:d375975e0bf9ec503b1ae48ce4cbfe055a51e22928f2eaa1b4977cf7be0c72e4` e scade il 1 febbraio 2027. Il manifest attestato ha SHA256 `46d8cd312d71e2d08bc3fd42433e1ff4f4defb4a459ccbbedaeca56dfb082952`. Il workflow vincola esattamente 20 importatori repository-wide e 12 nel modulo IAM.

## Confini

Questo lotto modifica esclusivamente test IAM e non il server standard già qualificato con quindici patch. Non sostituisce la coorte OCI esatta, non ammette una release e non chiude SW-G1 o alcun AT. Gli altri dodici importatori IAM e gli otto importatori nei test non qualificati restano aperti.

La prova hosted compila e verifica il signer senza rete, ma non costituisce un roundtrip STS live contro SeaweedFS; quel contratto resta da qualificare nel laboratorio IAM successivo.

MinIO resta in esercizio. Stato di acceptance invariato: 0/8 gate, 0/21 AT e 0/120 oggetti reali. Scope17/52 Engine GET, Teatri/M1 8/8 tecnici e 6/6 funzionali, e Farmacie 61 righe/10 OPEN/STRING sono preservati; autorità runtime e operazioni target sono zero.
