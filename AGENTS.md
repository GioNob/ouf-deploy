## Checkpoint storage 2026-11-03 — signer IAM/STS su SDK v2, hosted PASS

- Patch 21 test-only: `patches/seaweedfs/4.52-iam-sts-signer-sdk-v2.patch`, SHA256 `cf755f4046011666806b538b1835abf5188c648066f2c1f4d106598355bcf44b`.
- CI dedicata [41665635452](https://github.com/GioNob/ouf-deploy/actions/runs/41665635452): otto step principali PASS sul commit `92afdcfd104e6aed85fce0a7b4eded524629794f`.
- Artifact `13245451582`: 5.038 byte, digest GitHub `sha256:d375975e0bf9ec503b1ae48ce4cbfe055a51e22928f2eaa1b4977cf7be0c72e4`, scadenza 2027-02-01.
- Modulo `test/s3/iam` compilato con gli esatti pin e `-mod=readonly`; due test signer deterministici PASS.
- HTTP/XML raw, `POST /`, form body, servizio `sts`, regione, timeout e host singolo preservati; nessun client STS tipizzato introdotto.
- Importatori diretti SDK v1 repository-wide 21→20: 12 in `test/s3/iam`, 8 in altri test non qualificati.
- Tornata complessiva 51/51 SUCCESS; un'attestazione M2 non correlata è riuscita al secondo tentativo dopo `socket hang up` OIDC.
- La prova bounded non sostituisce un roundtrip STS live; binario e coorte OCI esatta a 15 patch invariati.
- MiniPET circa 35% ±10; 0/8 gate, 0/21 AT, 0/120 oggetti reali. MinIO attivo.
- Scope17/52 Engine GET, Teatri/M1 8/8 tecniche e 6/6 funzionali, Farmacie 61/10 OPEN/STRING invariati.
- Zero operazioni target, replay/reset/grant, release, merge, deploy o autorità runtime.

## Checkpoint storage 2026-11-03 — test SSE su SDK v2, hosted PASS

- Patch 20 test-only: `patches/seaweedfs/4.52-sse-tests-sdk-v2.patch`, SHA256 `53ea30a77b924f78832bd424ae9bde65315c587a845c5c98884bbfefd4bc259c`.
- CI dedicata [41656007239](https://github.com/GioNob/ouf-deploy/actions/runs/41656007239): otto step principali PASS sul commit `e98c774733e78b6c7a2d687aff510a464cc802f1`.
- Artifact `13239852878`: 4.777 byte, SHA256 `eff1b81794da7702e29f4b9349ef57ccd1707a4cb3d25e6f4f2b9ff5a59eac18`, otto file, scadenza 2027-02-01.
- Package `test/s3/sse`: 331 pacchetti, zero AWS SDK Go v1; compilazione `integration` e test locale/hosted non-network PASS.
- Retry SDK limitato a un tentativo; contesti test espliciti e cleanup indipendente limitato a 30 secondi.
- Importatori diretti SDK v1 repository-wide 22→21: 13 in `test/s3/iam`, 8 in altri test non qualificati.
- Tornata complessiva 51/51 SUCCESS.
- La prova bounded non sostituisce i roundtrip live cifrati; binario e coorte OCI esatta a 15 patch invariati.
- MiniPET circa 35% ±10; 0/8 gate, 0/21 AT, 0/120 oggetti reali. MinIO attivo.
- Scope17/52 Engine GET, Teatri/M1 8/8 tecniche e 6/6 funzionali, Farmacie 61/10 OPEN/STRING invariati.
- Zero operazioni target, replay/reset/grant, release, merge, deploy o autorità runtime.

## Checkpoint storage 2026-11-03 — signer S3Tables su SDK v2, hosted PASS

- Patch 19 test-only: `patches/seaweedfs/4.52-s3tables-signer-sdk-v2.patch`, SHA256 `aeeb5ceeb6cbeb2f176f3d4ae40561a7b7e70ddbd702598e7d097114cbfbd398`.
- CI dedicata [41649313494](https://github.com/GioNob/ouf-deploy/actions/runs/41649313494): otto step principali PASS sul commit `8fa05cb181c8816c8b6ae429822e9ea5b7170e96`.
- Artifact `13235454773`: 6.627 byte, SHA256 `7c0587f35a79f306912250b0e71dc5e5364f8232d021e0ea6cf52d5c935fb440`, sette file, scadenza 2027-02-01.
- Package `test/s3tables/catalog`: 639 pacchetti, zero AWS SDK Go v1; test locale/hosted non-network PASS.
- SigV4 mantiene servizio `s3tables`, regione e credenziali fixture; payload hash e contesto sono espliciti.
- Importatori diretti SDK v1 repository-wide 23→22: 13 in `test/s3/iam`, 9 in altri test non qualificati.
- Tornata complessiva 51/51 SUCCESS.
- Patch solo test: binario e coorte OCI esatta a 15 patch invariati; licence review e durable image custody OPEN.
- MiniPET circa 35% ±10; 0/8 gate, 0/21 AT, 0/120 oggetti reali. MinIO attivo.
- Scope17/52 Engine GET, Teatri/M1 8/8 tecniche e 6/6 funzionali, Farmacie 61/10 OPEN/STRING invariati.
- Zero operazioni target, replay/reset/grant, release, merge, deploy o autorità runtime.

## Checkpoint storage 2026-11-03 — test volume/gRPC su SDK v2, hosted PASS

- Patch 18 test-only: `patches/seaweedfs/4.52-volume-grpc-s3-test-sdk-v2.patch`, SHA256 `743687801734174592e8ac5e48c0b8d8be64ea33d187d51cff8069d0f0e5fac7`.
- CI dedicata [41643462164](https://github.com/GioNob/ouf-deploy/actions/runs/41643462164): otto step principali PASS sul commit `54c31f323440aacc4d199ee895730f0b0c14f17c`.
- Artifact `13233557928`: 6.280 byte, SHA256 `9b238c2c81d6e9c9c07801e1416dc644b885b593886e6f7ae6c7d48ee4fd0534`, sette file, scadenza 2027-02-01.
- Package `test/volume_server/grpc`: 580 pacchetti, zero AWS SDK Go v1; test locale/hosted non-network PASS.
- Retry SDK limitato a un tentativo; errori CreateBucket e PutObject ora verificati.
- Importatori diretti SDK v1 repository-wide 24→23: 13 in `test/s3/iam`, 10 in altri test non qualificati.
- Tornata complessiva 51/51 SUCCESS.
- Patch solo test: binario e coorte OCI esatta a 15 patch invariati; licence review e durable image custody OPEN.
- MiniPET circa 35% ±10; 0/8 gate, 0/21 AT, 0/120 oggetti reali. MinIO attivo.
- Scope17/52 Engine GET, Teatri/M1 8/8 tecniche e 6/6 funzionali, Farmacie 61/10 OPEN/STRING invariati.
- Zero operazioni target, replay/reset/grant, release, merge, deploy o autorità runtime.

## Checkpoint storage 2026-11-03 — strumento multipart su SDK v2, hosted PASS

- Patch 17 test-tool: `patches/seaweedfs/4.52-multipart-tool-sdk-v2.patch`, SHA256 `3477b4233312670e5e6174e9e734d1590b9f38445fe0991f0bf2f63c89ea7cf8`.
- CI dedicata [41638106512](https://github.com/GioNob/ouf-deploy/actions/runs/41638106512): otto step principali PASS sul commit `1dd71a6bd8a23490fb25b1879069985cb500c5fe`.
- Artifact `13230963602`: 4.341 byte, SHA256 `dd6391fffd52a29b5a67d41c249a7812502fc025180cb5caf7f440e10aa23c7a`, sette file, scadenza 2027-02-01.
- Package `test/s3/multipart`: 290 pacchetti, zero AWS SDK Go v1; test locale/hosted non-network PASS.
- Retry SDK limitato a un tentativo; tre tentativi espliciti solo sullo stesso upload ID e part number, che sostituisce la parte.
- Importatori diretti SDK v1 repository-wide 25→24: 13 in `test/s3/iam`, 11 in altri test non qualificati.
- Tornata complessiva 51/51 SUCCESS; un worker M2 è riuscito al secondo tentativo dopo scadenza della finestra sintetica, senza effetti target.
- Patch solo strumento di test: binario e coorte OCI esatta a 15 patch invariati; licence review e durable image custody OPEN.
- MiniPET circa 35% ±10; 0/8 gate, 0/21 AT, 0/120 oggetti reali. MinIO attivo.
- Scope17/52 Engine GET, Teatri/M1 8/8 tecniche e 6/6 funzionali, Farmacie 61/10 OPEN/STRING invariati.
- Zero operazioni target, replay/reset/grant, release, merge, deploy o autorità runtime.
