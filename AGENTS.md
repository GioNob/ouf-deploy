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
