## Checkpoint storage 2026-11-03 — immagine 29 hosted PASS; cold restore della coorte 15 verificato

- La tornata del commit `041992eacd851d277cd049f03b9fe68a393e6df4` è conclusa: **55/55 workflow SUCCESS**. Il run immagine 29 `41696541570` supera i quattro job, inclusi 6.156 PASS/5 skip/21 pacchetti, scansione fresca e verifica indipendente della provenienza su un runner distinto.
- Prove correnti: [receipt immagine 29](evidence/seaweedfs-452-generation29-image-hosted-20261103.json), [receipt cold 15](evidence/seaweedfs-452-cold-recovery-hosted-20261103.json) e [tornata CI](evidence/storage-generation29-image-ci-round-20261103.json).
- La nuova generazione ha binario `a0c74718e584942f58c02214f6b3abe46b71cd47d4995b8da3aa002dcdadeef7` e OCI `sha256:f8679022d5baff88c33285b501317510ac4d1713cc4901f99999a1df937b18bd`. Il piano la registra separatamente dalla coorte 15: binding licenze/coorte e laboratori runtime 29 restano PENDING finché non ne esistono prove effettive. Nessuna vecchia scansione, prova runtime o decisione viene trasferita.
- Cold restore della **sola coorte 15** PASS nel run `41696541366`: cinque oggetti sintetici, 8.388.702 byte; copia fredda di 110 file/8.417.419 byte, radici ripristinate indipendenti, otto container distinti e otto uscite pulite. Ricevuta e 31 file raw sono trattenuti e verificati. I corpi GET e i payload del backup non sono nell’artefatto: il readback controlla i confronti hosted e i manifest, senza dichiarare una seconda verifica locale dei payload.
- Il probe `octet-stream.txt` della coorte 15 conferma **FAIL** per GET e HEAD: `text/plain; charset=utf-8` al posto di `application/octet-stream`. Il successo della copia/ripristino non chiude G2 e non qualifica ancora il MIME della generazione 29. La correzione non ricostruisce MIME già perso nei vecchi oggetti.
- Avanzamento tecnico **circa 38% ±10**: credito SW-WP3 15→35 per il cold drill verificato; pesi originali `[4,6,8,8,8,4,4,4]`, crediti `[50,85,60,35,35,0,0,0]`, **17,5/46 = 38,04%**. È una stima di lavoro tecnico, non acceptance: **0/8 gate, 0/21 AT, 0/120 oggetti reali**. Nessun credito runtime trasferito alla nuova OCI.
- Recovery coordinato PostgreSQL/oggetti, WAL/PITR, fencing dei writer, crash/reboot, rotazione TLS/chiavi e obiettivi rappresentativi RPO/RTO restano OPEN; i 5,844 secondi del piccolo drill non sono RTO. Restano OPEN anche licenze/redistribuzione, custodia durevole e binding target. MinIO resta attivo.
- Scope consumati **17**, Engine GET cumulativi **52**, Teatri/M1 **8/8 tecniche + 6/6 funzionali** e Farmacie **61 righe/10 OPEN/STRING** invariati. Zero operazioni target, replay/reset/grant, merge, deploy o nuova autorità runtime.

## Checkpoint storage 2026-11-03 — profilo 28 hosted PASS; correzione MIME e nuova coorte 29 in qualifica

- Profilo standard OUF a 28 patch hosted PASS: run 41691297148 sul commit `24e96bb5e875a4c0b5c17aed2653e0bd14bd05be`; 5.591 PASS/5 skip/20 pacchetti, rientro root IAM 16+8 e IAM separato 14+4, Kafka compilato e tidy vuoto. Modulo root senza SDK v1/manager deprecato, esclusioni elastic/rclone esplicite. Grafo 1.811 e binario `85fa52c6…` identici alla coorte 15.
- Identità/TLS/egress sull’OCI esatta hosted PASS: run 41691296988, 23 casi S3, due rifiuti TLS e due dinieghi kernel egress; quattro arresti puliti. Prove raw e receipt conservate; non prova rotazione certificati né isolamento laterale dei ruoli.
- Secondo cold recovery 41691296882 FALLITO per `CONTENT_TYPE_MISMATCH` dopo seed/list e controlli corpo/hash riusciti; nessun backup/restore eseguito. Chiave e MIME effettivo del primo mismatch non erano registrati e non vengono inventati.
- Il drill cold separa ora la copia/ripristino con MIME esplicito dal probe octet-stream, che resta un risultato distinto: nessuna incompatibilità viene considerata risolta da un PASS recovery. 15 test locali PASS; nuova esecuzione hosted PENDING.
- Patch 29 `54982d752afc77e680cfa75b5ada1febc6680709bdb46f8d284f2090448849bc`: preserva il MIME deciso dal PUT S3, inclusi i default octet-stream per corpo vuoto/binario senza header; mantiene la normalizzazione nativa del filer. Prova negativa sul codice precedente e regressioni reali PUT→persistenza→GET/HEAD; 6.156 PASS/5 skip/21 pacchetti.
- Nuovo binario 29 `a0c74718e584942f58c02214f6b3abe46b71cd47d4995b8da3aa002dcdadeef7`, stessi 262 moduli e grafo 1.811. È una nuova generazione: immagine, scan, SBOM, provenienza, licenze, coorte e collaudi richiedono nuovi binding. Il lock e le prove 15 restano immutati; nessuna ammissione o trasferimento automatico di qualifiche. MIME già perso in vecchi oggetti non recuperabile automaticamente.
- Riconciliatore DB–oggetti sintetico: 13 test locali PASS, hash ricalcolati dai flussi dei corpi e rifiuto di oggetti mancanti/extra/corrotti, generazioni miste e ACK pendenti. Non esegue SQL, fencing writer o recovery PostgreSQL; non dichiara salute runtime.
- MiniPET circa 35% ±10 (15,9/46 crediti pesati), 0/8 gate, 0/21 AT, 0/120 oggetti reali. Compatibilità MIME della vecchia coorte, licenze/redistribuzione, custodia durevole, recovery coordinato e binding target restano OPEN. MinIO resta attivo.
- 17 scope consumati e 52 Engine GET cumulativi invariati; Teatri/M1 8/8 tecniche e 6/6 funzionali, Farmacie 61 righe/10 OPEN/STRING preservati. Zero operazioni target, replay/reset/grant, merge, deploy o nuova autorità runtime.

## Checkpoint storage 2026-11-03 — 27 patch qualificate, importatori diretti SDK v1 azzerati

- Tutti i sei workflow SDK sul commit `70cd2671b41b0f775889826b2617811451a5e2ba` sono SUCCESS; archivi e manifest scaricati e verificati indipendentemente.
- Sequenza esatta a 27 patch: zero importatori diretti v1 nell’intero sorgente; 30 test principali e 12 sottocasi unici PASS con pin pubblicati esatti.
- Il run root IAM 41687967264 prova anche il grafo produttivo identico di 1.811 pacchetti e il binario `85fa52c68a783f3cf4d54ae6064e7b46d022982c1bef4460616dd76cdc609033`, identico alla coorte OCI a 15 patch.
- [Ricevuta aggregata](evidence/seaweedfs-sdk27-hosted-20261103.json): grafi normal/policy singoli 1.801, congiunto 1.803, IAM 303, Kafka verificato 763; zero SDK v1 nei perimetri qualificati. Dipendenze indirette elastic/rclone e ulteriori moduli Kafka restano fuori dalla dichiarazione di chiusura.
- Cold recovery 41687967286 FALLITO durante il seed, prima di backup/restore. OCI esatto, quattro ruoli e isolamento verificati; causa timeout inferita dai log di avvio, errore figlio non trattenuto nel primo run. Ricevuta negativa conservata.
- Correzione del laboratorio: precondizione read-only del lock ring applicato, budget finiti, nessun retry mutativo e diagnostica figlio anche su timeout. 11 test offline PASS; nuova prova live ancora PENDING.
- Laboratorio identità/TLS/egress pronto sulla stessa OCI esatta: 13 test locali PASS, inclusi handshake TLS in memoria e rifiuti CA/hostname; 23 casi S3, due rifiuti TLS e due probe egress previsti in CI, ancora PENDING. Non prova isolamento laterale fra ruoli né rotazione certificati.
- Patch 28 del profilo standard OUF pronta: esclude esplicitamente elastic/rclone e nega quei tag in compilazione; grafo moduli root senza SDK v1/manager deprecato, nessun pin mantenuto aggiornato. Suite locale 5.591 PASS/5 skip/20 pacchetti, rientro root/IAM 30+12 e Kafka compilato PASS; binario identico. Qualifica hosted PENDING: il piano mantiene come corrente la sequenza 27 qualificata, senza promuovere il prototipo.
- MiniPET circa 35% ±10 (15,9/46 crediti pesati); 0/8 gate, 0/21 AT, 0/120 oggetti reali. Licenze/redistribuzione, custodia durevole e recovery coordinato OPEN; MinIO resta attivo.
- 17 scope consumati e 52 Engine GET cumulativi invariati; Teatri/M1 8/8 tecniche e 6/6 funzionali, Farmacie 61 righe/10 OPEN/STRING preservati. Zero operazioni target, replay/reset/grant, merge, deploy o nuova autorità runtime.

## Checkpoint storage 2026-11-03 — 27 patch, chiusura importatori sorgente locale

- Sei patch ulteriori migrano i test policy/S3 normal, i client IAM e il modulo IAM separato; ripuliscono il modulo Kafka.
- Sequenza completa riapplicata: importatori diretti AWS SDK Go v1 20→0 nell’intero sorgente.
- Prova combinata con pin esatti: 30 test principali e 12 sottocasi PASS; nessuna sostituzione modfile.
- Grafo server 1.811 pacchetti e binario `85fa52c6…` identici alla coorte OCI qualificata a 15 patch; l’immagine non viene sostituita.
- I grafi dei test normal/policy e dei moduli IAM/Kafka verificati non contengono SDK v1. Gli archi opzionali elastic/rclone e gli ulteriori moduli Kafka restano fuori dalla dichiarazione di chiusura.
- Sei workflow SDK condividono l’esatta sequenza a 27 patch; qualifica hosted ancora PENDING.
- Nuovo drill cold recovery pronto: quattro ruoli isolati, copia fredda e restore indipendente dell’OCI esatto; 6 test offline PASS, esecuzione Docker hosted PENDING.
- Fondazione recovery e dossier licenze già hosted PASS nei run 41684434955 e 41684434829 sul checkpoint `d2e927d`.
- MiniPET circa 35% ±10; 0/8 gate, 0/21 AT, 0/120 oggetti reali; MinIO attivo. Licenze, redistribuzione e custodia durevole OPEN.
- Scope17/52 Engine GET, Teatri/M1 e Farmacie invariati; nessuna operazione target o autorità runtime.

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

