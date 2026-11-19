# Generazione30: build osservata e pipeline immagine pronta

La generazione30 è vincolata alla patch cumulativa `4.52-maintained-dependency-closure.patch` SHA256 `78b2f5462c2d283b0a0d6d79dc5d620bfe9e3ca6dabac559faa55830aa1fb422`, applicata dopo le 29 patch congelate. La riapplicazione indicizzata indipendente produce il tree `13b3de2f130667ed060e94291fcf64b37b7f037a`. Nessun file o risultato della generazione29 viene riscritto.

| Fatto locale osservato | Valore |
| --- | --- |
| Binario Go1.27.3 linux/amd64, CGO0, trimpath, nessun tag | `5b7e3dcf61d6b3b7b2b44135dd0db980e43e3d96e5e7e87210c543f790448b02` |
| Pacchetti compilati | 1740; SHA256 `b5463bc0795b319fa6195640a419bd369fd5c9638ab99b153ba3aae7eb336a08` |
| Righe dep nel build-info | 234; SHA256 `60f0a111f7b228b9855b9d8e1f54d2117ccdbe08f660288f95c7096410e883fa` |
| Suite principale | 6371 PASS, 5 skip; 30 package PASS, 4 package senza test |
| Server mirato | 7 PASS, 1 package |
| Storage/compattazione mirata | 54 PASS, 2 skip ambientali, 1 package |
| Race HTTP shutdown e Raft store, CGO1 solo per test | 25 PASS, 2 package |
| File DB vecchio-v2 ↔ adattatore locale | 3 PASS; pin e lockfile candidati invariati |
| Pipeline Python e motore OCI | 46 unit test PASS, compreso roundtrip con immagini sintetiche esplicite |

La costruzione conserva upstream revision `984eac6a790be89e2a11de175a7413e1e3e32dd3` e `vcs.modified=true`. Il packaging locale dell'eseguibile reale produce OCI manifest `sha256:5af4cbe11899c7d4ef131e37d0c61912b2e9930d66ec21ae69cf38cbc32d9484`, config `sha256:31b99e914181a85a3e0ca3ca6b66621827df298235b215ccf1d0042fd4653771` e archivio Docker SHA256 `2b273d56f5476d910f2656d251922256b7ed2a953ffc7a7022ab1e2495a181e4`. Questi sono fatti di packaging locale, **non** prove di scansione fresca, provenienza hosted, nuova coorte o esecuzione runtime30.

I wrapper generation30 inizializzano una sola volta motori nuovi parametrizzati `generation_image_v1.py` e `generation_readback_v1.py`; il costruttore `runtime_image.py` rimane immutato. Il manifest29 è letto con SHA256 congelato esclusivamente per verificare il prefisso delle patch e rifiutare il riuso dei suoi hash di build. Binario, grafo, inventario moduli e tree30 devono essere nuovi e coincidere con i dati osservati; nessun esito della coorte29 viene trasferito.

La pipeline A ricostruisce da upstream esatto, controlla tidy fixed point e inventari root, esegue i quattro profili di test e il comparatore DB isolato. Non si limita a contare PASS: il manifest fissa gli hash delle identità terminali package/test/esito. I soli due test storage condizionati dall'ambiente sono identificati anche dal package esatto. Se l'enumerazione dei descrittori è supportata, entrambi i subtest readonly/remote devono passare; se i permessi directory sono verificabili da un utente non root, il relativo test deve passare. Gli skip locali restano skip e non diventano PASS nella ricevuta. I risultati e la compatibilità DB sono inclusi nel build-source e ricontrollati dal readback.

Il comparatore DB usa `raft-boltdb/v2@v2.4.2` come oracolo esterno e temporaneo. Non reintroduce quel modulo né Bolt archived nel candidato e verifica l'invarianza dei suoi pin. Non prova arresti improvvisi o migrazioni di formato. Il profilo principale e i casi server mirati evitano test che richiedono DNS/Google esterni; le prove negative storiche di tali dipendenze restano separate.

Le funzioni opzionali escluse dal profilo OUF standard sono rifiutate esplicitamente: Elastic/Rclone, notifiche o replica Kafka e provider KMS OpenBao/Vault. La pipeline verifica che i tag dedicati e una combinazione siano respinti con le diagnostiche previste. Il protocollo Kafka nativo di SeaweedFS non è la libreria di notifiche esclusa. Le esclusioni non vengono descritte come equivalenza funzionale con ogni profilo upstream.

Dopo il build, Trivy0.70.0 eseguirà una scansione nuova, includendo tutte le severità e gli unfixed, senza soppressioni. Scan e SPDX devono corrispondere all'intero inventario effettivo del nuovo binario. HIGH, CRITICAL e UNKNOWN impediscono la qualifica. Un runner separato rileggerà il digest reale del nuovo archivio, riprodurrà l'assessment e verificherà la provenienza del publisher mediante gh pinned. Nessun risultato hosted30 è dichiarato da questa consegna locale.

La manutenzione rimane distinta dalle vulnerabilità note: manifest e assessment richiedono `dependencyMaintenance.status=OPEN` e `allDependenciesMaintained=false`. Le dipendenze archived/EOL residue restano registrate; un'eventuale scansione CVE pulita non le rende mantenute. Licenze, custodia durevole, coorte e laboratori runtime30 rimangono fasi successive con prove proprie.

Nessuna operazione target, ammissione release/runtime o chiusura AT/gate viene emessa dalla pipeline A. Ricevuta locale: `evidence/seaweedfs-generation30-image-local-20261103.json`.
