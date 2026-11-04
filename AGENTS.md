## Checkpoint storage 2026-11-04 — coorte 32 riprodotta localmente, prove hosted richieste

- Immagine 32, run 41724851743: 20 checksum interni e 48 sorgenti ricontrollati, sette file di readback identici al runner indipendente. Firma verificata in CI. Lock di qualifica `91a7c874deb5b11f1a18dc483e99f6031644b62abb769a9e11ff1ad29250fb7d` vincolato al produttore esatto e all'OCI `sha256:5531868a8acc4ac8b1581339e5cae79c7a6211402c936eb74f2bcfcd070831f6`.
- Replay locale della coorte 32: 215 ZIP originali, 373.030.443 byte, 304 testi legali, sette archivi MPL upstream e sei file MPL locali. Receipt deterministica `cf3a01b6426bdb64725b155d252089026a3cf08bc94859da7619ac17a88af19c`. MongoDB v2 ha LICENSE identico a v1 e THIRD-PARTY-NOTICES diverso; i due testi v2 sono conservati e nessuna classificazione viene trasferita.
- Verificati 17 test coorte e 30 test runtime, più lock e preflight sulla ricevuta reale. La nuova CI deve ricostruire la coorte, verificare la firma e ripetere cold restore/MIME, identità S3, TLS ed egress sull'OCI32. La generazione 31 resta la candidata con qualifica tecnica completa finché queste prove non passano. Review licenze, redistribuzione e custodia durevole aperte.
- Riproduzione locale con Go 1.27.3 del footer `go-bip39`: il manifest generato su fixture sintetica viene respinto dal parser precedente e accettato da quello corretto senza aggiungere il modulo all'inventario. La verifica integrale YAML33 del run 41776440912 è separata.
- Osservazione YAML33 completata nel run 41776440912. Due build identiche con binario `c301b4f4…`. L'unico modulo e pacchetto rimosso rispetto a 32 è `gopkg.in/yaml.v3` (215→214 moduli e 1.533→1.532 package); nessuna aggiunta. Confermato il footer inattivo go-bip39. Verificati 13.917 file vendor contro i ZIP originali e 234 checksum dell'archivio CI. 41 test di guardia e 325 eventi Go PASS, inclusa race. L'immagine 33 e la sua provenienza richiedono una nuova qualifica.
- Laboratorio aggiuntivo PostgreSQL 17.11: dump logico con SHA verificato, restore in cluster inizialmente vuoto e indipendente, confronto degli snapshot e riconciliazione dei corpi sintetici. 14 test offline PASS, sette casi storici invariati. Prova nativa nuova PENDING; nessuna attestazione di recovery S3, fencing, PITR, RPO/RTO.
- MiniPET **38% ±10** (17,5/46 crediti), 0/8 gate, 0/21 AT, 0/120 oggetti reali. MinIO attivo. Scope 17 consumati / 52 Engine GET cumulativi, Teatri/M1 8/8 tecniche + 6/6 funzionali e Farmacie 61 righe / 10 OPEN / STRING preservati. Zero effetti target e nessuna autorità runtime.

## Checkpoint storage 2026-11-04 — immagine 32 e laboratorio PostgreSQL PASS, osservazione YAML33 corretta

- Tornata `20bded51` conclusa con 53 SUCCESS su 54. Immagine 32: quattro job PASS nel run 41724851743, inclusa verifica indipendente della provenienza. OCI `sha256:5531868a8acc4ac8b1581339e5cae79c7a6211402c936eb74f2bcfcd070831f6`, binario `33c54c17…`, zero findings nelle cinque severità. Coorte e laboratori sull'OCI32 ancora da qualificare. La generazione 31 resta la candidata con qualifica tecnica completa; nessuna ammissione.
- PostgreSQL 17.11: run 41724851796, 7/7 casi nativi PASS, zero skip, arresto riuscito. ZIP originale e tutti i 91 checksum interni verificati. È una prova di fixture SQL e riconciliazione sintetica; recovery coordinato, fencing, PITR e RPO/RTO restano aperti.
- Prima osservazione YAML33, run 41724851908: `go mod vendor` PASS, il controllo delle intestazioni si ferma prima della build. ZIP originale e 93 checksum interni verificati. Il manifest effettivo non era conservato dal primo run. Nel sorgente upstream è fissato il replace wildcard go-bip39, assente dal grafo osservato. Il parser consente solo il suo esatto footer finale se privo di modulo e pacchetti associati. Sostituzioni effettive, sconosciute o ripetute sono respinte. Il prossimo run conserva `vendor/modules.txt` prima del controllo. 12 test observer locali PASS; riproduzione completa e qualifica YAML ancora pendenti.
- MiniPET **38% ±10** (17,5/46 crediti pesati), 0/8 gate, 0/21 AT, 0/120 oggetti reali. MinIO attivo. Scope 17 consumati / 52 Engine GET cumulativi, Teatri/M1 8/8 tecniche + 6/6 funzionali e Farmacie 61 righe / 10 OPEN / STRING preservati. Zero operazioni target, replay/reset/grant, merge, deploy o nuova autorità runtime.

## Checkpoint storage 2026-11-03 — correzione identità sorgente32 e fixture PostgreSQL; osservazione YAML33

- Tornata `77215bee…` conclusa: 55 workflow, 53 SUCCESS e due FAIL conservati. La candidata corrente qualificata tecnicamente resta la 31, non ammessa; nessun trasferimento della qualifica alla 32 o 33.
- Primo run immagine32 `41719761247`: main 6.656 PASS / 12 skip, server 984 PASS, storage 58 PASS, race 185 PASS e shell 306 PASS; compatibilità DB, IAM e tidy PASS. Fallisce il binding del tree prima di immagine/scan/SPDX/provenienza. Le precedenti asserzioni su binario, grafo e 1.533 package sono passate nel log; nessun binario hosted scaricato indipendentemente.
- Causa riprodotta: indice locale inizializzato vuoto e git add -A avevano omesso 24 file upstream già tracciati ma ignorati. I 4.567 file erano presenti e corretti nel sorgente. Replay canonico da indice upstream conserva tutti i file e produce `80632ef3a54debb04531c1913860d2f94d2b418d`, identico al runner, invece del precedente `d58d388b…`. Patch, bytes sorgente, binario `33c54c17…`, 215 moduli e test richiesti invariati. Manifest originale e ricevuta locale conservati; manifest corretto `5289372f…`. Helper isolato con otto regressioni e controllo canonico prima della build; nuova qualifica completa obbligatoria. Nessun lock operativo32 né ammissione.
- PostgreSQL nativo secondo run `41719760642`: 5 PASS / 2 ERROR / 0 skip. Correzione passfile efficace; i due errori sono il prefisso mancante nell'identificatore sintetico del backup. Il runner ora usa `lab-native-fixture-0001`, con una regressione reale runner→manifest→riconciliazione che prova anche il rifiuto di un corpo corrotto. 51 test foundation locali PASS; foundation hosted precedente 50 PASS nel run `41719760718`. Nuova esecuzione nativa richiesta: nessuna dichiarazione di 7/7, PITR, fencing, RPO/RTO o recovery target.
- YAML33: preparata osservazione hosted di sorgente vendorizzato, inventari completi, origini ZIP/h1, patch minima Iceberg config e due build reali. Parent32 corretto vincolato; nessuna identità di vendor tree/binario anticipata. 11 test observer e review indipendente PASS; contratto preliminare immagine33 19 PASS. I 215 moduli originali sono verificati, ma la generazione33 non è ancora compilata/qualificata. Scanner/SPDX canonici non alterati; provenienza delle modifiche separata e nessun h1 inventato.
- MiniPET **38% ±10**, 17,5/46 crediti invariati; 0/8 gate, 0/21 AT, 0/120 oggetti reali. Nove dei dieci moduli archiviati censiti non sono compilati dalla candidata32, YAML resta OPEN; manutenzione completa, origini irrisolte, licenze/redistribuzione, custodia durevole, recovery coordinato/PITR, rotazione, RPO/RTO e binding target restano OPEN. MinIO attivo.
- Scope 17 consumati / 52 Engine GET cumulativi, Teatri/M1 8/8 tecniche + 6/6 funzionali e Farmacie 61 righe / 10 OPEN / STRING preservati. Zero operazioni target, replay/reset/grant, merge, deploy o nuova autorità runtime.

## Checkpoint storage 2026-11-03 — candidata 31 qualificata; nuova 32 in qualifica

- Generazione 31 candidata corrente tecnica, non ammessa: immagine run 41712811559 e coorte/runtime run 41715991128 tutti SUCCESS. Binario `5b7e3dcf…`, OCI `5af4cbe1…`, 234 moduli / 1.740 package. Scan fresco zero findings nelle cinque severità, provenienza verificata hosted e artefatti ricontrollati. Coorte: 234 ZIP, 324 testi legali, sette archivi MPL upstream e sei file MPL locali modificati; obblighi e custodia durevole OPEN.
- Sull'esatta OCI31: cinque oggetti / 8.388.702 byte ripristinati, 110 file backup / 8.417.282 byte, MIME GET/HEAD prima e dopo PASS; 23 casi S3, due dinieghi TLS e due egress. Dodici container distinti arrestati pulitamente; 62 membri runtime e 15 sorgenti verificati. Non è recovery PostgreSQL/PITR né accettazione target.
- Piano31: 60 test PASS e 369 input vincolati. L'intero piano29 precedente si ricostruisce allo stesso hash canonico; vecchio MIME FAIL, scope, decisioni e progresso preservati. Nessuna prova precedente viene trasferita alla nuova candidata. Il finding MongoDB è preciso: v1 deprecato ma con security fix 1.17.10 successivo; non viene dichiarato totalmente privo di manutenzione.
- Nuova patch cumulativa32 integra progress locale, MongoDB ufficiale v2.9.2 e esclusione esplicita dei quattro adapter Google prima degli effetti. Due build VCS e replay di 4.567 file identici: binario `33c54c17…`, tree `d58d388b…`, 1.533 package / 215 moduli. Un solo modulo nuovo, nessun pin/h1 mantenuto alterato. Rispetto all'inventario29, nove dei dieci moduli archiviati identificati non sono più compilati; YAMLv3 e le origini non risolte restano OPEN. Gli archi legacy opzionali del grafo root non sono dichiarati eliminati. Binding funzioni target e compatibilità MongoDB4.4+ restano da provare.
- Prove locali32: main 6.656 PASS / 12 skip; server 982 PASS / 2 skip; storage 54 PASS / 2 skip; race 185 PASS. Tidy IAM/Kafka vuoti e compilazione PASS, nove combinazioni escluse correttamente respinte. Shell locale 296 PASS / 10 FAIL ambientali AF_UNIX, conservati con confronto baseline; non è una suite completa PASS. La nuova CI obbliga tutte le 306 identità shell, i due casi TLS server e i due casi storage condizionali a PASS. 55 test pipeline/engine PASS e review indipendente; immagine32, scansione/SPDX/provenienza, coorte e runtime32 ancora PENDING.
- PostgreSQL17.11 run 41715990786 FAIL preservato: build server e nove test offline PASS, sette casi nativi con tre FAIL e quattro ERROR a causa dell'avviso libpq su PGPASSFILE=/dev/null. Correzione circoscritta: file vuoto regolare0600 in directory privata0700, cleanup anche su errore; stderr resta rigorosamente respinto. 50 test locali PASS e review indipendente; nuova prova hosted necessaria. Tornata9ead15c5: 52 SUCCESS / 1 FAIL.
- MiniPET **38% ±10**, 17,5/46 crediti invariati; 0/8 gate, 0/21 AT, 0/120 oggetti reali. Restano manutenzione completa, licenze/redistribuzione, custodia durevole, recovery coordinato/PITR, rotazione, RPO/RTO e binding target. MinIO resta attivo.
- Scope 17 consumati / 52 Engine GET cumulativi, Teatri/M1 8/8 tecniche + 6/6 funzionali e Farmacie 61 righe / 10 OPEN / STRING preservati. Zero operazioni target, replay/reset/grant, merge, deploy o nuova autorità runtime.

## Checkpoint storage 2026-11-03 — immagine 31 hosted PASS; coorte e laboratori pronti

- Generazione 31: run 41712811559 sul commit `5d0d456b…`, quattro job SUCCESS. Nuove prove hosted: 6.371 eventi PASS / 5 skip principali, server 7, storage 58, race 25, compatibilità DB 3, root IAM 24 e IAM separato 18; tidy root/Kafka vuoti. Non sono conteggi di test unici. Il FAIL della generazione 30 rimane conservato.
- Immagine OCI `sha256:5af4cbe1…`, binario `5b7e3dcf…`, 1.740 pacchetti e 234 moduli. Scansione fresca: zero findings nelle cinque severità, 236 componenti binario e 238 nodi SPDX coerenti. Provenienza verificata sul runner indipendente; ZIP, 45 sorgenti e 20 checksum interni ricontrollati localmente. Lock reale 31 `19cd03cc…`; la verifica Python locale non viene dichiarata verifica crittografica.
- Coorte 31 pronta con binding effettivo dei nuovi artefatti, 234 ZIP originali, 324 testi legali e sei sorgenti locali MPL modificati. Replay locale completo e 84 test Python PASS. Nuova esecuzione hosted coorte→cold restore→identità/TLS/egress ancora PENDING: nessun trasferimento dei risultati 29 e candidata corrente qualificata tecnicamente ancora 29. Licenze, redistribuzione e custodia durevole restano OPEN.
- Laboratorio PostgreSQL 17.11 pronto: sorgente con hash ufficiale, build nativa in CI, socket privato, ruolo SELECT-only e sette casi reali richiesti senza skip. Nove test offline PASS e review indipendente completata; esecuzione PostgreSQL hosted PENDING. Non qualifica PITR, fencing, recovery coordinato, RPO/RTO o target.
- Correzione test-only M2 verificata nei run 41712824449 e 41712811538: outage/recovery nello stesso processo, secondo worker respinto, revoca senza query e claim precedenti preservati. Nessun runtime owner o budget modificato. Il FAIL del controllo advisory storico 41712812265 resta un diniego corretto dopo drift dell'advisory, senza rinnovo della vecchia decisione HUMAN.
- MiniPET **38% ±10**, 17,5/46 crediti invariati; 0/8 gate, 0/21 AT, 0/120 oggetti reali. Rimozione completa delle dipendenze non mantenute ancora OPEN. MinIO resta attivo.
- Scope 17 consumati / 52 Engine GET cumulativi, Teatri/M1 8/8 tecniche + 6/6 funzionali, Farmacie 61 righe / 10 OPEN / STRING preservati. Zero operazioni target, replay/reset/grant, merge, deploy o nuova autorità runtime.

## Checkpoint storage 2026-11-03 — revisione 31 corregge il modulo Kafka; qualifica nuova richiesta

- La generazione 30 ha superato le regressioni hosted principali (6.371 PASS / 5 skip), server (7), storage (58), race (25), compatibilità DB (3), root IAM (24) e IAM separato (18), ma il run 41709442499 è FAIL: tidy del modulo test Kafka segnala una dichiarazione Btree e due checksum inutilizzati. Archivio completo e receipt negativa sono conservati; nessuna immagine, scansione o provenienza 30 è stata prodotta da quel run.
- Patch 31 aggiunta dopo il prefisso immutato delle 30 precedenti: rimuove solo tre righe da `test/kafka/go.mod` e `go.sum`. Tidy vuoto, compilazione dei quattro package Kafka e ricostruzione locale PASS. Il tree cambia in `c2b7d4bd…`; binario `5b7e3dcf…`, 1.740 pacchetti, 234 moduli e tutti i pin produttivi restano identici. Le prove precedenti non diventano una qualifica 31.
- Nuova pipeline 31 e review indipendente: 50 test Python PASS; vincoli sul prefisso, modifica circoscritta dei lockfile test e identità produttive. Sono richieste nuova esecuzione hosted, scansione/SPDX, provenienza, readback, coorte e laboratori. La candidata corrente qualificata tecnicamente resta la 29.
- Il controllo storico per il binario 4.51 `bb9f…` ha correttamente negato il riuso della decisione dopo la modifica dell'advisory GO-2026-5932. La decisione e il FAIL restano immutati. Le candidate 29/30/31 hanno già il pin crypto corretto e nessuno dei sette package segnalati compilato; questo non rinnova l'eccezione storica. La qualifica delle nuove candidate usa le proprie scansioni fresche.
- Una correzione solo nel laboratorio M2 legge il budget durevole dopo lo stop sincrono del worker, evitando la contesa con il reporter attivo. Il secondo processo deve essere respinto mentre il worker è vivo; tentativi, query e claim restano verificati. 13 test locali PASS, prova nativa della modifica ancora PENDING; nessun runtime owner cambiato.
- MiniPET **38% ±10**, 17,5/46 crediti, invariato: 0/8 gate, 0/21 AT, 0/120 oggetti reali. Restano aperti manutenzione completa, licenze/redistribuzione, custodia durevole, recovery PostgreSQL/PITR, rotazione e RPO/RTO rappresentativi. MinIO resta attivo.
- Scope 17 consumati / 52 Engine GET, Teatri/M1 8/8 tecniche + 6/6 funzionali e Farmacie 61 righe / 10 OPEN / STRING preservati. Zero operazioni target, replay/reset/grant, merge, deploy o autorità runtime nuova.

## Checkpoint storage 2026-11-03 — candidata 30 integrata localmente, nuova qualifica immagine in preparazione

- Sette fronti integrati nella patch cumulativa 30: metriche Hashicorp, LDAP mapstructure/v2, adattatore locale bbolt, esclusioni esplicite Kafka notifiche/replica e OpenBao/Vault, rimozione adapter Btree inutilizzato e timer/Stats HTTPdown locali. I profili esclusi sono rifiutati prima degli effetti; MQ Kafka nativo resta distinto. Il binding delle funzioni necessarie al target rimane OPEN.
- Replay indicizzato e ricostruzione producono il binario identico `5b7e3dcf…`. Pacchetti compilati 1.811→1.740, moduli binario 262→234; nessun modulo aggiunto e nessuna versione/h1 mantenuta alterata. Sei dei dieci moduli archived rimossi dal binario; colorstring, OpenCensus, YAMLv3 e PGV restano, insieme ai rilievi MongoDB v1/GCP e alle origini non risolte. Gli archi opzionali non compilati del grafo root non vengono dichiarati eliminati.
- Suite combinata: 6.432 eventi PASS / 7 skip, più 25 esiti race e tre compatibilità DB separati. Non sono conteggi di test unici. Sei profili/tag esclusi falliscono come previsto. Log raw, prove negative, patch isolate e decisione di non selezionare la migrazione IBM Sarama conservati; la pipeline immagine supera 46 test Python e review indipendente.
- La nuova pipeline 30 richiede build riproducibile, scansione fresca, SPDX, provenienza verificata su runner indipendente e inventario completo di 234 moduli. Nuova coorte/licenze e laboratori runtime30 restano PENDING; il sorgente MPL locale Raft è incluso per la successiva verifica. Nessun risultato della generazione29 viene trasferito.
- La candidata corrente qualificata tecnicamente resta la 29. Tornata del checkpoint `51fd3022…`: 51/51 workflow SUCCESS. MiniPET **38% ±10**, 17,5/46 crediti pesati, senza incremento per prototipi: 0/8 gate, 0/21 AT e 0/120 oggetti reali. Licenze/redistribuzione, custodia durevole, recovery coordinato PostgreSQL/PITR, RPO/RTO e binding target restano OPEN. MinIO resta attivo.
- Scope17 consumati / 52 Engine GET cumulativi, Teatri/M1 8/8 tecniche + 6/6 funzionali e Farmacie 61 righe / 10 OPEN / STRING invariati. Nessuna operazione target, replay/reset/grant, merge, deploy o nuova autorità runtime.

## Checkpoint storage 2026-11-03 — generazione 29 candidata corrente, coorte e laboratori hosted PASS

- Immagine 29 qualificata nel run 41696541570, sorgente `041992ea…`: 6.156 PASS / 5 skip / 21 pacchetti, zero vulnerabilità grezze di ogni severità, inventari scan/SPDX coerenti e provenienza publisher verificata sul runner indipendente. Binario `a0c74718…`, OCI `f8679022…`, lock 29 `ed2a3b04…`.
- Coorte e laboratori del run 41701381292 sul commit `7a712185…` SUCCESS: nuovo binding di 262 moduli / 353 testi, 17 archivi MPL, nove file legali sorgente e 39 toolchain; firma publisher ricontrollata hosted. Review licenze, tre classificazioni UNKNOWN e custodia durevole restano OPEN.
- Sulla stessa OCI 29: cold restore indipendente di cinque oggetti/8.388.702 byte, 110 file backup; GET e HEAD octet-stream PASS prima e dopo restore. Ripetuti 23 casi S3 identità, due rifiuti TLS e due dinieghi egress. Dodici container distinti, massimo quattro concorrenti, laboratori sequenziali. Non qualifica PostgreSQL/PITR, rotazione certificati, RPO/RTO o target.
- `currentQualification` del piano ora descrive esclusivamente la generazione 29 tecnica, non ammessa. `historicalQualification15` conserva senza modifica la vista OCI15/SDK27/profilo28; `historicalGeneration29PhaseA` conserva lo snapshot precedente. Il difetto MIME 15 rimane FAIL storico: la correzione 29 non recupera metadati già persi né chiude G2.
- La chiusura qualificata riguarda AWS SDKv1 e S3 manager deprecato. L’audit dei 262 moduli compilati rileva 10 moduli con repository archiviato, il termine della finestra annunciata di fix MongoDB v1 e il detector GCP dichiarato non più mantenuto. Per 12 moduli manca la risoluzione metadata GitHub: non sono considerati mantenuti per presunzione. I quattro fronti Shopify/rcrowley, Bolt, mapstructure e Armon sono una selezione di rimedi; l’inventario più ampio resta OPEN e i prototipi non sono qualificati.
- MiniPET **circa 38% ±10**, stessi 17,5/46 crediti pesati; nessun ulteriore incremento per questa promozione. 0/8 gate, 0/21 AT, 0/120 oggetti reali; MinIO resta attivo.
- Scope 17 consumati e 52 Engine GET invariati; Teatri/M1 8/8 tecniche e 6/6 funzionali, Farmacie 61 righe / 10 OPEN / STRING preservati. Zero target operations, replay/reset/grant, merge, deploy, ammissioni o nuova autorità runtime.

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

