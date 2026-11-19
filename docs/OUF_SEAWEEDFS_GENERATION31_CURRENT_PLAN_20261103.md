# Vista tecnica corrente: generazione 31

La candidata tecnica corrente è la generazione 31, dopo verifica delle prove hosted indipendenti di immagine, coorte e runtime. È **non ammessa**: MinIO resta attivo; nessuna autorità runtime o operazione target è emessa.

| Prova | Risultato e identità |
| --- | --- |
| Immagine A | Run 41712811559, commit 5d0d456bec5073192b8a1a86e35bb0dcbd97a6b5, tutti quattro job SUCCESS |
| Coorte B e runtime | Run 41715991128, commit 9ead15c56717c2e301eeb1a2bc1af38b007bfdb8, tutti tre job SUCCESS |
| Binario | `5b7e3dcf61d6b3b7b2b44135dd0db980e43e3d96e5e7e87210c543f790448b02` |
| OCI | `sha256:5af4cbe11899c7d4ef131e37d0c61912b2e9930d66ec21ae69cf38cbc32d9484` |
| Sorgente | 31 patch; 234 moduli nel binario e 1740 pacchetti compilati |
| Coorte | 234 record moduli, 324 testi, 7 archivi di moduli MPL e archivio modificato locale raftstore con 6 file |
| Runtime sintetico | 5 oggetti, 8.388.702 byte; backup 110 file/8.417.282 byte; MIME GET/HEAD PASS; 23 casi S3, 2 negativi TLS, 2 probe egress |

Il checker lega i receipt tramite SHA-256, i byte di immagine/build, la ZIP di coorte e la copia integrale nel runtime, il lock, i 15 input runtime, i 62 membri raw e i checksum, il nuovo archivio MPL e i job hosted. Una mutazione, una prova mancante o una sostituzione con il binario storico fallisce. Il piano29 precedente è ricostruito integralmente e confrontato al suo digest canonico: storico15, SDK27, profilo28, qualificazione29 e progresso restano immutati. I precedenti 48 test rimangono attivi; 12 test aggiunti coprono questi confini e i dinieghi.

La generazione31 ha rimosso dal binario sei dei dieci moduli archiviati censiti nella 29: Bolt, mapstructure, rcrowley, google/btree e facebookgo clock/stats. Anche i vecchi import Armon e Shopify sono assenti. Restano colorstring, OpenCensus, YAMLv3 e PGV. MongoV1 è deprecato, ma ha ricevuto la release di sicurezza 1.17.10 nel settembre 2026: il pin compilato 1.17.9 è precedente; non viene dichiarato assolutamente non mantenuto. Il detector GCP resta dichiarato non mantenuto; le origini non risolte non sono dichiarate mantenute. Il grafo transitivo completo non è dichiarato bonificato. Il lavoro source32 rimane separato e non acquisisce questa qualificazione.

La prova storica MIME15 fallita resta conservata: il PASS sintetico31 non ripara metadati perduti né chiude G2. Il diniego storico `ADVISORY_CHANGED_REASSESSMENT_REQUIRED` del run 41709442513 resta una prova valida del fail-closed dell'eccezione HUMAN sul vecchio binario bb9f; non viene reinterpretato come ammissione della 31. Le prove proprie della 31 comprendono la nuova scansione e i nuovi inventari.

Licenze/redistribuzione, custodia durevole, binding target delle funzionalità Kafka/OpenBao e manutenzione complessiva restano OPEN. Questo runtime non qualifica PostgreSQL coordinato, rotazione dei certificati, RPO/RTO o migrazione reale. Il fix del laboratorio PostgreSQL e i suoi esiti hanno una catena separata.

Il progresso rimane **38% ±10**: 17,5/46 unità, 0/8 gate, 0/21 test di accettazione, 0/120 oggetti reali. Restano immutati scope già consumati e risultati Teatri/Farmacie. Nessuna nuova azione HUMAN/THS è richiesta da questa promozione tecnica nei repository; le autorità target restano quelle dei PET.
