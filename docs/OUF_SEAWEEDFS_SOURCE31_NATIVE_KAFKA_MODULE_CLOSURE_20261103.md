# Generazione 31: chiusura del modulo test Kafka nativo

La generazione 30 si è fermata correttamente nel run 41709442499: il controllo `go mod tidy -diff` ha trovato Btree inutilizzato nel modulo separato `test/kafka`. La rimozione del vecchio adapter Btree aveva già eliminato il suo import produttivo; restavano una dichiarazione indiretta e due checksum nel modulo test.

La patch 31 rimuove solo quelle tre righe da due file. Non cambia codice produttivo, test Kafka, versioni/h1 trattenute o lockfile root. Il replay indicizzato produce tree `c2b7d4bd32316af277a76fb21c09894004c24b4b`; build Go 1.27.3 CGO0/trimpath riuscito, binario identico alla 30 `5b7e3dcf…`, stessi 1.740 pacchetti e 234 moduli. Tidy diff ora vuoto e compilazione Kafka `-run ^$` PASS; non è una prova broker live.

Il fallimento 30 rimane conservato integralmente nell'archivio pubblico e nella receipt: 6.371 PASS/5 skip principali, 7 server, 58 storage, 25 race, 3 compatibilità DB, 24 root IAM e 18 IAM separato. I due casi storage saltati localmente sono passati sul runner, inclusi i relativi sottocasi. I quattro profili di identità terminale sono stati ricontrollati indipendentemente. L'immagine 30, scansione e provenienza non sono state prodotte da quel run.

La candidata 31 ha una sequenza nuova che conserva intatte tutte le 30 patch precedenti. Identità del binario non significa riuso automatico delle prove: serve nuova qualifica hosted, scansione/SPDX, provenienza, coorte e laboratori. La 29 resta l'ultima candidata tecnicamente qualificata, non ammessa. MiniPET 38% ±10 invariato; MinIO attivo, 0/8 gate, 0/21 AT, 0/120 oggetti reali. Scope 17/52 Engine GET, Teatri/M1 e Farmacie invariati.
