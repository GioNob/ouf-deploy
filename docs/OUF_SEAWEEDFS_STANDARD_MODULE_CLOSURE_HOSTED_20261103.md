# Profilo standard OUF — qualifica hosted a 28 patch

La [CI 41691297148](https://github.com/GioNob/ouf-deploy/actions/runs/41691297148), sul commit `24e96bb5e875a4c0b5c17aed2653e0bd14bd05be`, è **PASS**: 12 step principali e 16 complessivi, inclusi attestazione e upload. La [ricevuta](../evidence/seaweedfs-ouf-standard-module-closure-hosted-20261103.json) deriva da log reali e bytes scaricati, non soltanto dal badge.

Sono verificati tutti i 28 hash delle patch, 27 checksum del manifest e i 28 membri dell’artifact `13255914712`: 548.373 byte, ZIP SHA256 `69687a7b68254476a0c075690672b7f1c219267906eef6cd3dc44c04557e8cc1`, scadenza 2027-02-01. Il manifest SHA256 `083a20a47872e5808f2e1cf3f18de620d713eacc42e33d36b9b4889a5a8946dd` è collegato all’[attestazione prodotta dal job](https://github.com/GioNob/ouf-deploy/attestations/63238309); questa ricevuta verifica i bytes, non dichiara una verifica crittografica indipendente della firma.

La suite standard conferma **5.591 PASS / 5 skip**, 20 package PASS: 1.782 test principali e 3.809 sottocasi, più sei package senza test. I test root IAM/policy/normal passano 16 principali + 8 sottocasi; IAM separato 14 + 4. Kafka compila sei package (quattro PASS, due senza test); tidy root e Kafka senza differenze. I tre profili di tag `elastic`, `rclone`, `elastic,rclone` sono negati esplicitamente.

Il modulo root ha 4.624 archi e 818 moduli selezionati elencati, senza SDK v1 né manager deprecato. Il grafo del server resta di 1.811 pacchetti, SHA256 `cb2536b10d73bc04e587c257a75a622c6b3cf855f1d232f26dba246b43b03f4a`; il binario resta esattamente `85fa52c68a783f3cf4d54ae6064e7b46d022982c1bef4460616dd76cdc609033`. L’immagine e il lock qualificati non sono sostituiti.

Le [prove bounded](../evidence/storage-ouf-standard-41691297148/BOUNDED_SHA256SUMS) conservano grafi, conteggi, eventi terminali, fixture, dinieghi e log hosted. Il log completo della suite è nell’artifact originale: la ricevuta ne conserva hash e conteggi verificati. La chiusura riguarda il profilo standard esplicito; non certifica tutta la distribuzione upstream o ogni modulo nested.

MiniPET ancora circa **35% ±10**, **0/8 gate**, **0/21 AT**, **0/120 oggetti reali**; MinIO attivo. Nessuna operazione target o nuova autorità HUMAN/THS. Scope17/52 Engine GET, Teatri/M1 e Farmacie invariati.
