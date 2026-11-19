# OUF — fondazione recovery sintetica SeaweedFS 4.52

Data: 2026-11-03. Stato: `SYNTHETIC_FOUNDATION_PREPARED_NOT_QUALIFIED`.

## Perimetro acquisito

Questo lotto introduce soltanto primitive repository, offline e fail-closed:

- profilo a ruoli separati `master`, `filer`, `volume`, `s3`, vincolato alla coorte SeaweedFS 4.52 esatta a 15 patch;
- rete dichiarata loopback/default-deny, filesystem root read-only, UID non root e percorsi persistenti distinti;
- manifest di backup sintetico con fence writer confermato, generazione unica, hash e limiti di byte;
- componenti obbligatorie: configurazione, metadati master/filer, volume e dump PostgreSQL fixture;
- piano di restore in radice indipendente e verifica read-only di dimensioni e SHA256.

Il validatore rifiuta campi ignoti, identità diverse del candidato, egress, endpoint target, autorità runtime, release admission, claim di accettazione, symlink, traversal, artefatti vuoti, set incompleti, generazioni miste, collisioni e hash alterati.

## Cosa non è stato fatto

Il codice non avvia SeaweedFS o PostgreSQL, non ferma writer, non crea backup, non copia o ripristina dati e non contatta endpoint. Il campo fence registra una prova sintetica fornita dal chiamante: non implementa da solo il coordinamento DB–oggetti. Il piano `PLANNED_NOT_EXECUTED` non prova che l'ambiente sia davvero vuoto o che gli originali siano inaccessibili.

Non sono qualificati TLS, rotazione segreti, egress runtime, fault/reboot, perdita host, capacità, latenza, restore coordinato PostgreSQL, RPO o RTO. Non cambia lo stato di G3, dei gate o degli AT.

## Invarianti preservati

- coorte tecnica: `TECHNICAL_COHORT_VERIFIED_NOT_ADMITTED`;
- licenze, redistribuzione e custodia durevole: OPEN;
- MinIO resta attivo;
- 0/8 gate, 0/21 AT, 0/120 oggetti reali copiati;
- zero operazioni target, replay/reset/grant, release, merge, deploy o autorità runtime;
- scope17/52 Engine GET, Teatri/M1 e Farmacie invariati.

## Passo successivo non implicito

Un workflow successivo potrà materializzare il profilo solo in CI isolata, partire dall'OCI esatto e produrre una ricevuta distinta per lifecycle, backup/restore vuoto e fault. Anche un PASS sintetico resterà distinto dall'accettazione su infrastruttura rappresentativa e dalle decisioni HUMAN/THS.
