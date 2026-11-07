# Prova di ripristino PostgreSQL dalla custodia storica

Decisione proposta `GIOVANNI-NONPROD-ISOLATED-POSTGRES-RESTORE-20261107-01`.

La [ricevuta Windows](../evidence/storage-retained-custody-windows-verified-operator-20261107.json) lega la custodia indipendente al manifest `58484aea53aefeb1fff390578ba6562efabffd914caf64944eee7c9d9a2e0d79`. La prova usa il materiale già conservato sul VPS e ricostruisce quel manifest prima di estrarre il cluster. La chiave di decifratura resta sul PC.

## Perimetro

- Un solo nuovo scope privato `/var/lib/ouf-storage-migration/historical-postgres-restore-20261107-v1`. Tar PostgreSQL, mount PGDATA e immagine vengono scelti dal piano conservato. Verifica di dimensioni, contenuto e riferimenti prima dell'estrazione. Il cluster originale resta escluso dalle mount del test.
- Massimo 900 secondi, 18 invocazioni Docker, cluster estratto entro 1 GiB logico e almeno 2 GiB liberi. Uso della sola immagine PostgreSQL con ID già registrato. Container temporanei con rete `none`, nessuna porta pubblicata e root filesystem in sola lettura. Soltanto il cluster estratto è montato in scrittura.
- Controllare lo stato di chiusura con `pg_controldata`, aprire i database del cluster copiato in modalità single-user e leggere un campione da una tabella applicativa per database. Il JSON espone soltanto i conteggi. I log restano privati sul VPS.
- Esito atteso `ISOLATED_HISTORICAL_POSTGRES_RESTORED`. La prova riguarda il cluster PostgreSQL storico. Restano da provare MinIO, continuità degli eventi e criteri G3. MiniPET **39,78%**, credito aggiunto zero.

## Programma da approvare

[restore-retained-postgres.py](../scripts/restore-retained-postgres.py) · 14.535 byte · SHA-256 `2c57dd92954b9edff61a3463aea5ac00dc95e315e6b1b15e1db26ea87d294d58`.

Avvio come root con Python isolato e argomento `--decision-reference GIOVANNI-NONPROD-ISOLATED-POSTGRES-RESTORE-20261107-01` dopo la decisione. Controllate sintassi e selezione del mount. Il tentativo sul VPS sarà la prima prova effettiva del ripristino.
