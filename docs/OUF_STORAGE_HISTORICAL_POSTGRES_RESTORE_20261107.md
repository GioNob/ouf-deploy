## Esito PostgreSQL sul VPS

[Prova riuscita](../evidence/storage-historical-postgres-restored-operator-20261107.json): 7 database aperti e 7 con una riga campione, stato cold verificato, 10 container complessivi e rete none. [Prossimo passo: MinIO](OUF_STORAGE_HISTORICAL_MINIO_RESTORE_20261107.md). MiniPET **39,78%**.

## Esito VPS e completamento del riscontro SQL

La [ricevuta](../evidence/storage-historical-postgres-restore-held-operator-20261107.json) riporta `POSTGRES_ROW_READ_NOT_PROVEN`. Il ramo raggiunto segue verifica del manifest, estrazione, `pg_controldata` e apertura del catalogo. Il controllo precedente dipendeva da un messaggio `NOTICE`, che può essere filtrato. Il riscontro corretto restituisce una riga `SELECT`, come già fa il catalogo.

Usare [il programma aggiornato](../scripts/restore-retained-postgres.py) con `--finish-row-proof` e il riferimento della decisione esistente. Questo modo usa il cluster già estratto, verifica claim e log precedenti e mantiene il massimo totale di 18 avvii. Il limite della sola lettura campione è 180 secondi. Log e claim nuovi sono separati in `row-proof-v1`. La query usa una tabella temporanea nella copia isolata. La prova originale di estrazione rimane registrata sotto. MiniPET **39,78%**.

# Prova di ripristino PostgreSQL dalla custodia storica

Decisione approvata `GIOVANNI-NONPROD-ISOLATED-POSTGRES-RESTORE-20261107-01`.

La [ricevuta Windows](../evidence/storage-retained-custody-windows-verified-operator-20261107.json) lega la custodia indipendente al manifest `58484aea53aefeb1fff390578ba6562efabffd914caf64944eee7c9d9a2e0d79`. La prova usa il materiale già conservato sul VPS e ricostruisce quel manifest prima di estrarre il cluster. La chiave di decifratura resta sul PC.

## Perimetro

- Un solo nuovo scope privato `/var/lib/ouf-storage-migration/historical-postgres-restore-20261107-v1`. Tar PostgreSQL, mount PGDATA e immagine vengono scelti dal piano conservato. Verifica di dimensioni, contenuto e riferimenti prima dell'estrazione. Il cluster originale resta escluso dalle mount del test.
- Massimo 900 secondi, 18 invocazioni Docker, cluster estratto entro 1 GiB logico e almeno 2 GiB liberi. Uso della sola immagine PostgreSQL con ID già registrato. Container temporanei con rete `none`, nessuna porta pubblicata e root filesystem in sola lettura. Soltanto il cluster estratto è montato in scrittura.
- Controllare lo stato di chiusura con `pg_controldata`, aprire i database del cluster copiato in modalità single-user e leggere un campione da una tabella applicativa per database. Il JSON espone soltanto i conteggi. I log restano privati sul VPS.
- Esito atteso `ISOLATED_HISTORICAL_POSTGRES_RESTORED`. La prova riguarda il cluster PostgreSQL storico. Restano da provare MinIO, continuità degli eventi e criteri G3. MiniPET **39,78%**, credito aggiunto zero.

## Programma da approvare

[restore-retained-postgres.py](../scripts/restore-retained-postgres.py) · 14.535 byte · SHA-256 `2c57dd92954b9edff61a3463aea5ac00dc95e315e6b1b15e1db26ea87d294d58`.

Avvio come root con Python isolato e argomento `--decision-reference GIOVANNI-NONPROD-ISOLATED-POSTGRES-RESTORE-20261107-01` dopo la decisione. Controllate sintassi e selezione del mount. Il tentativo sul VPS sarà la prima prova effettiva del ripristino.

## Esecuzione approvata

Giovanni ha autorizzato un singolo tentativo. [Decisione](../evidence/storage-historical-postgres-restore-operator-decision-20261107.json). Esecuzione VPS pendente.

```bash
sudo /usr/bin/python3 -I -B -S - <<'PY'
import hashlib, sys, urllib.request
url = ('https://raw.githubusercontent.com/GioNob/ouf-deploy/'
       'e91387a661f2eb68d7e09ec0820557fa25c26644/scripts/restore-retained-postgres.py')
with urllib.request.urlopen(url, timeout=30) as response:
    code = response.read(14536)
if len(code) != 14535 or hashlib.sha256(code).hexdigest() != '2c57dd92954b9edff61a3463aea5ac00dc95e315e6b1b15e1db26ea87d294d58':
    raise SystemExit('HELD: SHA-256 o dimensione non corrispondente')
sys.argv[1:] = ['--decision-reference', 'GIOVANNI-NONPROD-ISOLATED-POSTGRES-RESTORE-20261107-01']
exec(compile(code, 'isolated-postgres-restore', 'exec'), {'__name__': '__main__'})
PY
```

Conservare il JSON finale. Su `HELD` conservare anche lo scope e i log privati.
