## Esito VPS e log conservato

La [ricevuta](../evidence/storage-historical-minio-restore-held-operator-20261107.json) riporta `MINIO_ISOLATED_READY_TIMEOUT`. Il ramo segue verifica manifest, estrazione, avvio con PID e pin del namespace. La disponibilità veniva misurata con GET S3 firmata. Il codice non distingueva avvio HTTP, errore curl e autenticazione e non ha iniziato l'inventario. Il container temporaneo è stato rimosso dal ramo di chiusura e il log è rimasto nello scope privato. L'esecuzione approvata è consumata.

Primo dato utile: un solo riscontro dal log già conservato. Il comando non avvia container e restituisce dimensioni e occorrenze di soli frammenti consentiti.

```bash
f=/var/lib/ouf-storage-migration/historical-minio-restore-20261107-v1/minio.stderr.private
sudo wc -lc "$f"
sudo grep -Eio 'API: https?://127\.0\.0\.1:9000|MinIO Object Storage Server|FATAL|ERROR|permission denied|read-only file system|address already in use|unable to use the drive|insufficient read quorum|drive not found|unable to initialize|waiting for a minimum|invalid credentials|logging driver|exiting on signal' "$f" | sort -f | uniq -ic
```

# Ripristino isolato della copia storica MinIO

Decisione approvata `GIOVANNI-NONPROD-ISOLATED-MINIO-RESTORE-20261107-01`. La [prova PostgreSQL](../evidence/storage-historical-postgres-restored-operator-20261107.json) è riuscita con 7 database aperti e 7 letture campione. La prova MinIO è il prossimo passo distinto.

## Operazione

- Ricostruire il manifest Windows dai tar già presenti sul VPS e conservare gli hash verificati per il confronto successivo. Selezionare l'immagine MinIO registrata e il volume indicato dal comando server conservato. Estrarre la sola sorgente MinIO in `/var/lib/ouf-storage-migration/historical-minio-restore-20261107-v1`.
- Avviare un solo container temporaneo con l'immagine locale esatta, credenziali effimere, rete `none` e nessuna porta pubblicata. Il volume scrivibile è la copia estratta. L'accesso S3 avviene solo sul loopback del namespace del container.
- Enumerare i bucket e le versioni senza accettare una lista troncata. Leggere i corpi tramite GET, verificare le dimensioni e calcolare SHA-256. Conservare l'inventario privato per la parità SeaweedFS. Il JSON riporta conteggi e l'eventuale corrispondenza al riferimento storico di 120 corpi.
- Limiti: 600 secondi per la prova, un avvio, 320 GET locali, 256 versioni o marker, 64 MiB per corpo, 512 MiB complessivi. Chiusura e rimozione riguardano soltanto il container temporaneo. I dati e i log della prova restano nello scope privato.
- Esito atteso `ISOLATED_HISTORICAL_MINIO_RESTORED`. È una prova storica di lettura dei corpi. Copertura eventi, migrazione e parità SeaweedFS restano passi distinti. MiniPET **39,78%**.

## Programmi da approvare

[Driver MinIO](../scripts/restore-retained-minio.py), 13.529 byte e SHA-256 `2b8636d90e9950237f92d6c3d29a8cf3e51ca3e1a6638d1afff219c7b9f9d4b3`.

Il driver riusa la verifica manifest di [PostgreSQL](../scripts/restore-retained-postgres.py) al commit `5ae47689adeaf39f241527c9364a2c0c9e9b0b9b`, 19.046 byte e SHA-256 `3ff2281f380dcab555d22966f78622a4f4bd00798e5e623e5db8fb95dee2513d`. Il comando VPS carica entrambe le versioni fissate, con Python isolato e `--decision-reference GIOVANNI-NONPROD-ISOLATED-MINIO-RESTORE-20261107-01`.

Verificate localmente la sintassi e la lettura GET di un membro versionato. La prima prova effettiva con il materiale storico sarà sul VPS.

## Esecuzione approvata

Giovanni ha autorizzato un singolo tentativo. [Decisione](../evidence/storage-historical-minio-restore-operator-decision-20261107.json). Esecuzione VPS pendente.

```bash
sudo /usr/bin/python3 -I -B -S - <<'PY'
import hashlib, sys, urllib.request
root = 'https://raw.githubusercontent.com/GioNob/ouf-deploy/'
def load(ref, role, size, sha):
    name = f'restore-retained-{role}.py'
    with urllib.request.urlopen(root + ref + '/scripts/' + name, timeout=30) as response:
        raw = response.read(size + 1)
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != sha:
        raise SystemExit('HELD: SHA-256 o dimensione non corrispondente')
    mod = {'__name__': 'retained_' + role}
    exec(compile(raw, name, 'exec'), mod)
    return mod
pg = load('5ae47689adeaf39f241527c9364a2c0c9e9b0b9b', 'postgres', 19046,
          '3ff2281f380dcab555d22966f78622a4f4bd00798e5e623e5db8fb95dee2513d')
mi = load('f3f22efb066cd814251ebb0f161d434727ce8083', 'minio', 13529,
          '2b8636d90e9950237f92d6c3d29a8cf3e51ca3e1a6638d1afff219c7b9f9d4b3')
sys.argv[1:] = ['--decision-reference', 'GIOVANNI-NONPROD-ISOLATED-MINIO-RESTORE-20261107-01']
mi['main'](pg)
PY
```

Conservare il JSON finale. In caso di HELD conservare anche lo scope privato.
