# Completamento della prova S3 sulla copia MinIO

Decisione approvata `GIOVANNI-NONPROD-ISOLATED-MINIO-S3-20261107-02`.

Il [log redatto](../evidence/storage-historical-minio-startup-log-operator-20261107.json) riporta API su 127.0.0.1:9000 e la chiusura del container. La GET S3 firmata del primo tentativo è fallita. Il log non identifica la causa della GET.

La ripresa lega la copia già estratta al manifest conservato e verifica che il container precedente sia stato rimosso. Usa una sottodirectory privata `s3-proof-v1` e un nuovo container isolato con rete `none`. La prova HTTP di disponibilità precede le richieste firmate. Eventuali errori distinguono entrata nel namespace, uscita curl, stato HTTP e categorie S3 consentite. Le credenziali effimere rimangono in file privati. Root access esplicito vale soltanto per il container temporaneo.

Limiti: un solo nuovo avvio sulla stessa copia, **900 secondi**, massimo 320 GET complessive. L'inventario legge i corpi, confronta le dimensioni e conserva gli hash per la parità SeaweedFS. La rimozione finale riguarda il solo container temporaneo.

[Driver](../scripts/restore-retained-minio.py) · 18.795 byte · SHA-256 `ce0c2dd10ce05eddd8c6d258393cd87515aedc1aa12eab99bc9c9124ef42947c`. Usa lo stesso supporto PostgreSQL fissato a `5ae47689adeaf39f241527c9364a2c0c9e9b0b9b`. Modalità `--finish-s3-proof --decision-reference GIOVANNI-NONPROD-ISOLATED-MINIO-S3-20261107-02`. Sintassi verificata. La prima esecuzione di questo percorso sarà sul VPS. MiniPET **39,78%**.

## Esecuzione approvata

Giovanni ha autorizzato un singolo avvio con limite di 15 minuti. [Decisione](../evidence/storage-historical-minio-s3-operator-decision-20261107.json). Esecuzione VPS pendente.

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
mi = load('50f23a98a3f9f134ea8eaae64b91b0bb5cd43aa7', 'minio', 18795,
          'ce0c2dd10ce05eddd8c6d258393cd87515aedc1aa12eab99bc9c9124ef42947c')
sys.argv[1:] = ['--finish-s3-proof', '--decision-reference',
                'GIOVANNI-NONPROD-ISOLATED-MINIO-S3-20261107-02']
mi['main'](pg)
PY
```

Conservare il JSON finale e lo scope privato in caso di HELD.
