# Riscontro MinIO S3 con client HTTP Python

Decisione approvata `GIOVANNI-NONPROD-ISOLATED-MINIO-S3-20261107-03`. Il [secondo tentativo](../evidence/storage-historical-minio-s3-curl-held-operator-20261107.json) ha restituito l'errore client curl 43. Con curl 8.5 locale, le opzioni precedenti funzionano su loopback. La causa sul VPS e la fase della richiesta restano sconosciute.

La ripresa usa la copia MinIO già estratta e i claim conservati, verifica che entrambi i container precedenti siano stati rimossi e usa una nuova sottodirectory `s3-proof-v2`. Il driver mantiene la separazione tra sonda HTTP, lista bucket, lista versioni e lettura dei corpi. Il client usa la libreria standard Python con SigV4 per le sole richieste GET al loopback del namespace isolato. Firma validata col [vettore AWS Get Bucket Lifecycle](https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sig-v4-header-based-auth.html) e scambio locale binario verificato. La prossima esecuzione sul VPS prova il driver sul servizio reale.

Perimetro: **un solo avvio isolato, 15 minuti e fino a 320 GET locali complessive**. La copia estratta rimane l'unico volume montato. Gli errori indicano la fase e una causa consentita, senza risposte o credenziali. Risultato positivo atteso `ISOLATED_HISTORICAL_MINIO_RESTORED`, inventario e hash privati. G3 e MiniPET **39,78%** invariati.

[Programma](../scripts/restore-retained-minio.py), 21.823 byte, SHA-256 `c363c38e6a1a9b5768e40ae0c21ba7aef9b74a06a85914b890a6a84afb15bb93`. Stesso supporto PostgreSQL fissato a `5ae47689adeaf39f241527c9364a2c0c9e9b0b9b`. Invocazione Python isolata con `--finish-s3-proof --decision-reference GIOVANNI-NONPROD-ISOLATED-MINIO-S3-20261107-03`.

## Esecuzione approvata

Giovanni ha autorizzato un singolo avvio isolato con limite di 15 minuti. [Decisione](../evidence/storage-historical-minio-http-operator-decision-20261107.json). Esecuzione VPS pendente.

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
mi = load('fc15882c6f4a8786a49efd88e09c9f3bd8e2f7c5', 'minio', 21823,
          'c363c38e6a1a9b5768e40ae0c21ba7aef9b74a06a85914b890a6a84afb15bb93')
sys.argv[1:] = ['--finish-s3-proof', '--decision-reference',
                'GIOVANNI-NONPROD-ISOLATED-MINIO-S3-20261107-03']
mi['main'](pg)
PY
```

Conservare il JSON finale e lo scope privato in caso di HELD.
