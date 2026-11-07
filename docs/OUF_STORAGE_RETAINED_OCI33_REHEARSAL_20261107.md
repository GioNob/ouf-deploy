# Rehearsal reale della copia storica su SeaweedFS OCI33

Decisione approvata `GIOVANNI-NONPROD-RETAINED-TO-OCI33-20261107-01`. Lo [ZIP esatto è sul VPS](../evidence/storage-oci33-zip-staged-operator-20261107.json), 174.223.468 byte. La [ricevuta MinIO](../evidence/storage-historical-minio-restored-operator-20261107.json) lega la sorgente ai 120 corpi e al manifest privato.

## Operazione proposta

- In un unico scope privato `historical-oci33-rehearsal-20261107-v1`, verificare ZIP, tar Docker interno e config ID. Verificare eventuali conflitti di tag e caricare esclusivamente l'immagine locale esatta. Il caricamento lascia l'immagine nel Docker del VPS.
- Avviare due container temporanei, MinIO sulla copia storica e SeaweedFS con directory dati vuota separata. Entrambi condividono il namespace isolato senza rete esterna e senza porte pubblicate. Credenziali effimere nei file privati dello scope.
- Prima di copiare, verificare i due bucket e il profilo senza versioni o collisioni di chiavi. Rileggere i 120 corpi MinIO, confrontare SHA-256 con il manifest e acquisire metadati e tag via S3. Per ogni oggetto, registrare l'intento, eseguire un PUT con `If-None-Match: *` e rileggere corpo, metadati e tag. Confrontare anche gli insiemi finali di bucket e chiavi.
- Limiti: **15 minuti**, massimo due container e 700 richieste HTTP locali. Una singola esecuzione. I due container temporanei vengono rimossi alla chiusura. Directory dati e ricevute restano private sul VPS.

Esito atteso `HISTORICAL_OCI33_REHEARSAL_PARITY_VERIFIED` con 120 oggetti e 203.743 byte. La prova riguarda la copia storica. Restano aperti G4 complessivo, parità dei riferimenti applicativi, rollback e passaggio in esercizio. MiniPET **39,78%**, zero migrazione operativa.

## Programmi fissati

- [Rehearsal](../scripts/rehearse-oci33-retained.py), 22.711 byte, SHA-256 `3a8e769ea1552269ca9c6c913803c6a5afbb4419e731a77a1b64d9d8e75ec380`.
- Supporto PostgreSQL al commit `5ae47689adeaf39f241527c9364a2c0c9e9b0b9b`, 19.046 byte e SHA-256 `3ff2281f380dcab555d22966f78622a4f4bd00798e5e623e5db8fb95dee2513d`.
- Supporto MinIO al commit `fc15882c6f4a8786a49efd88e09c9f3bd8e2f7c5`, 21.823 byte e SHA-256 `c363c38e6a1a9b5768e40ae0c21ba7aef9b74a06a85914b890a6a84afb15bb93`.

Controllate sintassi e firme GET/PUT contro i [vettori AWS](https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sig-v4-header-based-auth.html). La prima copia reale con questo programma sarà sul VPS dopo la decisione.

## Esecuzione approvata

Giovanni ha autorizzato il caricamento dell'immagine esatta e una singola copia di rehearsal. [Decisione](../evidence/storage-retained-oci33-rehearsal-operator-decision-20261107.json). Esecuzione VPS pendente.

```bash
sudo /usr/bin/python3 -I -B -S - <<'PY'
import hashlib, sys, urllib.request
root = 'https://raw.githubusercontent.com/GioNob/ouf-deploy/'
def load(ref, name, size, sha):
    with urllib.request.urlopen(root + ref + '/scripts/' + name, timeout=30) as response:
        raw = response.read(size + 1)
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != sha:
        raise SystemExit('HELD: SHA-256 o dimensione non corrispondente')
    mod = {'__name__': 'retained_' + name}
    exec(compile(raw, name, 'exec'), mod)
    return mod
pg = load('5ae47689adeaf39f241527c9364a2c0c9e9b0b9b', 'restore-retained-postgres.py', 19046,
          '3ff2281f380dcab555d22966f78622a4f4bd00798e5e623e5db8fb95dee2513d')
mi = load('fc15882c6f4a8786a49efd88e09c9f3bd8e2f7c5', 'restore-retained-minio.py', 21823,
          'c363c38e6a1a9b5768e40ae0c21ba7aef9b74a06a85914b890a6a84afb15bb93')
rehearsal = load('d45d48fad99ade923ed17070a782c8778f999221', 'rehearse-oci33-retained.py', 22711,
                 '3a8e769ea1552269ca9c6c913803c6a5afbb4419e731a77a1b64d9d8e75ec380')
sys.argv[1:] = ['--decision-reference', 'GIOVANNI-NONPROD-RETAINED-TO-OCI33-20261107-01']
rehearsal['main'](pg, mi)
PY
```

Conservare il JSON finale e lo scope privato in caso di HELD.
