## 7 novembre — parità verificata sul VPS

Il rehearsal isolato del dataset storico è riuscito. SeaweedFS OCI33 contiene i 120 oggetti dei due bucket (203.743 byte) con insieme delle chiavi, corpi, metadati e tag coincidenti. La continuazione ha riusato l'immagine verificata e distinto il digest della configurazione dall'ID del daemon. [Ricevuta operatore](../evidence/storage-retained-oci33-rehearsal-parity-operator-20261107.json).

Il restore isolato di PostgreSQL aveva già aperto 7 database e letto una riga in ciascuno. Le due prove si riferiscono alla stessa custodia storica. Restano aperti la baseline comune corrente, il contenimento verificabile dei writer e i binding applicativi. Credito aggiunto 0, G4 aperto, oggetti operativi migrati 0. Avanzamento MiniPET 18,3/46 (39,78%), gate 0/8, AT 0/21.

Il prossimo riscontro utile confronta le sorgenti originali PostgreSQL e MinIO con la custodia e l'inventario G0 già disponibili. Una corrispondenza rende riutilizzabile la prova storica per la pianificazione e lascia separata l'ammissione operativa.

# Riprendere il rehearsal dall’immagine OCI33 caricata

La [ricevuta](../evidence/storage-retained-oci33-docker-image-held-operator-20261107.json) riporta `DOCKER_IMAGE_FAILED`. Il ramo segue la verifica del tar. Il programma precedente usava lo stesso codice per `image ls` e `image inspect`. La ricezione del codice non dimostra che il caricamento sia riuscito. Nessun container o PUT è stato avviato in quel ramo.

La ripresa usa il tar Docker già verificato e il tag esatto dichiarato al suo interno. Controlla i DiffID e l'utente dal daemon, riesporta l'immagine indicata dal tag, confronta il digest della configurazione raw e verifica che l'ID del daemon sia rimasto lo stesso durante l'esportazione. Docker con store containerd può rappresentare l'ID con un digest di manifest. Il controllo della configurazione esatta resta distinto dall'ID da passare a Docker.

Se il tag manca o la verifica fallisce, il comando si ferma. Se passa, prosegue la copia già approvata in `copy-proof-v1`, sullo stesso perimetro isolato di due container e 120 oggetti. Il caricamento già tentato rimane separato. Limite della ripresa 15 minuti, 700 richieste locali. Verificate sintassi e lettura della configurazione da un tar campione. Esito reale VPS pendente.

## Comando VPS eseguito

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
rehearsal = load('09386c72b54e703dbab4bdd296a493ccdf1f0e05', 'rehearse-oci33-retained.py', 25800,
                 'd22e0b380dacf0dce6f3c84de069d19c8eca4c39c759f6200ef9255019f2950d')
sys.argv[1:] = ['--finish-loaded-image', '--decision-reference',
                'GIOVANNI-NONPROD-RETAINED-TO-OCI33-20261107-01']
rehearsal['main'](pg, mi)
PY
```

Conservare il JSON finale e lo scope privato in caso di HELD.
