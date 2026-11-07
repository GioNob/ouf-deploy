# Collegamenti S3 privati per Onboarding e UDP

Lo [staging OCI33](../evidence/storage-retained-oci33-stage-ready-operator-20261107.json) ha già verificato 2 bucket e 120 oggetti. La coppia corrente usa quei dati sul VPS.

1. Preparare due identità distinte con i bucket vincolati dal rilievo G0, le configurazioni dei client e un certificato TLS temporaneo per `ouf-seaweedfs-stage`. La CA di staging è locale e il certificato dura 30 giorni. I file privati risiedono in `/var/lib/ouf-storage-migration/seaweedfs/staging-oci33-20261107-v1/application-s3-v1`.
2. Avviare un solo SeaweedFS OCI33 in rete `none`. Per ciascuna identità leggere un oggetto reale del proprio bucket su TLS e confrontarne l'hash, poi verificare il diniego sul bucket dell'altra identità. Il container viene rimosso al termine. Le richieste S3 sono tutte GET.

Lo script richiede lo staging riuscito e usa un'area nuova a creazione esclusiva. Durata massima sette minuti. Se il risultato è `HELD`, conservare i file e riportare il JSON. Sintassi, generazione delle configurazioni e validità locale del certificato sono state verificate. Il riscontro VPS è pendente.

Il risultato atteso `ISOLATED_OCI33_APP_BINDINGS_READY` qualifica i due accessi di lettura e i dinieghi sullo staging, con il client SigV4 locale. La successiva integrazione usa le immagini applicative, il trust Java e il mapping dei mount effettivi. L'isolamento del cambio operativo e l'ammissione restano aperti.

## Blocco unico sul VPS

```bash
sudo /usr/bin/timeout 420 /usr/bin/python3 -I -B -S - <<'PY'
import hashlib, urllib.request
def load(ref, name, size, sha):
    url = f'https://raw.githubusercontent.com/GioNob/ouf-deploy/{ref}/scripts/{name}'
    with urllib.request.urlopen(url, timeout=25) as response:
        raw = response.read(size + 1)
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != sha:
        raise SystemExit('HELD: SHA-256 o dimensione non corrispondente')
    module = {'__name__': 'ouf_stage_bindings'}
    exec(compile(raw, name, 'exec'), module)
    return module
stage = load('4adcbe4cda5e8fbae510de8a6ca6f7b040a1d11e', 'stage-retained-oci33.py', 12138,
             '7b8163939a6e08fb71e2acc31b92b24084c4364aedd64e230a793fac9565b2fe')
binding = load('e76b7a120d52793f0e0428938dbb8638ccffa9f7', 'bind-staged-oci33-apps.py', 15018,
               '1394bad48a665655588ca807c191380d1542ff585f8cf4dcab0f0b7414a03003')
raise SystemExit(binding['main'](stage))
PY
```

Riportare il JSON finale.
