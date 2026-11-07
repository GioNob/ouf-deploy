# Collegamenti S3 privati per Onboarding e UDP

Il [primo esito](../evidence/storage-oci33-app-bindings-http500-held-operator-20261107.json) riporta due configurazioni private create, HTTP 500 sulla prima lettura Onboarding e container rimosso. Il blocco si fermava subito sul 500 durante l'avvio. La causa specifica della risposta resta da verificare.

1. Riutilizzare le credenziali, i certificati e i dati staged esistenti. La ripresa controlla i file e registra il tentativo in `application-s3-v1/access-proof-v2`.
2. Avviare una sola istanza isolata. La prima lettura attende la disponibilità anche su HTTP 500, 502, 503 o 504, entro 45 secondi e al massimo 15 richieste iniziali. Poi verificare il corpo del proprio oggetto e il diniego sull'altro bucket per ciascuna identità.

Durata massima sette minuti per il comando completo, fino a 18 GET, nessuna mutazione S3. Su errore il blocco conserva il log privato sul VPS e riporta stato HTTP, codice S3 e categorie diagnostiche quando disponibili. Il risultato atteso è `ISOLATED_OCI33_APP_BINDINGS_READY`. Sintassi e riuso dei file verificati in locale. L'esecuzione VPS è pendente.

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
binding = load('7a952893de09e9f7779051ee38dac28599d85573', 'bind-staged-oci33-apps.py', 20268,
               'ce3dfb8b38be44be0f90a563e18d83815daa60539f64d8d46b55a62932b7d1f5')
raise SystemExit(binding['main'](stage, resume=True))
PY
```

Riportare il JSON finale.
