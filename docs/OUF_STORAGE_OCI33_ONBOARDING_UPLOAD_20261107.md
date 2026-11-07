# Upload Onboarding verso SeaweedFS sul VPS isolato

L'operatore ha riportato HTTP 502 dopo un solo POST. Onboarding era UP e la lettura pre-upload di SeaweedFS era riuscita. Il 502 è compatibile con la risposta che l'adapter Onboarding usa per gli errori S3 di scrittura e lascia l'esito da riconciliare. L'area e i log privati sono conservati e i container sono stati rimossi. [Ricevuta VPS](../evidence/storage-oci33-onboarding-upload-http502-held-operator-20261107.json).

Il [primo avvio](../evidence/storage-oci33-onboarding-boot-ready-operator-20261107.json) ha verificato readiness, SeaweedFS TLS e Flyway V39–V41. La coppia corrente riusa quelle copie come base.

1. Clonare le copie di lavoro in `onboarding-stack-v1/upload-proof-v1`, avviare i tre container sulla sola loopback e inviare un CSV sintetico Teatri al vero endpoint delegato Onboarding. Il blocco crea una chiave di firma e un'identità effimere limitate alla copia. La ricevuta vincola percorso, capability, hash, dimensione e idempotency key. Un solo POST.
2. Dopo HTTP 201, verificare l'asset, l'intento ACKED e la ricevuta upload in PostgreSQL. Leggere il nuovo oggetto da SeaweedFS via TLS e confrontarne dimensione e SHA-256. Fermare e rimuovere i container. La copia conserva l'oggetto e le ricevute.

Esito atteso `ISOLATED_ONBOARDING_UPLOAD_VERIFIED`. L'upload è un effetto reale sulla copia isolata e usa l'immagine esatta di Onboarding. La firma è emessa localmente per questa prova. Il percorso chatbot e Gateway richiederà il proprio riscontro. In caso di `HELD`, lasciare l'area sul VPS e riportare il JSON. Il blocco registra l'intento prima del POST e permette un solo invio per scope. Massimo 12 minuti. Sintassi e formato della ricevuta verificati localmente, il tentativo VPS si è fermato sul 502.

## Blocco del tentativo VPS eseguito

```bash
sudo /usr/bin/timeout 720 /usr/bin/python3 -I -B -S - <<'PY'
import hashlib, urllib.request
url = 'https://raw.githubusercontent.com/GioNob/ouf-deploy/a471deecc09169f76574d65d3ad9784cf1819acf/scripts/boot-oci33-onboarding.py'
with urllib.request.urlopen(url, timeout=25) as response:
    raw = response.read(29471)
if len(raw) != 29470 or hashlib.sha256(raw).hexdigest() != '2e60ecd77565a87bc4ba10363452003b5f08dcfa0f14781d09777cec8fb49ced':
    raise SystemExit('HELD: SHA-256 o dimensione non corrispondente')
module = {'__name__': 'onboarding_upload'}
exec(compile(raw, 'boot-oci33-onboarding.py', 'exec'), module)
raise SystemExit(module['main'](upload=True))
PY
```
