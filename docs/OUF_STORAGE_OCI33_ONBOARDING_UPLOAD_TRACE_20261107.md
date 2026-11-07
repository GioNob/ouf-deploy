# Upload isolato con Flight Recorder dopo HTTP 502

Il VPS ha confermato `ONB_STAGING_WRITE_FAILED` con HTTP 502 dopo un solo POST del nuovo intento. La lettura S3 pre-upload è riuscita. Flight Recorder ha conservato il file, mentre il riepilogo incorporato non l'ha decodificato. I contatori di eccezioni e handshake pari a zero in quella ricevuta sono valori iniziali del riepilogo. Tutti e tre i container sono stati rimossi. [Ricevuta VPS](../evidence/storage-oci33-onboarding-upload-trace-held-operator-20261107.json).

La [lettura del tentativo precedente](../evidence/storage-oci33-onboarding-upload-readback-operator-20261107.json) ha trovato un intento `DISPATCHED` senza ACK, asset o oggetto riservato. I log conservati non spiegano il 502.

1. Clonare le copie PostgreSQL V41 e SeaweedFS del primo avvio riuscito in `upload-proof-v1/instrumented-upload-v1`. Avviare i tre container in isolamento e inviare un solo POST Teatri tramite l'immagine esatta di Onboarding, con un intento e una firma locali nuovi. Flight Recorder osserva eccezioni e handshake TLS del JRE.
2. Su HTTP 201 verificare ACK PostgreSQL e SHA-256 dell'oggetto SeaweedFS. Su errore conservare risposta, registrazione JFR e log privati. Il JSON riporta solo codice applicativo, categorie di eccezioni, indizi di trasporto e conteggi nel periodo del POST. Rimuovere i container temporanei.

Il tentativo precedente rimane conservato. La nuova operazione riguarda esclusivamente le copie. Durata massima 12 minuti. La scrittura e decodifica del file JFR sono state verificate localmente con il JRE dell'immagine esatta. Il tentativo VPS si è fermato sul 502.

## Blocco del tentativo VPS eseguito

```bash
sudo /usr/bin/timeout 720 /usr/bin/python3 -I -B -S - <<'PY'
import hashlib, urllib.request
url = 'https://raw.githubusercontent.com/GioNob/ouf-deploy/6a557a0236b841b2a40c4ebcd84ea9b13dc1e125/scripts/boot-oci33-onboarding.py'
with urllib.request.urlopen(url, timeout=25) as response:
    raw = response.read(44510)
if len(raw) != 44509 or hashlib.sha256(raw).hexdigest() != '79fc2303851f09f805ad6c7919571113c98ed6d9b24bd7eaabf5faf375a354bf':
    raise SystemExit('HELD: SHA-256 o dimensione non corrispondente')
module = {'__name__': 'onboarding_upload_trace'}
exec(compile(raw, 'boot-oci33-onboarding.py', 'exec'), module)
raise SystemExit(module['main'](upload=True, trace=True))
PY
```

Riportare solo il JSON finale.
