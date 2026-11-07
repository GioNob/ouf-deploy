# Lettura dell'esito dopo HTTP 502

La lettura sul VPS ha trovato un intento `DISPATCHED` senza ACK, collegamento asset, asset o ricevuta. SeaweedFS ha risposto `404 NoSuchKey` sulla chiave riservata. Le due richieste S3 erano GET e i container di lettura sono stati rimossi. I log precedenti non identificano la causa del 502. [Ricevuta VPS](../evidence/storage-oci33-onboarding-upload-readback-operator-20261107.json).

Il [POST tentato](../evidence/storage-oci33-onboarding-upload-http502-held-operator-20261107.json) è consumato. Onboarding era disponibile e la lettura S3 pre-upload era riuscita. L'adapter converte diversi errori di scrittura in HTTP 502, quindi la causa specifica e l'effetto su SeaweedFS richiedono riscontri distinti.

1. Leggere le categorie dei log privati e interrogare il record esatto in una copia del PostgreSQL del tentativo. PostgreSQL accetta solo socket locale e usa transazioni di sola lettura. Il risultato distingue intento, ACK, ricevuta e asset.
2. Avviare SeaweedFS su una copia dello stesso scope con identità di sola lettura e verificare la chiave riservata dal record. Il risultato distingue corpo coincidente, corpo diverso, assenza confermata da NoSuchKey o chiave priva di binding. Fermare e rimuovere i due container temporanei.

La nuova area `upload-proof-v1/readback-v1` conserva la ricevuta. Il blocco esegue query e GET, senza nuovi upload o avvii di Onboarding. I log privati restano sul VPS. L'esito atteso è `ONBOARDING_UPLOAD_OUTCOME_READ_BACK`. Durata massima dieci minuti. Sintassi verificata localmente, esecuzione VPS completata.

## Blocco eseguito sul VPS

```bash
sudo /usr/bin/timeout 600 /usr/bin/python3 -I -B -S - <<'PY'
import hashlib, urllib.request
url = 'https://raw.githubusercontent.com/GioNob/ouf-deploy/b44a17c16ffa2dbaf6ed5e38271314e69b907dec/scripts/boot-oci33-onboarding.py'
with urllib.request.urlopen(url, timeout=25) as response:
    raw = response.read(37423)
if len(raw) != 37422 or hashlib.sha256(raw).hexdigest() != '9085d557e6a6e5ed9b4c571b23f518cfc1f8fdb92514ace64091be7a34f1efd0':
    raise SystemExit('HELD: SHA-256 o dimensione non corrispondente')
module = {'__name__': 'onboarding_upload_readback'}
exec(compile(raw, 'boot-oci33-onboarding.py', 'exec'), module)
raise SystemExit(module['main'](readback=True))
PY
```

Riportare soltanto il JSON finale.
