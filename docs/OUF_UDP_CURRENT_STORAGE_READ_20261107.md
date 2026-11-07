# Lettura corrente UDP prima del passaggio a SeaweedFS

Onboarding ha completato upload e profilo sul nuovo binding. UDP resta da verificare e collegare. Questo comando legge il container UDP identificato dal piano conservato, immagine, variabili/argomenti di storage, reti, classi e librerie S3 del JAR installato. Legge inoltre la configurazione SeaweedFS già preparata e controlla la presenza delle credenziali senza mostrarle.

Non ferma servizi, non cambia configurazioni e non emette richieste S3 o DB. Non è un test di connettività né una lettura della configurazione Spring/JVM effettiva. Le dichiarazioni concorrenti vengono riportate senza presumere quale prevalga.

## Comando VPS

Commit 1c922e9decaafc93d90692918f6050b739946894; script 10.200 byte, SHA-256 `4629a87bfb6783b81b65e06c58bd3de0468ae0d8b8ce05fd43393e4925ca3339`.

```bash
sudo /usr/bin/timeout 120 /usr/bin/python3 -I -B -S - <<'PY'
import hashlib, urllib.request
url = 'https://raw.githubusercontent.com/GioNob/ouf-deploy/1c922e9decaafc93d90692918f6050b739946894/scripts/read-current-udp-storage-20261107.py'
with urllib.request.urlopen(url, timeout=25) as response:
    raw = response.read(10201)
if len(raw) != 10200 or hashlib.sha256(raw).hexdigest() != '4629a87bfb6783b81b65e06c58bd3de0468ae0d8b8ce05fd43393e4925ca3339':
    raise SystemExit('STOP: dimensione o SHA-256 non corrispondente')
exec(compile(raw, 'read-current-udp-storage-20261107.py', 'exec'), {'__name__': '__main__'})
PY
```

Riportare il JSON finale. Risultato atteso `UDP_BINDINGS_READ_ONLY`; su errore conserva un codice sintetico, senza messaggi che possano esporre segreti. Nessuna esecuzione VPS attestata da questo documento.

## Verifiche locali e prossimo passo

`python3 tests/check_current_udp_storage_read.py`: PASS per sintassi, redazione di endpoint con credenziali, selezione delle sole variabili consentite, forme degli argomenti e operazioni di sola lettura. Questi controlli non provano l'accesso al JAR tramite /proc sul VPS.

Dopo il risultato: identificare bucket/configurazione e SDK reali, riutilizzare l'immagine installata, confrontare gli oggetti correnti, verificare il client UDP con TLS e applicare il cambio con writer fermo. Il cambio UDP non è incluso in questo comando.

L'asset CSV `c51745c5-1fc0-4d36-bdcf-1e9a8a049c94` e il profilo `da3f17a2-5cbc-4d7d-9ed8-7f4b39a00342` restano il punto di ripresa E2E; non ricaricare.
