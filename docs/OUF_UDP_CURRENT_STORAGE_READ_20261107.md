# Lettura corrente UDP prima del passaggio a SeaweedFS

**Lettura corretta completata alle 18:27 CET:** UDP_BINDINGS_READ_ONLY, JAR /app/app.jar e AWS SDK 2.54.17 identificati. [Ricevuta](../evidence/udp-current-storage-bindings-operator-20261107.json). Non occorre ripetere questo comando: il prossimo passo è la [prova del client installato](OUF_UDP_SEAWEEDFS_CLIENT_PROBE_20261107.md).

Il primo comando si è fermato con `KNOWN_UDP_JAR_LAUNCH_REQUIRED`: il lettore assumeva il percorso Onboarding `/app/application.jar`, mentre il [Dockerfile UDP conservato](https://github.com/GioNob/ouf-udp-object-resolution/blob/0d40da05408a14db31d4d41af2372d6a71480291/Dockerfile) indica `/app/app.jar`. Il percorso live non è ancora stato restituito. [Ricevuta originale](../evidence/udp-storage-read-launch-held-operator-20261107.json).

Il comando corretto legge il percorso dall'argomento `-jar` dell'avvio Java diretto e non valuta shell. Raccoglie immagine, variabili/argomenti di storage, reti, classi e librerie S3. Legge la configurazione SeaweedFS preparata e verifica la presenza delle credenziali senza mostrarle. Se l'ispezione del JAR è incompleta, la sezione `udp.installedJar` lo dichiara senza eliminare gli altri binding.

Non ferma servizi, non cambia configurazioni e non emette richieste S3 o DB. Non è un test di connettività né una lettura della configurazione Spring/JVM effettiva.

## Comando VPS corretto

Commit 8d34ce385f84d9b99fe507634a58d73f1c7cae50; script 11410 byte, SHA-256 `71cede5f23c97b20483fe340ef146a89aef86d66162276d6ad92bf08ce0de350`.

```bash
sudo /usr/bin/timeout 120 /usr/bin/python3 -I -B -S - <<'PY'
import hashlib, urllib.request
url = 'https://raw.githubusercontent.com/GioNob/ouf-deploy/8d34ce385f84d9b99fe507634a58d73f1c7cae50/scripts/read-current-udp-storage-20261107.py'
with urllib.request.urlopen(url, timeout=25) as response:
    raw = response.read(11411)
if len(raw) != 11410 or hashlib.sha256(raw).hexdigest() != '71cede5f23c97b20483fe340ef146a89aef86d66162276d6ad92bf08ce0de350':
    raise SystemExit('STOP: dimensione o SHA-256 non corrispondente')
exec(compile(raw, 'read-current-udp-storage-20261107.py', 'exec'), {'__name__': '__main__'})
PY
```

Riportare il JSON finale. Risultato dei binding atteso `UDP_BINDINGS_READ_ONLY`; controllare separatamente `udp.installedJar.status`. La correzione è stata eseguita: installedJar.status READ. Le precedenti istruzioni restano come traccia del comando.

## Verifiche e seguito

`python3 tests/check_current_udp_storage_read.py`: PASS per forma d'avvio UDP del Dockerfile conservato, forma Onboarding, percorso relativo, lettura fixture JAR, JAR assente, wrapper non valutato, traversal rifiutato, redazione segreti e operazioni di sola lettura. La fixture non è l'immagine UDP installata. [Dettagli](../evidence/udp-storage-read-launch-fix-20261107.json).

Dopo il risultato: identificare bucket/configurazione e SDK reali, conservare l'immagine, confrontare gli oggetti correnti, verificare il client UDP con TLS e applicare il cambio a writer fermo. Il cambio UDP non è incluso in questo comando.

Asset CSV `c51745c5-1fc0-4d36-bdcf-1e9a8a049c94`, profilo `da3f17a2-5cbc-4d7d-9ed8-7f4b39a00342`: punto di ripresa E2E, non ricaricare.
