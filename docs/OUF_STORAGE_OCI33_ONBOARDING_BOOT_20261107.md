# Primo avvio isolato di Onboarding con OCI33

Il VPS ha avviato Onboarding sull'immagine esatta. PostgreSQL e SeaweedFS TLS erano disponibili, la readiness era UP e Flyway ha confermato V39, V40 e V41. I tre container sono stati rimossi e le copie di lavoro conservate. [Ricevuta VPS](../evidence/storage-oci33-onboarding-boot-ready-operator-20261107.json).

Il VPS ha [caricato l'immagine Onboarding esatta e confermato UDP](../evidence/storage-oci33-application-images-ready-operator-20261107.json). Gli accessi S3 tramite le due identità e TLS sono già verificati.

1. Preparare un cluster PostgreSQL di lavoro dal solo tar PostgreSQL della custodia e copiare i dati SeaweedFS staged. Le copie vanno sotto `onboarding-stack-v1`. Un segreto JDBC nuovo viene applicato soltanto al ruolo applicativo sulla copia. Il programma verifica che la coda di export protetti sia vuota prima di avviare l'applicazione.
2. Avviare PostgreSQL, SeaweedFS e il JAR Onboarding esatto in un namespace con sola loopback. Importare la CA di staging nel truststore Java temporaneo, controllare readiness e Flyway V39–V41. Fermare e rimuovere i container e conservare le copie, i log privati in caso di errore e la ricevuta.

L'avvio può aggiornare le copie di lavoro. Il PostgreSQL e lo storage originali restano fuori dai mount. I tre container sono temporanei e senza porte pubblicate. Il collegamento Gateway e il worker che ne dipende sono esclusi da questo avvio. Il risultato copre bootstrap, migrazioni e disponibilità locale di SeaweedFS via TLS. L'upload tramite applicazione e il flusso UDP sono fasi successive.

L'esito atteso è `ISOLATED_ONBOARDING_STACK_READY`. In caso di `HELD`, riportare il JSON e lasciare lo scope privato sul VPS. Durata massima 12 minuti. Verificate sintassi e presenza di keytool nell'immagine esatta. Esecuzione VPS completata.

## Blocco unico eseguito sul VPS

```bash
sudo /usr/bin/timeout 720 /usr/bin/python3 -I -B -S - <<'PY'
import hashlib, urllib.request
url = 'https://raw.githubusercontent.com/GioNob/ouf-deploy/9555287483d42d8d16f1a22badedbb17491e3d9b/scripts/boot-oci33-onboarding.py'
with urllib.request.urlopen(url, timeout=25) as response:
    raw = response.read(19992)
if len(raw) != 19991 or hashlib.sha256(raw).hexdigest() != 'cc86901e033d841dc4a23306f1bd0507258862eeba9636cfc48d7d6b0a3e4916':
    raise SystemExit('HELD: SHA-256 o dimensione non corrispondente')
exec(compile(raw, 'boot-oci33-onboarding.py', 'exec'), {'__name__': '__main__'})
PY
```
