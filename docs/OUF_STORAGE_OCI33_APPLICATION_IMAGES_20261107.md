# Immagini applicative per il prossimo avvio isolato

Il VPS ha caricato e vincolato l'immagine Onboarding testata e confermato l'immagine UDP conservata. L'ID del daemon per Onboarding è registrato accanto al digest raw della configurazione verificato in precedenza. [Ricevuta VPS](../evidence/storage-oci33-application-images-ready-operator-20261107.json).

Gli accessi S3 isolati per Onboarding e UDP sono verificati sul VPS. La prossima coppia prepara le immagini senza avviare i servizi.

1. Scaricare sul VPS lo ZIP del run Onboarding 42049214518, verificare i digest e caricare l'immagine esatta. Il commit CI e il candidato d5155899 hanno lo stesso albero Git. [Binding dell'artefatto](../evidence/storage-oci33-onboarding-image-artifact-binding-20261107.json).
2. Verificare che il daemon conservi l'immagine UDP esatta già collegata al commit 0d40da05. [Riconciliazione delle origini](../releases/m2-retained-runtime-origin-reconciliation-20261101.json).

Le immagini restano nel daemon locale. I file di custodia rimangono nell'area privata `application-images-v1` sotto lo staging. L'esito atteso è `ISOLATED_APPLICATION_IMAGES_READY`. Se manca UDP, il JSON conserva lo stato di Onboarding. Durata massima nove minuti. Lo ZIP, l'archivio e la configurazione raw di Onboarding sono stati verificati localmente. Esecuzione VPS completata.

## Blocco unico eseguito sul VPS

L'URL temporaneo arriva nel blocco consegnato all'operatore. Il repository conserva soltanto il modello senza credenziali di download.

```bash
sudo /usr/bin/timeout 540 /usr/bin/python3 -I -B -S -c '
import hashlib, urllib.request
with urllib.request.urlopen("https://raw.githubusercontent.com/GioNob/ouf-deploy/6c1d97b56d7d5f18980444342ab117bfae044303/scripts/stage-oci33-application-images.py", timeout=25) as r:
    raw = r.read(9035)
if len(raw) != 9034 or hashlib.sha256(raw).hexdigest() != "3a91b353a5b0b854811ebd8b06053e60a123bc1a1d43b62248d4ab7f680df91e":
    raise SystemExit("HELD: script digest")
exec(compile(raw, "stage-oci33-application-images.py", "exec"), {"__name__": "__main__"})
' <<'OUF_URL'
INSERIRE_URL_TEMPORANEO_FORNITO_SEPARATAMENTE
OUF_URL
```
