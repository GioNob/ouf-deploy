# Staging SeaweedFS OCI33 sul VPS

Il VPS ha restituito `ISOLATED_OCI33_STAGE_READY`. La copia dei file è verificata, SeaweedFS ha elencato 2 bucket e 120 oggetti in rete isolata con 5 GET, poi il container è stato rimosso. I dati staged sono disponibili per configurare gli accessi applicativi. [Ricevuta operatore](../evidence/storage-retained-oci33-stage-ready-operator-20261107.json).

1. Copiare i dati SeaweedFS del [rehearsal riuscito](../evidence/storage-retained-oci33-rehearsal-parity-operator-20261107.json) in `/var/lib/ouf-storage-migration/seaweedfs/staging-oci33-20261107-v1`. Confrontare il manifest dei file prima dell'avvio e riusare l'immagine già verificata.
2. Avviare un solo container SeaweedFS in rete `none` e leggere l'elenco dei due bucket e dei 120 oggetti tramite loopback. La configurazione di staging usa credenziali locali di sola lettura. Fermare e rimuovere il container al termine, lasciando i dati staged per la fase applicativa.

Il blocco crea solo la nuova area e il container isolato. Il controllo si ferma se trova container attivi all'ingresso. L'avvio interno può aggiornare i file della copia di staging. Le operazioni S3 sono GET. L'esito atteso è `ISOLATED_OCI33_STAGE_READY`. In caso di `HELD`, riportare l'esito e conservare l'area. Durata massima 10 minuti. Il confronto della copia e la sintassi sono stati verificati in locale su un albero minimo. Avvio VPS completato.

L'avvio isolato verifica la riutilizzabilità dei dati staged. Il pacchetto di applicazione, i binding TLS e la decisione di riapertura sono fasi distinte. MiniPET 18,3/46 (39,78%) prima dell'esecuzione.

## Blocco unico eseguito sul VPS

```bash
sudo /usr/bin/timeout 600 /usr/bin/python3 -I -B -S - <<'PY'
import hashlib, urllib.request
url = 'https://raw.githubusercontent.com/GioNob/ouf-deploy/4adcbe4cda5e8fbae510de8a6ca6f7b040a1d11e/scripts/stage-retained-oci33.py'
with urllib.request.urlopen(url, timeout=30) as response:
    raw = response.read(12139)
if len(raw) != 12138 or hashlib.sha256(raw).hexdigest() != '7b8163939a6e08fb71e2acc31b92b24084c4364aedd64e230a793fac9565b2fe':
    raise SystemExit('HELD: SHA-256 o dimensione non corrispondente')
exec(compile(raw, 'stage-retained-oci33.py', 'exec'), {'__name__': '__main__'})
PY
```

Riportare il JSON finale.
