# Confronto delle sorgenti PostgreSQL e MinIO conservate

## 7 novembre — sorgenti originali e inventario G0 corrispondono

Il riscontro operatore ha verificato la custodia e trovato zero differenze per 5.032 voci PostgreSQL e 325 voci MinIO. I 120 oggetti coincidono con G0 per bucket, chiave, dimensione e SHA-256. I due container sorgente corrispondevano alle identità catturate e i controlli Docker prima e dopo hanno osservato zero container attivi. [Ricevuta](../evidence/storage-retained-source-comparison-match-operator-20261107.json).

Il backup cifrato verificato su Windows, i due restore isolati e la parità OCI33 restano le evidenze da riusare. Il confronto non attesta la copertura degli eventi della cattura, un common cut temporale o una barriera persistente alle scritture esterne. G4 resta aperto. MiniPET 18,3/46 (39,78%), gate 0/8, AT 0/21, oggetti migrati operativamente 0.

Il comando conservato sotto documenta la lettura già completata.

La [parità storica SeaweedFS](../evidence/storage-retained-oci33-rehearsal-parity-operator-20261107.json) è acquisita. Questo confronto legge una sola volta le due sorgenti dati originali e le confronta con i manifest della custodia verificata. Collega inoltre i 120 oggetti già verificati a G0 per bucket, chiave, dimensione e SHA-256. Controlla prima e dopo l'assenza di container attivi e l'identità dei due container sorgente, con quattro comandi Docker di sola lettura al massimo. Restituisce soltanto conteggi ed esiti.

La scansione ricontrolla i file originali e non riestrae l'archivio. Durata massima sette minuti per il comando completo. I download riguardano esclusivamente codice GitHub con dimensione e SHA-256 fissati. Esecuzione VPS completata. Verificati localmente sintassi e confronto degli inventari.

Il [primo esito](../evidence/storage-retained-source-comparison-g0-held-operator-20261107.json) ha verificato la custodia e si è fermato prima di Docker e dei volumi. Lo script usava per G0 la serializzazione della custodia, che aggiunge un fine riga al JSON. Il comando aggiornato usa il formato G0 e verifica anche l'hash del file pubblicato nella ricevuta precedente. La correzione è verificata localmente. L'esecuzione con i volumi originali ha confermato la corrispondenza.

## Comando unico eseguito sul VPS

```bash
sudo /usr/bin/timeout 420 /usr/bin/python3 -I -B -S - <<'PY'
import hashlib, urllib.request
url = 'https://raw.githubusercontent.com/GioNob/ouf-deploy/08cbe8c4369776b47170df6d183d178432f2fd9f/scripts/compare-retained-storage-sources.py'
with urllib.request.urlopen(url, timeout=30) as response:
    raw = response.read(7926)
if len(raw) != 7925 or hashlib.sha256(raw).hexdigest() != '9560e094ba48a80a9ab44fe195cd56c220600525d756cda485a1d4f087917138':
    raise SystemExit('HELD: SHA-256 o dimensione non corrispondente')
exec(compile(raw, 'compare-retained-storage-sources.py', 'exec'), {'__name__': '__main__'})
PY
```

Riportare il JSON finale. `RETAINED_SOURCE_COMPARISON_MATCH` indica corrispondenza con i manifest ai controlli eseguiti e riuso dell'inventario G0. `RETAINED_SOURCE_COMPARISON_DIVERGENCE` indica le fonti da riconciliare. In caso di `HELD` usare la ragione restituita. Un match è un riscontro sulle due sorgenti, mentre la prova temporale del common cut, il contenimento dei writer e l'ammissione al cutover rimangono aperti. Nessun credito MiniPET per il solo confronto.
