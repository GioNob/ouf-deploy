# Confronto delle sorgenti PostgreSQL e MinIO conservate

La [parità storica SeaweedFS](../evidence/storage-retained-oci33-rehearsal-parity-operator-20261107.json) è acquisita. Questo confronto legge una sola volta le due sorgenti dati originali e le confronta con i manifest della custodia verificata. Collega inoltre i 120 oggetti già verificati a G0 per bucket, chiave, dimensione e SHA-256. Controlla prima e dopo l'assenza di container attivi e l'identità dei due container sorgente, con quattro comandi Docker di sola lettura al massimo. Restituisce soltanto conteggi ed esiti.

La scansione ricontrolla i file originali e non riestrae l'archivio. Durata massima sette minuti per il comando completo. I download riguardano esclusivamente codice GitHub con dimensione e SHA-256 fissati. Esecuzione VPS pendente. Verificati localmente sintassi e confronto degli inventari.

## Comando unico sul VPS

```bash
sudo /usr/bin/timeout 420 /usr/bin/python3 -I -B -S - <<'PY'
import hashlib, urllib.request
url = 'https://raw.githubusercontent.com/GioNob/ouf-deploy/6bb0d0b690d4fa93b50b65c4abe5ad06ccb4add3/scripts/compare-retained-storage-sources.py'
with urllib.request.urlopen(url, timeout=30) as response:
    raw = response.read(7544)
if len(raw) != 7543 or hashlib.sha256(raw).hexdigest() != '34c2a4cbe4f1db8fdf530c110aa820ef845b47aec60de0dd607e4a1f6b6a510b':
    raise SystemExit('HELD: SHA-256 o dimensione non corrispondente')
exec(compile(raw, 'compare-retained-storage-sources.py', 'exec'), {'__name__': '__main__'})
PY
```

Riportare il JSON finale. `RETAINED_SOURCE_COMPARISON_MATCH` indica corrispondenza con i manifest ai controlli eseguiti e riuso dell'inventario G0. `RETAINED_SOURCE_COMPARISON_DIVERGENCE` indica le fonti da riconciliare. In caso di `HELD` usare la ragione restituita. Un match è un riscontro sulle due sorgenti, mentre la prova temporale del common cut, il contenimento dei writer e l'ammissione al cutover rimangono aperti. Nessun credito MiniPET per il solo confronto.
