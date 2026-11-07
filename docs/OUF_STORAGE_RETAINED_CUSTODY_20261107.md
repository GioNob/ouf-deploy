# Custodia storica del materiale di cattura OUF

**Qualifica nativa PASS.** Cifratura e decifratura con age, 34 tar sorgente, 14 rootfs, 53 digest verificati e controlli negativi in fixture isolata. [Esecuzione](https://github.com/GioNob/ouf-deploy/actions/runs/42352184254) · [Ricevuta di qualifica](../evidence/storage-retained-custody-qualified-20261107.json). Giovanni ha approvato l'esecuzione singola con «Autorizzo». [Decisione registrata](../evidence/storage-retained-custody-operator-decision-20261107.json). Esecuzione VPS pendente.

Decisione approvata `GIOVANNI-NONPROD-HISTORICAL-CUSTODY-20261107-01` sul perimetro qualificato con age. La decisione di cattura precedente copriva un tentativo, ora consumato.

## Evidenza del VPS

Il secondo inventario termina al comando 56, con 145 container, zero in esecuzione e stati dei selezionati invariati nei dati conservati. Il comando eventi 57 è assente. Nel codice, tra inventario ed eventi, restano la verifica completa dell'inventario e delle sorgenti runtime e il confronto dei manifest con il filesystem. Il readback non identifica la causa. I 72 secondi misurano dal claim interno all'ultimo output osservato e non misurano la durata totale del tentativo. [Ricevuta](../evidence/storage-capture-post-export-operator-20261107.json)

I 34 tar sorgente, 14 tar rootfs e il tar immagini sommano 6.540.999.168 byte. I manifest sorgente sono conservati. Il materiale è storico e incompleto rispetto alla procedura di backup. La continuità delle sorgenti, la copertura degli eventi e il restore restano aperti.

## Operazione proposta

- Un solo scope nuovo `capture-historical-custody-20261107-v1` sotto `/var/lib/ouf-storage-migration`. Gli originali restano privati e conservati.
- Vincolo su decisione, claim e piano originali, stadio osservato a 56 comandi e dimensioni aggregate esatte. Rivalidare i 34 tar sorgente contro i manifest col verificatore del produttore. Includere 53 membri del payload, hashati durante lo streaming, e i claim di provenienza nel manifesto cifrato. I 14 rootfs e il tar immagini sono conservati come artefatti storici con hash dei byte. L'esercitazione di restore rimane separata.
- Una invocazione del binario age già verificato e stesso destinatario. Flusso tar verso age con tetto **8 GiB** sul cifrato e tempo **900 secondi**. Lo scope non contiene un nuovo bundle in chiaro. Output privato, con ricevuta finale soltanto dopo uscita di age, sincronizzazione, verifica di stabilità e SHA-256. Gli errori conservano claim e parziale.
- Scadenza invariata **7 novembre 2026, 20:53:39 ora di Roma**. Avvio entro **20:38:39**. Restano contabilizzati 184 comandi e 2400 secondi del fermo, 56 marker e 3600 secondi della cattura. Zero richieste al provider, segnali, cambi di policy, riavvii o apertura del traffico.
- `HISTORICAL_CUSTODY_ARCHIVE_SEALED` espone percorso, byte e SHA-256 per la successiva copia indipendente. Custodia storica distinta da backup operativo. MiniPET **39,78%**, zero credito nuovo.

[Script](../scripts/seal-retained-storage-capture-20261107.py) · [Qualifica nativa](../.github/workflows/storage-retained-custody.yml)

La fixture locale ha verificato corruzione, idempotenza del claim, errore del cifratore, integrità dei membri e conservazione degli originali. Il test locale usa pass-through. Il workflow separato verifica cifratura e decifratura con age su fixture isolate.

## Comando pinned dopo la decisione

Il comando richiede il riferimento esatto della nuova decisione. Il riferimento è un vincolo di provenienza e non autentica una decisione operativa. Eseguire soltanto dopo la sua registrazione.

```bash
sudo /usr/bin/python3 -I -B -S - <<'PY'
import hashlib
import sys
import urllib.request

url = (
    "https://raw.githubusercontent.com/GioNob/ouf-deploy/"
    "45d18601a8b0993c5a843477809197c3d02574fa/"
    "scripts/seal-retained-storage-capture-20261107.py"
)
with urllib.request.urlopen(url, timeout=30) as response:
    raw = response.read(14301)
if len(raw) != 14300 or hashlib.sha256(raw).hexdigest() != "1e269721c9ee0104cf7ead1e35505048a7152ab4a61102eee6a7e000c5128d1e":
    raise SystemExit("HELD: download o SHA256 non corrispondente")
sys.argv[1:] = [
    "--decision-reference", "GIOVANNI-NONPROD-HISTORICAL-CUSTODY-20261107-01",
    "--historical-custody-only",
]
exec(compile(raw, "verified-retained-custody", "exec"), {"__name__": "__main__"})
PY
```

Attendere il JSON finale. Un HOLD conserva la prova locale e ferma il tentativo. Dopo `HISTORICAL_CUSTODY_ARCHIVE_SEALED` usare percorso, byte e SHA-256 effettivi per la copia indipendente.
