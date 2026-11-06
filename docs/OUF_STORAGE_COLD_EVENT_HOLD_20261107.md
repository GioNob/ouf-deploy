# HOLD sugli eventi Docker — lettura unica del journal

Il VPS riporta UNEXPECTED_CONTAINER_EVENT dopo l'installazione del programma collegato. [Ricevuta](../evidence/storage-host-bound-cold-held-operator-20261107.json). Nel driver esatto il controllo segue tutte le azioni di fermo, l'ultimo inventario e offline(); precede il risultato stop e l'avvio della cattura. Questa collocazione non sostituisce la lettura delle ricevute né una verifica live.

Non rilanciare il vecchio comando, non riavviare container e non eliminare le aree. Nessun nuovo consenso necessario per questa lettura locale già compresa nell'assistenza autorizzata.

Il lettore verifica49intenti/reply,35postcondizioni policy,5gruppi,ultimo inventario145container e stream eventi conservato, rileggendo i digest alla fine. Legge localmente metadati potenzialmente sensibili; stampa solo digest, conteggi, nomi dei ruoli già noti e classificazioni. Nessun corpo di credenziali, configurazione o comando exec. Non legge sorgenti applicative/runtime correnti e non invoca Docker, systemd, IAM o servizi. Non installa file e non crea scope. Il download iniziale da GitHub è distinto dalle zero chiamate ai provider del lettore.

Limiti90secondi,192MiB totali comprese le riletture,1024file. I file stderr vuoti sono validi; quelli non vuoti vengono conteggiati e vincolati senza stamparli. Il confronto del comando exec con Healthcheck.Test è solo un confronto testuale: non prova attribuzione o autorizzazione. La soglia256eventi è segnalata senza affermare completezza della cronologia.

Sei test locali PASS: journal sintetico generato dal driver originale con HOLD finale, preservazione byte/frame, redazione, stderr non vuoto, intent alterato, reply assente, symlink ed eventi estranei. [Prova locale](../evidence/storage-cold-event-readback-local-20261107.json). [Run42312623241](https://github.com/GioNob/ouf-deploy/actions/runs/42312623241),job128217510640 **SUCCESS** alcommitd214a75e8147271218c6d60092c3f6af4b10282a: gli stessi6testPASS,log verificato. Il workflow storage-cold-event-readback verifica soltanto questo lettore; nessuna ripetizione delle prove native backup già riuscite.

## Comando da eseguire nella shell Bash del VPS

```bash
sudo /usr/bin/python3 -I -B -S - <<'PY'
import hashlib, urllib.request
url = ("https://raw.githubusercontent.com/GioNob/ouf-deploy/"
       "460706827004046d7f2a55a46ed2f7ed3ec8aed2/"
       "scripts/read-storage-cold-event-held-20261107.py")
with urllib.request.urlopen(url, timeout=30) as response:
    raw = response.read(15319)
if len(raw) != 15318 or hashlib.sha256(raw).hexdigest() != "3d96e397c3331c4ab17c32a517338f56135c7d9c9120e236be2295af30ff794a":
    raise SystemExit("HELD: download o SHA256 non corrispondente")
print("Download e SHA256: OK — sola lettura del journal Docker", flush=True)
exec(compile(raw, "verified-local-readback", "exec"), {"__name__": "__main__"})
PY
```

Codice pinned 460706827004046d7f2a55a46ed2f7ed3ec8aed2;15318byte;SHA2563d96e397c3331c4ab17c32a517338f56135c7d9c9120e236be2295af30ff794a.

Restituire il solo JSON redatto. Nessun file privato va caricato in chat/GitHub. Questa diagnostica non autorizza replay, riavvio o cattura e non aggiunge credito MiniPET. Dopo il riscontro, l'obiettivo è riconciliare l'eventuale fermo completato e proseguire con la sola cattura, senza reinviare35policy/14segnali. Cattura, trasferimentoWindows e restore target non sono ancora riusciti.
