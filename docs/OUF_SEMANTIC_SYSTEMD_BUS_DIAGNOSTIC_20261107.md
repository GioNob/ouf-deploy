# Lettura dell'errore D-Bus Semantic

**DIAGNOSI COMPLETATA alle 20:56 CET:** GetUnit fallisce perché l'unità non è caricata. [Ricevuta](../evidence/semantic-systemd-get-unit-not-loaded-operator-20261107.json). Non ripetere questo lettore: la prossima azione è il [ripristino v3](OUF_SEMANTIC_TOKEN_RENEWAL_20261107.md), che verifica i file dell'unità senza chiamate D-Bus dirette. Quanto segue conserva il contesto e il comando diagnostico storico.

La ricevuta operatore del **7 novembre, 20:43:40 CET** (19:43:40 UTC) termina `TYPED_SERVICE_METADATA_READ_FAILED`. Il servizio operativo rimane inactive/disabled. Nessun override rimosso, daemon-reload, avvio, abilitazione o GET policy.

Sono ora provati i nomi omessi nell'output testuale: ExecStartPre, ExecStartPost, ExecCondition. Sono verificati path e byte dell'override di cattura. La v2 scarta però il codice di uscita e stderr di busctl e accorpa GetUnit e get-property: **non è provata la causa del nuovo errore né la fase che fallisce**. Non dedurre assenza di hook da un errore. I 19 scenari precedenti simulavano D-Bus e non provavano il trasporto sul VPS.

## Prossimo passo

Eseguire solo questa diagnosi: un GetUnit e, se riesce, una lettura separata per ciascuno dei tre hook. Riporta fase, codice di uscita, errore del comando di metadati e, per le letture riuscite, solo tipo/conteggio; non stampa gli argomenti degli hook. Non legge token o credenziali, non chiama LoadUnit, non modifica o avvia servizi.

```bash
sudo /usr/bin/python3 -I -B -S - <<'PY'
import hashlib
import urllib.request
url = 'https://raw.githubusercontent.com/GioNob/ouf-deploy/9745f249627469567f4a49d2cc7c3120b9bb4c90/scripts/read-semantic-systemd-bus-error-20261107.py'
with urllib.request.urlopen(url, timeout=20) as response:
    code = response.read(2765)
if len(code) != 2764 or hashlib.sha256(code).hexdigest() != 'dfdfe61612f32804f3f3d7b7a2a0be8d5e4c3212ac18e5c50776d799a6b55396':
    raise SystemExit('STOP: dimensione o SHA-256 non corrispondente')
exec(compile(code, 'semantic-bus-diagnostic', 'exec'), {'__name__': '__main__'})
PY
```

Incollare il JSON anche con READ_INCOMPLETE: in questo caso l'errore è il risultato utile. Preparazione verificata sintatticamente; nessuna esecuzione VPS locale.

La precedente procedura di ripristino resta sospesa finché è noto l'errore. Dopo la correzione: ripristino dell'esatto override, avvio produttore, token montato fresco, GET policy200, ricerca MCP. F1 resta PASS; F2–F6 e ricerca semantica restano aperti.

[Ricevuta](../evidence/semantic-operational-owner-dbus-held-operator-20261107.json) · [Stato](STATE.md).
