# Lettura del percorso semantico dopo il cambio storage

## Esito che manca

La chiamata MCP `semantic.search` per `teatro` restituisce HTTP 502. Il profilo CSV è leggibile e MCP dichiara HEALTHY per il proprio modulo. Il catalogo corrente include il grant di ricerca semantica per admin: questo non prova l'autorizzazione effettiva lungo tutta la richiesta. Una lettura separata dello stato Ingestion è negata e non è stata ritentata; non va confusa con il 502. [Evidenza delle chiamate](../evidence/post-storage-e2e-entry-checks-20261107.json).

Onboarding e UDP sono già collegati a SeaweedFS. Questa lettura cerca il blocco che impedisce di proseguire il CSV nel Semantic Registry locale.

## Cosa legge

Lo script usa il piano corrente del VPS, fissato tramite hash, per selezionare Semantic Registry, APISIX e Gateway owner. Verifica immagini e stato; legge al massimo 200 righe degli ultimi 30 minuti dei log Semantic/APISIX e restituisce solo conteggi di categorie note. Non stampa log grezzi o credenziali.

Usa in memoria la chiave amministrativa già configurata per **una sola GET** delle rotte APISIX. Seleziona la rotta esatta di ricerca semantica e confronta gli upstream con il registro installato; verifica DNS e connessione TCP dalla rete APISIX. Se il registro è fermo lo segnala, senza avviarlo. Non esegue richieste di business, SQL o S3, non cambia configurazioni o permessi.

Un esito di rete positivo non equivale a una ricerca semantica riuscita. Le categorie dei log non sono una traccia correlata alla singola richiesta. La lettura corrente serve a scegliere la correzione successiva, non assume che il problema storico di DNS del 16 ottobre sia ricomparso.

## Comando unico sul VPS

Sorgente `ce3802c5bd3596cd3103ed47635cd1c344936caf`, 16626 byte, SHA-256 `2fc4d6c64e9901dbacd94f86f968c99849f31545f39933024bff540cd39da7a8`. Controlli locali PASS: selezione credenziale, oscuramento output, selezione rotta, registro fermo, namespace DNS/TCP e contratto GET. Esecuzione VPS ancora pendente.

```bash
sudo /usr/bin/timeout 140 /usr/bin/python3 -I -B -S - <<'PY'
import hashlib
import urllib.request

url = 'https://raw.githubusercontent.com/GioNob/ouf-deploy/ce3802c5bd3596cd3103ed47635cd1c344936caf/scripts/read-current-semantic-upstream-20261107.py'
with urllib.request.urlopen(url, timeout=20) as response:
    raw = response.read(16627)
if len(raw) != 16626 or hashlib.sha256(raw).hexdigest() != '2fc4d6c64e9901dbacd94f86f968c99849f31545f39933024bff540cd39da7a8':
    raise SystemExit('STOP: dimensione o SHA-256 non corrispondente')
exec(compile(raw, 'read-current-semantic-upstream-20261107.py', 'exec'), {'__name__': '__main__'})
PY
```

Riportare il JSON finale. `SEMANTIC_UPSTREAM_READ_COMPLETE` significa lettura completata, non problema risolto; gli indizi sono in `services` e `upstream`. Anche un risultato parziale può indicare il punto da correggere. Nessun riavvio automatico.

## Dopo la lettura

Correggere soltanto la causa osservata e ripetere la ricerca semantica tramite la capability. Riprendere dall'asset `c51745c5-1fc0-4d36-bdcf-1e9a8a049c94` e profilo `da3f17a2-5cbc-4d7d-9ed8-7f4b39a00342`, senza un nuovo upload. F2 applicativo UDP e F3–F6 restano aperti.
