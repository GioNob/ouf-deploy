# Lettura corrente della policy Semantic

**Stato: controllo preparato e verificato localmente; esecuzione VPS pendente.** Semantic è ora avviato nello stesso container e con la stessa immagine, Java come processo init e readiness HTTP 200/UP. La ricerca MCP successiva risponde **403 `SEM_READ_RECEIPT_OR_POLICY_DENIED`**. [Avvio](../evidence/semantic-application-ready-operator-20261107.json) · [Ricerca e analisi del codice](../evidence/semantic-ready-search-denial-20261107.json).

## Domanda che il controllo risolve

Il codice installato accorpa il rifiuto della ricevuta firmata e della policy locale. Il grant admin per `ouf.semantic.search` è già presente nel catalogo letto. Prima di modificare permessi, verificare il canale di caricamento della policy: dichiarazioni correnti, token effettivamente visto dal container e risposta del suo endpoint.

L'avviatore corrente non include un servizio di rinnovo token Semantic nella propria lista `TOKEN_SERVICES`. Questo è un fatto del codice, non prova dell'assenza di qualsiasi rinnovo sul VPS né della causa del 403.

Il lettore:
- riusa i controlli esatti di configurazione Semantic e dipendenze del runtime helper già eseguito;
- legge solo i campi selezionati da ambiente, JSON e argomenti; si ferma se confliggono, senza dichiararli configurazione Spring effettiva;
- legge il token tramite `/proc/PID/root` dal mount readonly del container, controlla se coincide ancora col file sorgente host e restituisce metadati/scadenza, mai token o claim completi;
- controlla soltanto la forma della chiave di delega montata; non firma né verifica una ricevuta;
- effettua **un solo GET HTTPS**, senza redirect o retry, all'endpoint di policy già dichiarato dalla configurazione verificata, usando quel token;
- non richiede nuovi token, non installa policy, non cambia permessi, non riavvia servizi, non invia richieste di business, SQL o S3.

La GET usa il trasporto HTTPS dell'host. Anche un 200 non dimostra il trasporto JVM o la policy caricata in memoria da Semantic. Il controllo non legge il database direttamente; il normale servizio di autorizzazione può accedervi per rispondere.

## Comando corrente

Commit `3612761e4fe2e33c0bfd8823a6e8b98f55aafe2d`; lettore 13307 byte, SHA-256 `28c17fd6fd7611efbcb5307644be0d2f44e0b745652f79bc0d70eeaedb8763d5`. Helper 30554 byte, SHA-256 `b3acd99dd437ebb454a5ba5550dd20fe222f3b1dc9de839627af21dabe77563b`. [Test e limiti](../evidence/semantic-current-policy-read-preparation-20261107.json).

```bash
sudo /usr/bin/timeout 150 /usr/bin/python3 -I -B -S - <<'PY'
import hashlib
import urllib.request

base = 'https://raw.githubusercontent.com/GioNob/ouf-deploy/3612761e4fe2e33c0bfd8823a6e8b98f55aafe2d/scripts/'
files = [
    ('ouf-runtime-20261107.py', 30554, 'b3acd99dd437ebb454a5ba5550dd20fe222f3b1dc9de839627af21dabe77563b'),
    ('read-current-semantic-policy-20261107.py', 13307, '28c17fd6fd7611efbcb5307644be0d2f44e0b745652f79bc0d70eeaedb8763d5'),
]
sources = {}
for name, size, expected in files:
    with urllib.request.urlopen(base + name, timeout=20) as response:
        raw = response.read(size + 1)
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != expected:
        raise SystemExit('STOP: dimensione o SHA-256 non corrispondente')
    sources[name] = raw
runtime = {'__name__': 'retained_runtime_reader'}
exec(compile(sources[files[0][0]], files[0][0], 'exec'), runtime)
exec(compile(sources[files[1][0]], files[1][0], 'exec'),
     {'__name__': '__main__', 'RUNTIME_READER': runtime})
PY
```

Incollare il JSON, incluso un eventuale `READ_INCOMPLETE`. Non rilanciare l'avvio Semantic: ha già avuto successo.

## Lettura degli esiti

| Esito | Passo successivo |
| --- | --- |
| Token scaduto e GET 401 | Riparare il rinnovo del token esattamente montato, poi osservare il refresh normale e riprovare la ricerca. Non prova da solo che ogni controllo della ricevuta passerà. |
| GET 403 | Diagnosticare l'identità di servizio e il suo permesso di leggere la policy; non ampliare il grant umano di ricerca. |
| GET 200 con policy corrente | Il token e il GET host funzionano; occorre distinguere refresh JVM, policy in memoria e ricevuta della richiesta reale. |
| Errore TLS/trasporto host | Non attribuirlo alla JVM; verificare il percorso applicativo prima di cambiare trust o rete. |
| File sorgente diverso dal mount | Verificare una possibile rotazione invisibile al container, conservando entrambi i riferimenti. |
| Dichiarazioni mancanti o confliggenti | Leggere soltanto l'ulteriore sorgente di configurazione indicata; non inventare una precedenza. |

Le differenze `Config.MacAddress` su Onboarding/UDP restano visibili. Il modo `e2e` conserva il confronto completo e può ancora fermarsi: nessuna impronta è stata riscritta.
