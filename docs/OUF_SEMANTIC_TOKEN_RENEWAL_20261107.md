# Ripristino del rinnovo del token Semantic

**Correzione del produttore selezionato. Preparato e verificato localmente; esecuzione VPS pendente.**

## Risultato del comando precedente

La [ricevuta delle 19:06:36 UTC](../evidence/semantic-legacy-token-renewal-held-operator-20261107.json) termina HELD: `ouf-policy-token@semantic.service` e timer sono masked/inactive. Nessun avvio, abilitazione o GET policy eseguito. Il token resta scaduto alle 23:08:50 UTC del 6 novembre.

Il precedente script `restore-current-semantic-policy-token-20261107.py` selezionava il produttore sbagliato. **È superato; non rilanciarlo e non smascherare le unità legacy.** La [lettura del 6 novembre](../evidence/storage-runtime-writer-metadata-operator-20261106.json) distingueva già la coppia legacy mascherata dal produttore operativo `ouf-registry-token-7cb59501000058b5dc5030ad.service`, attivo/running/enabled. La [continuazione della cattura](../evidence/storage-host-continuation-success-operator-20261107.json) registra `registryDisabledAndStopped=true`. L'avviatore generale attuale ripristina cinque altri produttori e omette questo servizio. Queste evidenze erano disponibili e avrebbero dovuto essere lette prima del comando precedente.

## Azione corretta

Riavviare il **servizio operativo continuo già installato**, poi ripristinarne l'abilitazione al boot. Non è una nuova installazione né il ripristino del timer legacy.

Il comando controlla la configurazione conservata di Semantic, la review operativa già installata, gli hash della configurazione e dell'unità, il comando caricato da systemd e la corrispondenza fra output del produttore e token montato. Verifica issuer/client/scope come metadati; non presenta la decodifica dei claim come verifica della firma.

Legge il registro dei tentativi senza modificarlo. Prima di avviare si ferma su BLOCKED/REVOKED o su DISPATCHING/PUBLISHING di un processo fermo: non cancella esiti incerti e non azzera contatori. Il produttore esistente effettua i propri controlli firmati e gestisce rinnovi, contatori, frequenza e backoff.

1. Mantiene entrambe le unità legacy mascherate/inattive.
2. Se il produttore corretto è fermo, registra un tentativo privato esclusivo ed esegue un solo `systemctl start`. Se è già attivo, osserva senza riavviarlo.
3. Attende al massimo 90 secondi una pubblicazione ACTIVE, token montato con oltre 60 secondi residui e hash uguale a quello registrato dal produttore.
4. Esegue un solo GET della policy, dal trasporto HTTPS dell'host.
5. Solo dopo HTTP 200 e risposta policy valida abilita il medesimo servizio al boot, se disabilitato. Attende il refresh dichiarato di Semantic più due secondi.

Il programma non legge il client secret, non cambia grant, configurazione applicativa, reti o container e non emette credenziali. Il produttore riattivato può leggere la propria credenziale, richiedere token e aggiornare il proprio registro. Un HELD dopo l'avvio **può lasciare il produttore in esecuzione**: conservare l'esito, non rilanciare alla cieca e non resettare file o contatori.

## Comando attuale

Codice [`1d0a93a9`](https://github.com/GioNob/ouf-deploy/commit/1d0a93a9dbb3dd1a3f26a9fa92c71af841427084); script 12441 byte, SHA-256 `f99d29dfe5be132e448a0f64293729d6ada4665965856c1bdece04ec0dc38f5e`. [Preparazione](../evidence/semantic-operational-owner-resume-preparation-20261107.json).

```bash
sudo /usr/bin/timeout 360 /usr/bin/python3 -I -B -S - <<'PY'
import hashlib
import urllib.request

base = 'https://raw.githubusercontent.com/GioNob/ouf-deploy/1d0a93a9dbb3dd1a3f26a9fa92c71af841427084/scripts/'
files = [
    ('ouf-runtime-20261107.py', 30554, 'b3acd99dd437ebb454a5ba5550dd20fe222f3b1dc9de839627af21dabe77563b'),
    ('read-current-semantic-policy-20261107.py', 13307, '28c17fd6fd7611efbcb5307644be0d2f44e0b745652f79bc0d70eeaedb8763d5'),
    ('observe-registry-operational-owner-20261024.py', 10724, '92da54e145df58f929c5aaa383f14b7a81bc742b173182a3a66d02232abb1760'),
    ('resume-current-semantic-operational-owner-20261107.py', 12441, 'f99d29dfe5be132e448a0f64293729d6ada4665965856c1bdece04ec0dc38f5e'),
]
sources = []
for name, size, expected in files:
    with urllib.request.urlopen(base + name, timeout=20) as response:
        raw = response.read(size + 1)
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != expected:
        raise SystemExit('STOP: dimensione o SHA-256 non corrispondente')
    sources.append(raw)
helpers = []
for (name, _, _), raw in zip(files[:3], sources[:3]):
    namespace = {'__name__': 'read_only_helper'}
    exec(compile(raw, name, 'exec'), namespace)
    helpers.append(namespace)
exec(compile(sources[3], files[3][0], 'exec'), {
    '__name__': '__main__', 'RUNTIME_READER': helpers[0],
    'POLICY_READER': helpers[1], 'OWNER_READER': helpers[2]})
PY
```

Esito atteso: `SEMANTIC_OPERATIONAL_OWNER_ACTIVE_TOKEN_FRESH_POLICY_GET_OK`. Incollare il JSON anche in caso HELD.

## Cosa resta da provare

Dopo il successo riprovare `semantic.search(q=teatro, limit=20)` tramite MCP. Il GET host 200 non prova il caricamento della policy nella JVM o la verifica della ricevuta della richiesta. Il 403 `SEM_READ_RECEIPT_OR_POLICY_DENIED` resta aperto fino alla prova applicativa. Il singolo rinnovo non certifica un ciclo automatico successivo.

I 13 scenari locali usano systemd/HTTP simulati: avvio del produttore corretto, riuso se attivo, produttore legacy invariato, binding errato, comando differente, stati incerti del registro, deriva applicativa, avvio fallito e policy 401. Nessuna esecuzione VPS locale.

Dopo la verifica live, integrare questo servizio continuo nel percorso generale di ripartenza senza trattarlo come uno dei cinque timer. Resta inoltre aperto il confronto [MacAddress](OUF_LEARNED_CONTAINER_MAC_INVARIANTS.md): questo intervento non modifica impronte o guard dei container.
