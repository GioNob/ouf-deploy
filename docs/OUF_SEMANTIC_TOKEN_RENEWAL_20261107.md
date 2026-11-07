# Ripristino del rinnovo del token Semantic

**Preparato e verificato localmente; esecuzione VPS pendente.**

La [ricevuta delle 18:52:14 UTC del 7 novembre](../evidence/semantic-current-policy-expired-token-operator-20261107.json) prova che il token letto dal mount del container è scaduto alle **23:08:50 UTC del 6 novembre** e coincide con la sorgente host. Un GET all'endpoint configurato della policy usando quel token termina **401**. Semantic continua a eseguire Java. La chiave di delega ha formato valido, ma nessuna ricevuta di richiesta è stata verificata.

È un guasto concreto nel canale di caricamento della policy; non prova che sia l'unica causa del 403 `SEM_READ_RECEIPT_OR_POLICY_DENIED`. Il trasporto della prova è quello HTTPS dell'host, non quello della JVM.

## Azione

Il comando verifica prima l'esatta configurazione corrente Semantic. Legge i metadati del servizio `ouf-policy-token@semantic.service`, del suo timer, il programma installato e la configurazione selezionata. Lo storico identifica quel produttore ma **non ne prova lo stato odierno**: il comando ammette solo la sorgente già osservata, SHA-256 `728b4c44d0e24b3c3bfc31769346c0c05752e870e93c096fac1c2897250e5c79`, unità root oneshot non mascherata, nessun hook aggiuntivo e timer esistente a un minuto.

Confronta output del produttore, mount corrente, gruppo, issuer, client e scope del token montato. I claim decodificati sono metadati, non una verifica locale della firma. I valori restano privati. Un programma cambiato, un servizio mascherato, una destinazione diversa o uno stato non supportato causano HELD prima degli effetti.

Se il token è ancora scaduto o ha meno di 60 secondi residui:
1. Registra un tentativo esclusivo in `/var/lib/ouf-storage-migration/semantic-policy-renewals/`.
2. Invoca una sola volta il servizio di rinnovo esistente; il produttore può richiedere un nuovo token.
3. Rilegge il token dal mount e richiede più di 60 secondi residui; effettua un solo GET della policy.
4. Solo dopo HTTP 200 e risposta policy valida abilita/avvia il timer esistente. Attende l'intervallo normale di refresh Semantic più due secondi (32 secondi con la configurazione osservata).

Se trova già un token sufficientemente fresco, riusa quello senza invocare manualmente il produttore. Non crea nuovi servizi o identità, non cambia grant/configurazione applicativa, non riavvia Semantic e non tocca S3 o SQL diretto. Il timer abilitato effettuerà i successivi rinnovi secondo la sua configurazione.

Un errore dopo il dispatch non autorizza un nuovo tentativo automatico sullo stesso token. Conservare il JSON e il file privato di tentativo; nessun rollback o reset.

## Comando attuale

Codice `591041c8c546c17cee56b129b1a5c908215cbfc0`; file 16776 byte, SHA-256 `83fd7fae0d400bed243388166db529376e2b846db82870b62486d96a6049c21d`. [Preparazione e test](../evidence/semantic-existing-token-renewal-preparation-20261107.json).

```bash
sudo /usr/bin/timeout 300 /usr/bin/python3 -I -B -S - <<'PY'
import hashlib
import urllib.request

base = 'https://raw.githubusercontent.com/GioNob/ouf-deploy/591041c8c546c17cee56b129b1a5c908215cbfc0/scripts/'
files = [
    ('ouf-runtime-20261107.py', 30554, 'b3acd99dd437ebb454a5ba5550dd20fe222f3b1dc9de839627af21dabe77563b'),
    ('read-current-semantic-policy-20261107.py', 13307, '28c17fd6fd7611efbcb5307644be0d2f44e0b745652f79bc0d70eeaedb8763d5'),
    ('restore-current-semantic-policy-token-20261107.py', 16776, '83fd7fae0d400bed243388166db529376e2b846db82870b62486d96a6049c21d'),
]
sources = {}
for name, size, expected in files:
    with urllib.request.urlopen(base + name, timeout=20) as response:
        raw = response.read(size + 1)
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != expected:
        raise SystemExit('STOP: dimensione o SHA-256 non corrispondente')
    sources[name] = raw
runtime = {'__name__': 'retained_runtime_reader'}
policy = {'__name__': 'current_policy_reader'}
exec(compile(sources[files[0][0]], files[0][0], 'exec'), runtime)
exec(compile(sources[files[1][0]], files[1][0], 'exec'), policy)
exec(compile(sources[files[2][0]], files[2][0], 'exec'),
     {'__name__': '__main__', 'RUNTIME_READER': runtime, 'POLICY_READER': policy})
PY
```

Esito atteso: `SEMANTIC_TOKEN_RENEWED_POLICY_GET_OK_TIMER_ACTIVE`. Incollare il JSON anche in caso HELD; non rilanciare alla cieca.

## Verifica successiva e limiti

Riprovare `semantic.search(q=teatro, limit=20)` tramite MCP dopo l'esito positivo. Il comando non prova la policy in memoria della JVM, la ricevuta firmata, un intero ciclo automatico di rinnovo o l'E2E. Se la ricerca resta 403, distinguere quei controlli con evidenza della richiesta reale.

I test locali usano un produttore sintetico e systemd/HTTP simulati: verificano i binding, l'ordine degli effetti, i dinieghi, il riuso di un token fresco, l'assenza di retry e la non divulgazione. Non sono una prova del servizio sul VPS.

Il tema MacAddress conserva il [precedente recuperato](OUF_LEARNED_CONTAINER_MAC_INVARIANTS.md); questo intervento non modifica guard, impronte o reti.
