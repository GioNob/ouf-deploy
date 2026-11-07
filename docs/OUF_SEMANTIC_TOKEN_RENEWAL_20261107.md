# Ripristino del rinnovo del token Semantic

**Versione 3 preparata e verificata localmente; esecuzione VPS pendente.**

## Stato verificato

Semantic esegue Java nello stesso container/immagine, readiness 200/UP. Il token montato per leggere la policy è scaduto; GET policy401. Il produttore operativo `ouf-registry-token-7cb59501000058b5dc5030ad.service` è stato fermato/disabilitato dalla cattura, che ha lasciato l'esatto override con Restart=no. Le unità legacy `ouf-policy-token@semantic.service/.timer` restano mascherate.

La [diagnosi delle 20:56:29 CET](../evidence/semantic-systemd-get-unit-not-loaded-operator-20261107.json) prova che fallisce **GetUnit**, exit1: unità non caricata. Nessuna proprietà degli hook letta e nessun effetto. La v2 dipendeva quindi da un'unità già presente in memoria dopo la chiusura di un altro client. Il tempo preciso di scaricamento non è stato osservato.

La [documentazione systemd](https://www.freedesktop.org/software/systemd/man/260/systemd.unit.html#Unit%20Garbage%20Collection) descrive lo scaricamento delle unità inattive non referenziate. [GetUnit e LoadUnit](https://github.com/systemd/systemd/blob/v252/man/org.freedesktop.systemd1.xml) hanno semantiche distinte. Il successo delle precedenti simulazioni D-Bus non era una prova del comportamento VPS.

## Correzione v3

Il controllo degli hook usa la configurazione già verificata, senza chiamate D-Bus dirette:

- unità principale vincolata alla review e al relativo SHA-256;
- elenco completo dei drop-in riportato da systemd, lettura e confronto di ogni file;
- NeedDaemonReload=no, comando effettivo corrispondente alla review e nessun hook testuale non vuoto;
- verifica esplicita che nessun file dichiari ExecStartPre, ExecStartPost o ExecCondition;
- nei drop-in sono ammessi solo la sezione Service e le direttive già previste di rete/cattura: IPAddressAllow, Restart, SendSIGKILL, RuntimeDirectoryPreserve, TimeoutStopSec. Continuazioni, codifiche o direttive non gestite causano HELD.

L'assenza di un campo nell'output testuale non è usata come prova. Il rapporto esplicita lo scope `HASH_PINNED_MAIN_UNIT_ALL_LOADED_DROPINS_NO_PENDING_RELOAD`. I file sono riletti prima dell'avvio e dell'abilitazione.

## Effetti e ordine

1. Controlla Semantic, configurazione installata del produttore, output del token montato e registro dei tentativi. BLOCKED/REVOKED o esiti incerti di un processo fermo impediscono modifiche.
2. Se il produttore è fermo, registra un solo tentativo privato. Per l'esatto override di cattura conserva una copia privata, rimuove solo quel file e ricarica systemd. Richiede Restart=on-failure e le altre impostazioni originali; membership e byte degli altri drop-in devono restare identici.
3. Avvia il servizio continuo esistente una sola volta. Se è già attivo senza override di cattura, osserva senza riavviarlo.
4. Attende al massimo 90 secondi pubblicazione ACTIVE, token montato con oltre 60 secondi residui e hash coincidente col registro del produttore. Esegue un solo GET policy tramite HTTPS dell'host.
5. Solo dopo policy200 e risposta valida abilita lo stesso servizio al boot e attende il normale refresh Semantic più due secondi.

Il produttore può richiedere token e aggiornare il proprio registro; lo script non lo azzera. Non modifica grant, configurazione applicativa, reti o container. Un HELD dopo gli effetti può lasciare l'override rimosso o il produttore avviato: conservare il JSON e non rilanciare alla cieca.

## Comando attuale

Codice [`c30f8c28`](https://github.com/GioNob/ouf-deploy/commit/c30f8c287bf4bb78cc07d73e18407eb019eec66e), script 19129 byte, SHA-256 `32fc3f89772e16877654bf6fdab647ec2cf0307e1ced1a406e8314998f510295`. [Preparazione](../evidence/semantic-operational-owner-resume-preparation-20261107.json).

```bash
sudo /usr/bin/timeout 360 /usr/bin/python3 -I -B -S - <<'PY'
import hashlib
import urllib.request

base = 'https://raw.githubusercontent.com/GioNob/ouf-deploy/c30f8c287bf4bb78cc07d73e18407eb019eec66e/scripts/'
files = [
    ('ouf-runtime-20261107.py', 30554, 'b3acd99dd437ebb454a5ba5550dd20fe222f3b1dc9de839627af21dabe77563b'),
    ('read-current-semantic-policy-20261107.py', 13307, '28c17fd6fd7611efbcb5307644be0d2f44e0b745652f79bc0d70eeaedb8763d5'),
    ('observe-registry-operational-owner-20261024.py', 10724, '92da54e145df58f929c5aaa383f14b7a81bc742b173182a3a66d02232abb1760'),
    ('resume-current-semantic-operational-owner-20261107.py', 19129, '32fc3f89772e16877654bf6fdab647ec2cf0307e1ced1a406e8314998f510295'),
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

## Verifica e limiti

25 scenari locali PASS: file temporanei reali per ripristino/conservazione degli override, systemd/HTTP simulati, rifiuto di hook aggiunti, direttive inattese, sintassi non gestita e ricarica pendente. Qualsiasi chiamata subprocess diretta non prevista, incluso busctl, fallisce il test. Nessuna prova VPS è già attestata.

Dopo successo riprovare `semantic.search(q=teatro, limit=20)` via MCP. GET host200 non prova la policy caricata nella JVM o la ricevuta di delega; il 403 resta aperto fino alla prova applicativa. Restano da verificare un rinnovo automatico successivo e l'integrazione del servizio continuo nell'avviatore generale.

## Ricevute precedenti

[Legacy mascherato, nessun effetto](../evidence/semantic-legacy-token-renewal-held-operator-20261107.json) · [Metadati incompleti, nessun effetto](../evidence/semantic-operational-owner-metadata-held-operator-20261107.json) · [D-Bus fallito, nessun effetto](../evidence/semantic-operational-owner-dbus-held-operator-20261107.json). Le vecchie procedure restano storiche; il comando corrente è soltanto quello sopra. La [lezione MAC](OUF_LEARNED_CONTAINER_MAC_INVARIANTS.md) resta valida e non viene modificata da questo intervento.
