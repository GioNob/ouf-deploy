# Registro semantico: processo e porta in ascolto

## Evidenza corrente

La [lettura operatore delle 18:10:35 UTC del 7 novembre](../evidence/semantic-upstream-dns-pass-tcp-fail-operator-20261107.json) ha verificato:
- Semantic, APISIX e Gateway owner running, con immagini conservate.
- Nome upstream corrispondente al registro; DNS risolve soltanto il suo indirizzo.
- Connessione TCP alla porta configurata non riuscita dalla rete APISIX, anche usando direttamente l'indirizzo del registro.
- Un indizio `connectionRefused` nei log APISIX, senza correlazione alla singola chiamata; nessun log Semantic negli ultimi 30 minuti.

La prima lettura non mostrava porta numerica, processi o socket. Non prova ancora se Java manchi, usi una porta diversa, ascolti soltanto su localhost o sia irraggiungibile per un altro motivo. Il sorgente conservato `eccef11a…` dichiara Java con `/app/application.jar` e porta `${PORT:8080}`: sono valori del sorgente, non una verifica dell'esecuzione attuale.

## Lettura estesa v2

Lo stesso script, aggiornato, aggiunge confronto tra avvio del container e dell'immagine, tipi dei processi presenti, numero di processi Java, proprietà di porta/indirizzo selezionate da env/JSON/JVM, listener TCP IPv4/IPv6 e appartenenza dei socket a Java. Non stampa argomenti grezzi, credenziali o log grezzi. Lo snapshot di processi/socket non è atomico; la stabilità dell'elenco processi è indicata nel risultato.

Conserva una GET delle rotte APISIX, la verifica DNS/TCP e i conteggi di categorie dei log. Nessun avvio/stop, cambio di configurazione o permessi, richiesta di business, SQL o S3. [Preparazione e limiti](../evidence/semantic-process-read-preparation-20261107.json).

## Comando unico sul VPS

Commit `d4aa038f57c874666c2d619c08c5018b370b7272`, 24720 byte, SHA-256 `22e67557cf3d6b453ba15e2d72cb04139edc8b2d4d75325dec9fc6a5c387b07a`. Test locali della lettura e delle nuove proiezioni PASS; esecuzione VPS pendente.

```bash
sudo /usr/bin/timeout 160 /usr/bin/python3 -I -B -S - <<'PY'
import hashlib
import urllib.request

url = 'https://raw.githubusercontent.com/GioNob/ouf-deploy/d4aa038f57c874666c2d619c08c5018b370b7272/scripts/read-current-semantic-upstream-20261107.py'
with urllib.request.urlopen(url, timeout=20) as response:
    raw = response.read(24721)
if len(raw) != 24720 or hashlib.sha256(raw).hexdigest() != '22e67557cf3d6b453ba15e2d72cb04139edc8b2d4d75325dec9fc6a5c387b07a':
    raise SystemExit('STOP: dimensione o SHA-256 non corrispondente')
exec(compile(raw, 'read-current-semantic-upstream-20261107.py', 'exec'), {'__name__': '__main__'})
PY
```

Riportare il JSON, in particolare `semanticProcess` e `upstream`. `SEMANTIC_UPSTREAM_READ_COMPLETE` indica una lettura completa, non una correzione. Schema atteso: `ouf.current-semantic-upstream-read.v2`.

## Prossimo intervento

Scegliere la correzione dal processo e dai listener effettivamente osservati; poi ripetere la ricerca semantica tramite capability. Non modificare DNS soltanto perché lo storico del 16 ottobre conteneva un errore DNS: oggi il nome risolve correttamente. Onboarding e UDP restano su SeaweedFS; normale operazione lake UDP e E2E fino al grafo ancora aperti. Riprendere dal CSV già profilato, senza nuovo upload.
