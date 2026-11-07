# Avvio applicativo del Semantic Registry

## Blocco osservato

La [ricevuta VPS delle 18:18:23 UTC del 7 novembre](../evidence/semantic-no-java-operator-20261107.json) mostra `sh` e `sleep`, zero Java e nessun listener sulla porta 8080 della rotta semantica. DNS risolve il registro corretto. L'avviatore precedente considerava sufficiente il container running anche quando l'applicazione non era partita.

Il [comando di attesa conservato](https://github.com/GioNob/ouf-deploy/blob/969ba8e293a20b81595985920c96c447f4847174/tools/semantic_application_cutover/gated_creation_plan.py) attende `SIGUSR1`, poi esegue `java -XX:MaxRAMPercentage=75 -jar /app/application.jar`. Non si sostituisce l'immagine e non si ricostruisce il container.

## Azione concreta

Il modo `semantic` dell'avviatore verifica i riferimenti conservati, inclusi i container sostitutivi Onboarding/UDP. Prima dell'invio verifica sul VPS l'esatto comando di attesa, il processo originale, UID 10001, privilegi, gestione di SIGUSR1 e generazione. Se non corrispondono, si ferma senza segnale.

Registra il tentativo e invia una sola volta `SIGUSR1` al container Semantic già acceso. Attende che Java sostituisca la shell nello stesso PID e che `/actuator/health/readiness` risponda 200/UP sulla porta 8080. Se Java è già avviato esegue soltanto la verifica di readiness. La normale inizializzazione dell'applicazione può accedere al database; lo script non esegue SQL diretto.

L'attesa della readiness è limitata a 150 secondi. Un esito incerto dell'invio non viene ripetuto sulla stessa generazione. Un fallimento non innesca rollback o riavvio automatico; il JSON include stato e categorie del log di avvio, senza log grezzi o credenziali.

Anche `e2e` usa questa verifica e avvia Semantic dopo Gateway owner, APISIX e Caddy. Onboarding/UDP restano con i marker SeaweedFS. [Prove locali e limiti](../evidence/semantic-application-start-preparation-20261107.json).

## Comando unico sul VPS

**Avvio applicativo effettivo, non sola lettura.** Codice `50561024b2bfdb7055514e132ee04690a35f835b`, 26061 byte, SHA-256 `cc8a6325ce860736142012fe61fa7110c1ae189a48a1484bee7ee4b3d4daed55`. Test locali PASS, inclusa prova shell→applicazione nello stesso PID e regressioni dei due marker storage. Nessuna nuova build necessaria; esecuzione VPS ancora pendente.

```bash
sudo /usr/bin/timeout 420 /usr/bin/python3 -I -B -S - <<'PY'
import hashlib
import sys
import urllib.request

url = 'https://raw.githubusercontent.com/GioNob/ouf-deploy/50561024b2bfdb7055514e132ee04690a35f835b/scripts/ouf-runtime-20261107.py'
with urllib.request.urlopen(url, timeout=20) as response:
    raw = response.read(26062)
if len(raw) != 26061 or hashlib.sha256(raw).hexdigest() != 'cc8a6325ce860736142012fe61fa7110c1ae189a48a1484bee7ee4b3d4daed55':
    raise SystemExit('STOP: dimensione o SHA-256 non corrispondente')
sys.argv = ['ouf-runtime-20261107.py', 'semantic']
exec(compile(raw, 'ouf-runtime-20261107.py', 'exec'), {'__name__': '__main__'})
PY
```

Risultato atteso: **`OUF_SEMANTIC_APPLICATION_READY`**, `semanticProcessAfter=APPLICATION_RUNNING`, `semanticReadinessUp=true`, `semanticJavaIsContainerInit=true`. Incollare il JSON anche se l'esito è HELD; non rilanciare alla cieca.

## Verifica successiva

Dopo il successo, ripetere la ricerca semantica tramite MCP. Readiness non dimostra che policy, token o ricerca funzionino. Proseguire dall'asset `c51745c5-1fc0-4d36-bdcf-1e9a8a049c94` e profilo `da3f17a2-5cbc-4d7d-9ed8-7f4b39a00342`, senza nuovo upload. F2 applicativo UDP e percorso fino al grafo ancora aperti.
