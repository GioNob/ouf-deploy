# Riavvio governato della piattaforma

D-063 / R-039. L’operatore approva un plan per avviare o fermare i container già presenti. Al boot l’unità costruisce e verifica un nuovo plan di start. Il provider R3 conserva il proprio operatore di lifecycle. Prima dello stop della piattaforma, fermare R3 con quella procedura e attenderne l’arresto.

## Preparare il profilo privato

Compilare i nomi esatti dall’inventario dell’installazione. Inserire i due nomi R3 in `governedElsewhere`. I nomi devono essere univoci tra tutti i livelli e le esclusioni. Il validatore rifiuta i nomi gestiti contenenti `retained`, `retired` o `before-`, anche con maiuscole. Il controller richiede di poter identificare anche i container esclusi.

| Livello | Ruoli osservati nell’installazione di riferimento |
| --- | --- |
| 1 | PostgreSQL, object storage, staging, etcd del Gateway |
| 2 | IAM |
| 3 | I due lettori delle evidenze |
| 4 | Gateway e proxy di frontiera |
| 5 | Owner operativo del Gateway, Onboarding, UDP, Ingestion |
| 6 | Semantic Registry |
| 7 | Server MCP |

Lo schema pubblico è [platform-restart-profile-v1.schema.json](../contracts/platform-restart-profile-v1.schema.json). Il frammento seguente mostra un livello con i tre tipi di controllo. Espandere `levels` secondo le dipendenze dell’installazione. Sostituire i segnaposto numerici con interi JSON. Calcolare il digest sui byte definitivi del profilo.

```json
{
  "schema": "ouf.platform-restart-profile.v1",
  "docker": {"path": "<ESEGUIBILE_DOCKER>", "sha256": "<SHA256_DOCKER>"},
  "dockerSocket": "<PERCORSO_SOCKET_UNIX>",
  "receipts": "<DIRECTORY_RICEVUTE>",
  "incidents": "<DIRECTORY_INCIDENTI>",
  "inventoryTimeoutSeconds": "<SECONDI_INVENTARIO>",
  "stopTimeoutSeconds": "<SECONDI_STOP>",
  "bootRetryDelaysSeconds": ["<PRIMA_ATTESA>", "<SECONDA_ATTESA>"],
  "governedElsewhere": ["<ADAPTER_R3>", "<SOUTHBOUND_R3>"],
  "levels": [
    {
      "timeoutSeconds": "<SECONDI_LIVELLO>",
      "containers": [
        {"containerName": "<NOME_A>", "readiness": {"type": "running", "stableSeconds": "<SECONDI_STABILITA>"}},
        {"containerName": "<NOME_B>", "readiness": {"type": "healthy"}},
        {"containerName": "<NOME_C>", "readiness": {"type": "tcp", "network": "<NOME_RETE>", "port": "<PORTA>", "timeoutSeconds": "<SECONDI_CONNESSIONE>"}}
      ]
    }
  ]
}
```

Usare percorsi assoluti canonici, privi di symlink, spazi o metacaratteri. Preparare directory dedicate distinte per ricevute e incidenti, root e modo 0700. Preparare il profilo privato in custodia root. Il socket locale può consentire l’accesso al gruppo Docker. Eseguibili, sorgenti installati e antenati dei percorsi devono essere protetti dalla scrittura di utenti ordinari. Scegliere percorsi visibili all’unità con `ProtectHome=yes` e `PrivateTmp=yes`. Fornire la directory delle unità locali presente nel percorso di ricerca di systemd.

## Installare e qualificare lo start presidiato

Usare una shell autorizzata come root e una copia locale verificata del repository. Dopo la review Claude compila lo stesso pin di consegna nei due runbook. I runbook confrontano i SHA-256 dei file consegnati con i blob del commit e usano questi ultimi per la copia di lavoro temporanea. Tutte le operazioni successive usano il profilo installato.

```bash
export OUF_PYTHON='<PERCORSO_PYTHON_3_13>'
export OUF_INSTALL_ROOT='<DIRECTORY_INSTALLAZIONE>'
install_args=(--dest "$OUF_INSTALL_ROOT" --profile '<PROFILO_PRIVATO>'
  --profile-sha256 '<SHA256_PROFILO_VERIFICATO>' --unit-dir '<DIRECTORY_UNITA_SYSTEMD>'
  --systemctl '<ESEGUIBILE_SYSTEMCTL>' --checksum '<ESEGUIBILE_SHA256SUM>')
bash ops/vps/platform-restart-install.sh plan "${install_args[@]}"
bash ops/vps/platform-restart-install.sh apply "${install_args[@]}" --plan-sha256 '<DIGEST_PLAN_INSTALLAZIONE>'
bash ops/vps/platform-restart.sh plan start
bash ops/vps/platform-restart.sh apply start '<DIGEST_PLAN_START>'
```

L’installazione pubblica l’archivio Python, il profilo, i binding e l’unità, esegue `daemon-reload` e verifica che l’unità risulti caricata e disabilitata. Il plan di installazione include l’impronta dei file sorgente e lo stato delle destinazioni. Dopo un’interruzione si può ricostruire il plan per completare una consegna parziale con byte identici. Un file divergente richiede riconciliazione.

Verificare nella ricevuta dell’apply presidiato `mode=apply`, `action=start`, `status=SUCCEEDED` e gli esiti dei livelli. Il campo `receipt` stampato dal comando identifica il file privato. Per attivare l’avvio al boot, passare il nome di quel file. L’installer verifica custodia, sorgente, profilo e unità prima dell’abilitazione.

```bash
bash ops/vps/platform-restart-install.sh enable --dest "$OUF_INSTALL_ROOT" --receipt '<NOME_RICEVUTA_APPLY_START>'
bash ops/vps/platform-restart-install.sh disable --dest "$OUF_INSTALL_ROOT"
```

`disable` revoca l’avvio ai boot successivi. Per fermare i servizi correnti usare lo stop presidiato. L’unità oneshot esegue il solo avvio al boot.

## Plan, apply e arresto

```bash
bash ops/vps/platform-restart.sh plan stop
bash ops/vps/platform-restart.sh apply stop '<DIGEST_PLAN_STOP>'
```

Il plan prende l’inventario con `ps` e legge con `inspect` i campi necessari. Confronta gli IPv4 attivi dei container estranei con gli indirizzi attivi o statici dei container gestiti sulla stessa rete. Questo copre il caso in cui Docker abbia già svuotato l’indirizzo attivo di un container fermo. Eventuali conflitti, nomi mancanti o ambigui compaiono in `plan.reasons`. Per ogni container gestito il plan indica livello, nome, ID completo, stato, politica di riavvio, reti, IPv4 e operazione prevista. Il digest copre la rappresentazione JSON ordinata e compatta del plan, incluso l’hash del profilo. I tempi di emissione appartengono alla ricevuta.

L’apply rilegge il plan sotto lock locale. La mutazione usa l’ID completo e ricontrolla identità e stato prima del comando. Coordinare eventuali operazioni Docker esterne nella stessa finestra presidiata. Docker applica start e stop individualmente. Un inventario concorrente che cambia può richiedere un nuovo plan.

Lo start avvia i membri mancanti del livello nell’ordine dichiarato, poi verifica tutti i membri nella stessa passata, inclusi quelli già avviati. Il controllo `running` osserva la stessa generazione in esecuzione per l’intera finestra dichiarata. `healthy` legge lo stato dell’healthcheck Docker. `tcp` prova dall’host l’IPv4 attivo della rete dichiarata entro il minore tra timeout della sonda e tempo residuo. Lo stop percorre i livelli all’indietro, usa il timeout di terminazione del profilo e legge lo stato dopo ogni arresto. Dimensionare il timeout di ciascun livello anche per gli stop sequenziali.

Al primo errore l’apply manuale termina con `HELD` e conserva il lavoro già eseguito. Se scade il timeout del client Docker, l’esito del comando va riosservato sul daemon. Nella ricevuta sono disponibili motivo, livello, container, operazioni ed esiti. Per riprendere, correggere la causa e produrre un nuovo plan.

## Moduli con avvio a cancello

Il 20 novembre 2026 Semantic è rimasto fermo per 73 minuti dopo un `docker restart`. Docker vedeva il container in esecuzione. Il PID 1 era ancora la shell in attesa di USR1. Durante un upgrade questo intervallo consente all’owner di completare la migrazione prima dell’avvio dell’applicazione.

Le cinque voci seguenti sono un esempio per gli array `containers` dei rispettivi livelli. Mantenere l’ordine delle dipendenze dell’installazione. Sostituire nomi e ID immutabili delle immagini con quelli qualificati per ciascun modulo e verificare porta, budget e array del comando.

```json
[
  {
    "containerName": "example-ingestion",
    "gate": {
      "imageId": "sha256:<ID_INGESTION>",
      "entrypoint": ["/bin/sh", "-c", "OUF_APPLICATION_GATE=0; trap \"OUF_APPLICATION_GATE=1\" USR1; while [ \"$OUF_APPLICATION_GATE\" = 0 ]; do sleep 1 & wait \"$!\"; done; exec \"$@\"", "ouf-gated-application"],
      "command": ["java", "-XX:MaxRAMPercentage=75", "-jar", "/app/application.jar"]
    },
    "readiness": {"type": "actuator", "address": "127.0.0.1", "port": 8080, "path": "/actuator/health/readiness", "acceptStatus": [200], "jsonStatus": "UP", "timeoutSeconds": 2, "budgetSeconds": 60}
  },
  {
    "containerName": "example-semantic",
    "gate": {
      "imageId": "sha256:<ID_SEMANTIC>",
      "entrypoint": ["/bin/sh", "-c", "OUF_APPLICATION_GATE=0; trap \"OUF_APPLICATION_GATE=1\" USR1; while [ \"$OUF_APPLICATION_GATE\" = 0 ]; do sleep 1 & wait \"$!\"; done; exec \"$@\"", "ouf-gated-application"],
      "command": ["java", "-XX:MaxRAMPercentage=75", "-jar", "/app/application.jar"]
    },
    "readiness": {"type": "actuator", "address": "127.0.0.1", "port": 8080, "path": "/actuator/health/readiness", "acceptStatus": [200], "jsonStatus": "UP", "timeoutSeconds": 2, "budgetSeconds": 60}
  },
  {
    "containerName": "example-udp",
    "gate": {
      "imageId": "sha256:<ID_UDP>",
      "entrypoint": ["/bin/sh", "-c", "OUF_APPLICATION_GATE=0; trap \"OUF_APPLICATION_GATE=1\" USR1; while [ \"$OUF_APPLICATION_GATE\" = 0 ]; do sleep 1 & wait \"$!\"; done; exec \"$@\"", "ouf-gated-application"],
      "command": ["java", "-XX:MaxRAMPercentage=75", "-jar", "/app/application.jar"]
    },
    "readiness": {"type": "actuator", "address": "127.0.0.1", "port": 8080, "path": "/actuator/health/readiness", "acceptStatus": [200], "jsonStatus": "UP", "timeoutSeconds": 2, "budgetSeconds": 60}
  },
  {
    "containerName": "example-onboarding",
    "gate": {
      "imageId": "sha256:<ID_ONBOARDING>",
      "entrypoint": ["/bin/sh", "-c", "OUF_APPLICATION_GATE=0; trap \"OUF_APPLICATION_GATE=1\" USR1; while [ \"$OUF_APPLICATION_GATE\" = 0 ]; do sleep 1 & wait \"$!\"; done; exec \"$@\"", "ouf-gated-application"],
      "command": ["java", "-XX:MaxRAMPercentage=75", "-jar", "/app/application.jar"]
    },
    "readiness": {"type": "actuator", "address": "127.0.0.1", "port": 8080, "path": "/actuator/health/readiness", "acceptStatus": [200], "jsonStatus": "UP", "timeoutSeconds": 2, "budgetSeconds": 60}
  },
  {
    "containerName": "example-mcp",
    "gate": {
      "imageId": "sha256:<ID_MCP>",
      "entrypoint": ["/bin/sh", "-c", "OUF_APPLICATION_GATE=0; trap \"OUF_APPLICATION_GATE=1\" USR1; while [ \"$OUF_APPLICATION_GATE\" = 0 ]; do sleep 1 & wait \"$!\"; done; exec \"$@\"", "ouf-gated-application"],
      "command": ["/usr/local/bin/ouf-mcp", "server"]
    },
    "readiness": {"type": "actuator", "address": "127.0.0.1", "port": 8080, "path": "/health/ready", "acceptStatus": [204], "timeoutSeconds": 2, "budgetSeconds": 60}
  }
]
```

Il controller verifica nel namespace che il PID 1 sia la shell del cancello, con gli argomenti esatti e il gestore USR1 installato. Invia il segnale una volta al CID completo appena avviato. Dopo l’exec verifica l’intero array `gate.command` e il percorso dell’eseguibile per un comando assoluto, oppure il nome dell’eseguibile per un comando come `java`.

La sonda `actuator` esegue la GET sul loopback del container al percorso dichiarato. Accetta i codici elencati in `acceptStatus`. Se il profilo dichiara `jsonStatus`, il campo `status` dell’oggetto JSON deve avere quel valore. Per MCP basta HTTP 204, anche a corpo vuoto. Dopo la risposta il controller verifica nuovamente identità del processo e generazione. Nei profili a cancello del task-20b aggiungere i campi espliciti mostrati sopra prima di ricalcolare l’hash.

Il budget del modulo decorre dall’operazione di start o skip. Ogni GET è limitata dal tempo residuo e da `timeoutSeconds`. Dimensionare il livello per l’avvio dei suoi membri e per le sonde. In caso di scadenza la ricevuta riporta `status=HELD`, `reason=READINESS_NOT_UP`, livello e modulo. Un rifiuto di apertura riporta `reason=GATE_HELD` e il dettaglio in `gateReason`. Entrambi gli esiti fermano anche il boot. Un nuovo apply verifica l’applicazione già avviata. Una shell trovata già in attesa richiede riconciliazione con l’owner dell’upgrade, anche dopo una risposta persa al segnale.

### Comandi equivalenti in emergenza

Lavorare in una finestra esclusiva con l’owner del modulo. Verificare nel journal dell’upgrade che l’immagine sia quella già migrata e che nessun rilascio del cancello sia in corso o abbia esito incerto. Usare il CID completo della ricevuta approvata, il profilo installato e il binding Docker verificato. Questi comandi Bash mostrano i controlli per **un solo modulo Java**. Coordinare gli altri membri e i livelli con il controller.

```bash
set -euo pipefail
# PROFILE, NAME e CID provengono dal profilo e dal plan verificati.
member=$(jq -ce --arg n "$NAME" '.levels[].containers[] | select(.containerName == $n and .gate)' "$PROFILE")
d=("$(jq -er '.docker.path' "$PROFILE")" --host "unix://$(jq -er '.dockerSocket' "$PROFILE")")
[[ $CID =~ ^[a-f0-9]{64}$ ]]

# Solo per un modulo osservato fermo in stato exited nel plan.
# Se la shell è già in attesa, riconciliare journal, migrazione e generazione con l’owner.
[[ $("${d[@]}" inspect --type container --format '{{.Name}} {{.State.Status}}' "$CID") == "/$NAME exited" ]]
"${d[@]}" start "$CID"
frame() {
  "${d[@]}" inspect --type container --format \
    '[{{json .Id}},{{json .Name}},{{json .Image}},{{json .Config.Entrypoint}},{{json .Config.Cmd}},{{json .State.Status}},{{json .State.Pid}},{{json .State.StartedAt}}]' "$CID" |
    jq -ce --arg id "$CID" --argjson m "$member" \
      'select(.[:6] == [$id,("/"+$m.containerName),$m.gate.imageId,$m.gate.entrypoint,$m.gate.command,"running"] and .[6] > 1) | .[6:]'
}
generation=$(frame)
pid=$(jq -er '.[0]' <<<"$generation")
argv_matches() {
  cmp -s "/proc/$pid/cmdline" <(jq -jr "$1 | .[] | ., \"\\u0000\"" <<<"$member")
}
[[ $(awk '/^NSpid:/{print $NF}' "/proc/$pid/status") == 1 ]]
argv_matches '(.gate.entrypoint + .gate.command)'
caught=$(awk '/^SigCgt:/{print $2}' "/proc/$pid/status")
(( (16#$caught & (1 << ($(kill -l USR1) - 1))) != 0 ))
[[ $(frame) == "$generation" ]]
"${d[@]}" kill --signal=USR1 "$CID"
```

Se una verifica fallisce, fermarsi. Se manca ancora il gestore del segnale, ripetere solo le letture entro il budget. Dopo il segnale eseguire le verifiche seguenti finché riescono, entro il budget residuo del modulo. Impostare `T` al minore tra il timeout della GET e i secondi residui. Alla scadenza registrare `READINESS_NOT_UP` e fermare la sequenza.

```bash
addr=$(jq -er '.readiness.address' <<<"$member")
port=$(jq -er '.readiness.port' <<<"$member")
path=$(jq -er '.readiness.path' <<<"$member")
[[ $(frame) == "$generation" ]]
argv_matches '.gate.command'
[[ $(basename "$(readlink "/proc/$pid/exe")") == java ]]
response=$(nsenter --target "$pid" --net curl --noproxy '*' --silent --show-error \
  --max-time "$T" --max-filesize 65536 --write-out $'\n%{http_code}' "http://$addr:$port$path")
[[ ${response##*$'\n'} == 200 ]]
jq -e '.status == "UP"' <<<"${response%$'\n'*}" >/dev/null
[[ $(frame) == "$generation" ]]
argv_matches '.gate.command'
```

## Comportamento al boot

L’unità verifica i digest del sorgente installato e dell’interprete. Il driver verifica il profilo e il binding Docker. Registra in modo esclusivo il boot ID del kernel nella directory persistente delle ricevute prima del primo inventario. Una seconda invocazione nello stesso boot restituisce `BOOT_ALREADY_ATTEMPTED`. Il lock della directory serializza le operazioni del controller.

Le attese crescenti nel profilo sono intervalli fra tentativi. Ogni livello dispone di un primo tentativo e di un ulteriore tentativo per intervallo. Su errore transitorio Docker o timeout di prontezza il driver riosserva l’inventario prima di riprovare quel livello e verifica gli ID autorizzati. Un diniego di identità o di binding interrompe il ciclo. Il tempo massimo dell’unità deriva dai timeout di inventario e di livello, dai tentativi e dalle attese, con margine per l’avvio e la scrittura delle ricevute.

Un fallimento conclusivo del driver scrive `PLATFORM_BOOT_START_FAILED` nella directory degli incidenti e sul journal a priorità `err`. L’incidente contiene schema, codice, tempo, livello, container e motivo. Livello e container valgono `null` per un errore precedente all’identificazione del bersaglio. Per un errore di systemd precedente all’ingresso nel driver, consultare il journal dell’unità. Conservare il marcatore anche dopo un’interruzione e riprendere con plan e apply presidiati.

## Verifiche riproducibili

```bash
python -m unittest discover -s tests -p 'test_platform_restart*.py' -v
OUF_PLATFORM_RESTART_NATIVE=1 python -m unittest discover -s tests -p 'test_platform_restart_native.py' -v
```

La suite nativa richiede un Engine Linux locale di prova, accesso al socket e un compilatore C con libc statica. Costruisce un’immagine scratch dalla fixture locale, crea due reti di test e rimuove gli oggetti di sua creazione a fine prova. Per adattare il test locale, fornire `OUF_TEST_DOCKER_SOCKET` e `OUF_TEST_SUBNETS` (due CIDR IPv4 disponibili separati da virgola). Il workflow esegue entrambe le suite con Python 3.13 su Ubuntu ospitato da GitHub.
