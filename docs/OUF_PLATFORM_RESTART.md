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
