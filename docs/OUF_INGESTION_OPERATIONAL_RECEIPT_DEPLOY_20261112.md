# Ingestion — deploy della ricevuta operativa, 12 novembre 2026

Stato della consegna: implementazione locale, **qualifica GitHub e installazione non eseguite**. I test unitari offline passano; non esiste ancora una ricevuta CI o VPS per questo task. Non lanciare sul VPS finché entrambi i job nativi e la build/scansione/archivio non sono verdi e revisionati.

## Perimetro e fonti

Sorgente candidato fissato: `ouf-ingestion-runtime@01756a5a22ddc88beba270b7645a64440b1e5a7b`. Il diff locale rispetto a `c85d9fd3be215e518dc6e7d075797720b5afbd91` aggiunge soltanto classi, test, vettori e `docs/R3_PRODUCER_IDENTITY.md`; nessun file esistente cambia. La build verifica anche le migrazioni effettive nel JAR contro il record storico.

Baseline attesa, da riconfermare in ogni piano: immagine `sha256:562e4c6e19d5227f00fb3159deb506da256d2245ee4a40a652b0c03865704baa`, revisione immagine `c85d9fd3be215e518dc6e7d075797720b5afbd91`, running e readiness HTTP 200. Questa è un'aspettativa fornita nel task, non una nuova osservazione live.

Sono stati letti la [catena preflight](OUF_INGESTION_WIDE_PREFLIGHT_20261108.md), l'[upgrade/resume concluso](OUF_INGESTION_WIDE_UPGRADE_20261108.md), i quattro workflow, tutti i controller/delivery e le evidenze `ingestion-wide-*-20261108.json`, oltre alla [regola MAC](OUF_LEARNED_CONTAINER_MAC_INVARIANTS.md) e al [precedente](handoffs/OUF_ACQUISITION_MAC_LESSON_AND_RETAINED_STATE_20261025.md). Questi file restano invariati. Non rieseguire gli installer dell'8 novembre.

Il nuovo controller importa soltanto la primitiva pura `retained_mac.py`, verificata per SHA-256. Il gate USR1 è copiato letteralmente dal controller storico; il compilatore CREATE è nuovo perché quello storico modifica anche label, JAVA_VERSION e argomenti. Il trasporto usa API1.44 per tutte le osservazioni e mutazioni.

## Contratto del piano

Tutti i dati d'installazione sono argomenti o osservazioni. I soli valori fissi nel controller sono il commit candidato, il protocollo del gate, i nomi delle proprietà, l'opt-in e il digest del helper. Sono supportati esclusivamente il profilo già qualificato a **una rete nominativa**, MAC legacy presente/stringa/unicast/nonzero uguale all'endpoint e restart policy `no`. Un profilo diverso dà HELD, senza adattamenti impliciti.

`--plan` non scrive file, Docker o SQL. Legge come root il file properties individuato attraverso il mount osservato e verifica:

- presenza delle cinque chiavi `ouf.summary.receipt-key-file`, `tenant-id`, `issuer`, `audience`, `workload` (tutte con prefisso `ouf.summary.`); nessun requisito di presenza per `enabled`;
- valori obbligatori non vuoti e senza placeholder irrisolti; il valore del solo `receipt-key-file` serve internamente a risolvere il mount della chiave;
- chiave in un bind read-only, file regolare esistente, 64 caratteri esadecimali dopo rimozione degli spazi esterni, come nel filtro Java;
- `SPRING_CONFIG_ADDITIONAL_LOCATION` esattamente riferito al target passato, nessun override summary diretto in ENV/argomenti o `SPRING_APPLICATION_JSON`;
- processo corrente uguale a `Config.Cmd`, gate invariato, Flyway false e schema-mode VALIDATE_ONLY espliciti e non contraddetti;
- candidato già importato, ID esatto e revisione immagine esatta; le aggiunte implicite da default dell'immagine che allargherebbero il delta sono rifiutate prima dello stop.

Le proprietà sono interpretate in memoria, senza output dei valori o salvataggio dei contenuti. Il JSON pubblico emette solo booleani per le verifiche di identità e digest per i campi privati. Se manca una chiave, `SUMMARY_PROPERTIES_MISSING` include la mappa booleana dei cinque nomi; non modifica il file e non genera valori. Non usare `cat`, `docker inspect` integrale o log applicativi nei report pubblici.

Il delta Config è **solo Image + append di `OUF_SUMMARY_ENABLED=true`**. User, working directory, label, ENV preesistenti e loro ordine, argomenti, HostConfig/limiti e mount restano esatti. Il candidato eredita dunque la vecchia label di revisione del *container*: la revisione nuova si attesta separatamente con l'inspect dell'*immagine*, senza cambiare una terza proprietà. IP, MAC, IPAM e alias osservati sono trasferiti; Engine aggiunge l'alias generato del nuovo CID, distinto dagli alias conservati. `Config.MacAddress` è conservata anche nella CREATE API1.44 e deve coincidere esattamente nel sostituto running: nessuna esclusione globale. Solo il vecchio fermo e detached può perderla secondo il helper storico. La forma `OomKillDisable:null → false` è ammessa soltanto nella cattura CREATE; nel running è richiesta uguaglianza esatta al vecchio.

Il piano lega controller/helper, parametri, identità, frame/generazione vecchia, request e immagine candidata. Esclude i contatori di health polling, che cambiano senza un cambio di deployment. `--apply` ricalcola il piano e lo rilegge ancora immediatamente prima dello stop. Hash differente: HELD senza effetti Docker. Il padre del journal deve essere root:0700; ogni tentativo esclusivo `apply-HASH` è 0700, i file 0600 con fsync. Una claim persistente per CID impedisce anche due piani concorrenti differenti sullo stesso vecchio container. Non cancellare directory, claim o intenti per riprovare.

Non sono previste letture DB: non c'è delta di migrazioni, Flyway e VALIDATE_ONLY sono preservati, e il task riguarda il trasferimento della configurazione Docker. Non si deduce invarianza delle righe DB. L'applicazione riavviata può eseguire il normale lavoro già presente, inclusi aggiornamenti del polling scheduler. Zero SQL del controller, nessun nuovo lavoro business inviato.

## 1. Qualifica e archivio, eseguiti da GitHub Actions

Claude effettua review, commit e push secondo D-001; questo task non li esegue. L'apertura/aggiornamento della PR fa partire i due nuovi workflow tramite `pull_request`. Per consultare i risultati da un terminale umano:

```bash
gh run list --repo GioNob/ouf-deploy --branch sprint-01/task-08-ingestion-operational-receipt-deploy --workflow ingestion-operational-receipt-qualify-20261112.yml
gh run list --repo GioNob/ouf-deploy --branch sprint-01/task-08-ingestion-operational-receipt-deploy --workflow ingestion-operational-receipt-archive-20261112.yml
```

Se i workflow sono già registrati nel branch predefinito, è disponibile anche il lancio manuale:

```bash
gh workflow run ingestion-operational-receipt-qualify-20261112.yml --repo GioNob/ouf-deploy --ref sprint-01/task-08-ingestion-operational-receipt-deploy
gh workflow run ingestion-operational-receipt-archive-20261112.yml --repo GioNob/ouf-deploy --ref sprint-01/task-08-ingestion-operational-receipt-deploy
```

La qualifica esegue unit test e tre cicli CLI reali per ciascuno store classic/containerd su Engine29.8.1 isolato: legacy esplicita, endpoint-only con legacy realmente presente, fallimento readiness senza rollback. Zero skip ammessi. Fixture con Python HTTP, rete interna, properties e chiave sintetiche: non è una prova del nuovo filtro Spring o della configurazione reale del VPS. Build separata: intera suite del commit fissato, immagine nonroot, scansione HIGH/CRITICAL senza bypass, JAR/migrazioni, archivio `docker save` compresso senza timestamp.

La build registra i digest risolti delle immagini base e il Dockerfile con FROM fissati per digest. Le dipendenze Maven/APK del Dockerfile upstream continuano a essere risolte durante la build: non è attestata una ricompilazione bit-per-bit. Il confine ripetibile del deploy è l'**archivio prodotto e verificato**, non una ricompilazione successiva sotto lo stesso tag. Una nuova build produce nuovi ID/hash da revisionare.

Scaricare solo l'artefatto della build verde e dello stesso commit deploy revisionato; leggere integralmente i log dei due job nativi e l'esito della scansione. ID run, ID immagine e manifest hash sono prodotti a runtime, quindi sono richiesti esplicitamente:

```bash
set -euo pipefail
read -r -p 'Run ID della build verde revisionata: ' ouf_build_run
gh run watch "$ouf_build_run" --repo GioNob/ouf-deploy --exit-status
ouf_download=$(mktemp -d /tmp/ouf-ingestion-receipt-artifact.XXXXXX)
gh run download "$ouf_build_run" --repo GioNob/ouf-deploy \
  --name "ingestion-operational-receipt-image-$ouf_build_run" --dir "$ouf_download"
(cd "$ouf_download" && sha256sum --check SHA256SUMS)
sha256sum "$ouf_download/manifest.json"
python3 - "$ouf_download/manifest.json" <<'PY'
import json,sys
m=json.load(open(sys.argv[1]))
print(json.dumps({k:m[k] for k in ('sourceCommit','deployCommit','imageIds','archiveSha256')},indent=2))
PY
read -r -p 'Destinazione SSH del VPS verificata: ' ouf_ssh_host
scp -r "$ouf_download" "$ouf_ssh_host:"
```

Confrontare `manifestSha256` con il summary della build fidata, non solo con SHA256SUMS nello stesso download. L'artefatto contiene immagine, manifest e bundle `scripts/` + helper `tools/`; non contiene dati del VPS. Per containerd selezionare il digest manifesto OCI dall'elenco, per classic il config ID; non inventare un ID e non riusare quello storico. Il launcher d'importazione controlla ID/revisione dopo il load; un errore richiede riconciliazione dell'import, non un apply.

## 2. Importazione sul VPS: launcher umano D-004

Questi comandi sono da eseguire dall'umano sul VPS; nessun SSH dal controller o dall'agente. Non ristampare credenziali. Il percorso bundle e gli hash dipendono dall'artefatto appena prodotto:

```bash
set -euo pipefail
read -r -p 'Directory assoluta del bundle verificato trasferito: ' ouf_bundle
cd -- "$ouf_bundle"
read -r -p 'SHA-256 manifest dal summary CI revisionato: ' ouf_manifest_sha
read -r -p 'ID candidato esatto dal manifest per questo store Docker: ' ouf_candidate_image
bash scripts/install-ingestion-operational-receipt-public-archive-20261112.sh \
  "$ouf_bundle" "$ouf_manifest_sha" "$ouf_candidate_image" /usr/bin/docker /run/docker.sock
sudo install -d -o root -g root -m 0700 /var/lib/ouf-ingestion-operational-receipt-20261112
```

Il launcher importa solo l'immagine, non tocca container. Anche binario e socket Docker dell'importazione sono parametri espliciti. Il bundle mantiene i byte LF del helper pubblicato: un checkout Windows CRLF non è un bundle installabile e fallisce il pin senza normalizzazioni del controller.

## 3. Piano e approvazione dell'hash

Nella stessa shell Bash:

```bash
ouf_common=(
  --container ouf-ingestion
  --expected-current-image sha256:562e4c6e19d5227f00fb3159deb506da256d2245ee4a40a652b0c03865704baa
  --expected-current-revision c85d9fd3be215e518dc6e7d075797720b5afbd91
  --candidate-image "$ouf_candidate_image"
  --properties-target /run/secrets/ingestion-summary.properties
  --docker-socket /run/docker.sock
  --nsenter-bin /usr/bin/nsenter
  --readiness-port 8080
  --readiness-path /actuator/health/readiness
  --readiness-timeout 120
  --stop-timeout 35
  --journal-root /var/lib/ouf-ingestion-operational-receipt-20261112
)
bash scripts/launch-ingestion-operational-receipt-20261112.sh --plan "${ouf_common[@]}" \
  | tee ingestion-receipt-plan.public.json
```

Atteso: `INGESTION_OPERATIONAL_RECEIPT_PLANNED`, `HUMAN_HASH_APPROVAL_REQUIRED`, `runtimeChanged:false`, delta di due campi, cinque presenze true, chiave valida/montata true e ID candidato atteso. Se HELD, conservare l'output e risolvere il motivo con review distinta. Non creare chiavi o modificare i properties per far passare il piano. Non è attualmente noto se le cinque chiavi esistano sul VPS.

L'umano revisiona il JSON e approva **quel preciso hash**. Il comando richiede l'hash trascritto dall'umano; non lo approva ricavandolo automaticamente dal piano:

```bash
read -r -p 'SHA-256 del piano esplicitamente approvato HUMAN: ' ouf_approved
[[ "$ouf_approved" =~ ^[a-f0-9]{64}$ ]]
python3 - "$ouf_approved" <<'PY'
import json,sys
p=json.load(open('ingestion-receipt-plan.public.json'))
assert p['status']=='INGESTION_OPERATIONAL_RECEIPT_PLANNED'
assert p['planSha256']==sys.argv[1]
PY
bash scripts/launch-ingestion-operational-receipt-20261112.sh --apply \
  --plan-sha256 "$ouf_approved" "${ouf_common[@]}" \
  | tee ingestion-receipt-result.public.json
```

## 4. Risultato e limiti

Sequenza unica: journal/claim → nuova lettura → STOP vecchio → controllo → DETACH → controllo MAC stretto → RENAME conservativo → CREATE → verifica → START gate → prova trap armata (child sleep) → USR1 → readiness entro timeout → verifica completa e vecchio conservato. Non ci sono LOAD nel controller, migrazioni SQL, rollback o ripetizioni delle mutazioni.

Atteso: exit 0, `INGESTION_OPERATIONAL_RECEIPT_READY`, immagine/revisione candidate, `summaryEnabled:true`, `mountsPreserved:true`, `environmentPreservedExceptSummaryEnabled:true`, `argumentsPreserved:true`, `addressMacAliasesPreserved:true`, readiness 200 e `oldRetainedStopped:true`. Il vecchio resta detached/spento, con nome originale + `-before-receipt-` + primi 16 caratteri dell'hash. Journal e log storici rimangono intatti.

HELD dopo STOP non ripristina nulla. La ricevuta include CID noti e osservazioni di stato disponibili, riferimento al journal e istruzione di riconciliazione. `runtimeChanged:null` significa esito dello stop incerto; diventa true appena lo stop è osservato, anche se un guard successivo fallisce. Un nuovo container può esistere anche senza ACK della CREATE: in quel caso riconciliare l'intento prima di qualunque comando. Non rilanciare apply, non rimuovere claim/journal e non usare gli installer storici.

Readiness e l'opt-in non provano ricevute APISIX, grant ACTIVE, risposta summary/incidents, ingestione 1024 o E2E. Queste prove restano distinte. Non viene attestato lo stato dei servizi esterni o la correttezza dei valori di identità effettivi, oltre ai controlli dichiarati sopra.

## 5. Ripristino manuale

Serve una decisione umana distinta dopo lettura di risultato e journal. Conservare il nuovo container, anche fallito, e impedire che due applicazioni siano attive contemporaneamente. Le informazioni private vanno lette da root con script che non ne stampino il contenuto. Non usare `cat plan.private.json` in un terminale registrato.

Prima di effetti, identificare nel journal gli ultimi intenti e gli ACK. Per un errore prima di CREATE, il vecchio può essere solo fermo, oppure fermo/detached/rinominato: ricollegare la rete soltanto se assente; rinominare soltanto se il vecchio ha il nome conservativo e quello originale è libero. Un intento CREATE senza `created-id.private.json` richiede riconciliazione manuale Docker, senza tentare un'altra CREATE.

Il seguente launcher umano copre **il caso con CREATE riconosciuta e sostituto presente**, incluso il ritorno dopo un deploy riuscito. Non è chiamato dal controller. Verifica vecchio/CID/configurazioni, ferma e conserva il candidato, trasferisce l'endpoint originale e riavvia il vecchio attraverso lo stesso gate. Se una precondizione differisce si ferma; non rilanciarlo dopo effetti parziali senza riconciliazione:

```bash
read -r -p 'Directory assoluta apply-HASH da ricevuta: ' ouf_attempt
sudo python3 -I -B - "$ouf_bundle" "$ouf_attempt" <<'PY'
import importlib.util,json,pathlib,sys,time
b=pathlib.Path(sys.argv[1]); w=pathlib.Path(sys.argv[2])
s=importlib.util.spec_from_file_location('restore',b/'scripts/apply-ingestion-operational-receipt-20261112.py')
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
p=json.loads(m.read(w/'plan.private.json')); old=p['old']; req=p['request']; params=p['parameters']
created=json.loads(m.read(w/'created-id.private.json'))['containerId']
e=m.Engine(params['docker_socket']); prior=e.inspect(old['Id']); new=e.inspect(created)
assert prior['State']['Running'] is False and prior['State']['Pid']==0
assert prior['Image']==old['Image'] and prior['State']['StartedAt']==old['State']['StartedAt']
assert prior['HostConfig']==old['HostConfig'] and m.mounts(prior)==m.mounts(old)
assert prior['Config']==old['Config'] or prior['Config']==m.mac_helper().detached_config(old)
assert new['Image']==req['Image'] and new['Id']!=old['Id'] and new['Name']==old['Name']
expected={k:v for k,v in req.items() if k not in ('HostConfig','NetworkingConfig')}
assert new['Config']==expected and new['HostConfig']==old['HostConfig'] and m.mounts(new)==m.mounts(old)
net,endpoint=next(iter(req['NetworkingConfig']['EndpointsConfig'].items()))
assert set(new['NetworkSettings']['Networks'])=={net}
assert prior['NetworkSettings']['Networks']=={}
assert prior['Name']==old['Name']+'-before-receipt-'+w.name[len('apply-'):][:16]
r=w/'manual-restore';r.mkdir(mode=0o700)
m.record(r,'stop-candidate-intent.private.json',{'containerId':created})
if new['State']['Running']:e.api('POST','/containers/'+created+'/stop?t='+str(params['stop_timeout']))
assert e.inspect(created)['State']['Running'] is False
m.record(r,'detach-candidate-intent.private.json',{'containerId':created})
e.api('POST','/networks/'+m.quote(net,safe='')+'/disconnect',{'Container':created,'Force':False})
m.record(r,'rename-candidate-intent.private.json',{'containerId':created})
e.api('POST','/containers/'+created+'/rename?name='+m.quote(old['Name'][1:]+'-failed-'+w.name[-16:],safe=''))
m.record(r,'connect-old-intent.private.json',{'containerId':old['Id']})
e.api('POST','/networks/'+m.quote(net,safe='')+'/connect',{'Container':old['Id'],'EndpointConfig':endpoint})
e.api('POST','/containers/'+old['Id']+'/rename?name='+m.quote(old['Name'][1:],safe=''))
m.record(r,'start-old-intent.private.json',{'containerId':old['Id']})
e.api('POST','/containers/'+old['Id']+'/start')
end=time.monotonic()+params['readiness_timeout']
while not m.gate_armed(e.inspect(old['Id'])):
    assert time.monotonic()<end
    time.sleep(.2)
assert m.process(e.inspect(old['Id']))==m.ENTRY+old['Config']['Cmd']
m.record(r,'usr1-old-intent.private.json',{'containerId':old['Id']})
e.api('POST','/containers/'+old['Id']+'/kill?signal=USR1')
from types import SimpleNamespace
a=SimpleNamespace(**params)
while not m.readiness(e.inspect(old['Id']),a):
    assert time.monotonic()<end
    time.sleep(.5)
restored=e.inspect(old['Id'])
assert restored['Config']==old['Config'] and restored['HostConfig']==old['HostConfig']
assert m.mounts(restored)==m.mounts(old) and m.process(restored)==old['Config']['Cmd']
ep=restored['NetworkSettings']['Networks'][net]
assert ep['IPAddress']==endpoint['IPAMConfig']['IPv4Address'] and ep['MacAddress']==endpoint['MacAddress']
assert set(ep.get('Aliases') or [])==set(endpoint['Aliases'])|{old['Id'][:12]}
assert e.inspect(created)['State']['Running'] is False
m.record(r,'complete.private.json',{'oldRestoredReady':True,'candidateRetainedStopped':True})
print('{"oldRestoredReady":true,"candidateRetainedStopped":true}')
PY
```

Questo percorso manuale non è qualificato dal ciclo del deploy e non ripristina dati DB: il task non modifica schema, ma il normale avvio applicativo può aver aggiornato dati. Per il caso senza CREATE riconosciuta, l'operatore deve ricostruire lo stato dai soli intenti completati e riusare l'endpoint nel piano privato; non assumere che ogni fase sia avvenuta. L'assenza di una ricevuta non prova l'assenza dell'effetto.

## Verifiche locali ripetibili

```bash
python3 -B -m unittest discover -s tests -p test_ingestion_operational_receipt_20261112.py -v
bash -n scripts/install-ingestion-operational-receipt-public-archive-20261112.sh
bash -n scripts/launch-ingestion-operational-receipt-20261112.sh
```

Su Windows sono stati eseguiti con il Python 3.8.19 già presente in LibreOffice e Bash di Git. I test caricano il helper puro dal checkout CRLF; il pin di consegna del controller non viene indebolito. I test nativi richiedono invece Linux/root e i job CI predisposti. Nessun accesso a rete esterna, VPS o segreti effettuato durante lo sviluppo.
