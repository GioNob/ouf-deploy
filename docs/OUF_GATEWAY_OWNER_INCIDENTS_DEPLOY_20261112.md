# Gateway incidents — collector e owner, 12 novembre 2026

Consegna locale, **qualifica GitHub e deploy non eseguiti**. Non è una ricevuta VPS.
I workflow devono passare ed essere revisionati prima dell'uso operativo. Nessuna
modifica di STATE, registro funzionale o checkpoint fa parte di questo task.

## Contratto e provenienza

A usa soltanto i byte di `tools/operational_incidents.py` di
`ouf-api-gateway@f60391301cd82465107d0884ec1ada67b78429d3`, SHA256
`cbc6ee191a85289efe57b8f0cd8c1d57c16bc3d9bd1910b7eeb8717581292854`.
La base richiesta è `1629652163edce7b3bc4c8f80bf29a3ef1b1ab8a`, file SHA256
`6afeb598905550acaceab75ef314eaf0f6de9a5f9508eb6ea71e943eb70f51d1`.
Il checkout deve essere pulito, compresi gli untracked non ignorati. A non fa
checkout/reset: dopo la sostituzione HEAD resta invariato e **quel file risulta
modificato**. Questa è la condizione attesa, non un motivo per rilanciare A.

B usa l'immagine archiviata da
`ouf-api-gateway@2a760ca90cf860a6dcae3eef536e87524aa0fa04` (include gli
aggiornamenti Spring/Jackson). Il workflow installa e testa il vendor SDK, esegue
`verify` del modulo owner, verifica il JAR copiato dall'immagine e scansiona
HIGH/CRITICAL, compresi gli unfixed. Un finding fa fallire l'archivio.
Base Temurin risolta per digest, Dockerfile risolto, hash JAR, tree sorgente,
commit deploy, ID immagine e hash archivio sono nel manifest/evidenze.
Le dipendenze Maven e la risoluzione iniziale della base restano operazioni della
build: il confine di ripetibilità è il bundle già prodotto, non una futura build
con lo stesso tag. Una nuova build richiede nuovi hash e review.

Nessuna label OCI di revisione è aggiunta: il predecessore ne è privo e i default
Docker aggiungerebbero una label al Config, violando il delta solo Image.
La provenienza è vincolata dal manifest approvato e dagli ID esatti importati;
B non deduce una revisione dal tag. Sono registrati anche gli ID config/manifest
OCI del salvataggio per il trasferimento fra store Docker.

Entrambi i controller importano soltanto primitive nominate del controller
Ingestion del 12 novembre, verificato per SHA256
`487798d53ae88ed0a0f31f4c62ed608a2403b4427a236efd61330bc2d93909eb`.
Non ne invocano il deploy, l'identità, le letture di chiavi o il gate USR1.
Il helper MAC conserva il suo pin
`cb5dbbee4a80ce71860dfe5d32362a662d98898c58fd82009e69c5eb6ac1f7ce`.
Questi due file storici sono inclusi senza modifiche nel bundle. La copia adattata
del compilatore CREATE e del ciclo operativo è necessaria per il delta solo
Image e l'avvio diretto dell'entrypoint. La fixture nativa deriva dalla stessa
catena Ingestion; la selezione Engine dei workflow è copiata dal suo workflow
di qualifica. Nessun vecchio claim o comando VPS viene riutilizzato.

## Piani, journal e verifiche

Tutti i dati d'installazione sono argomenti o osservazioni. `--plan` non scrive
file né Docker né SQL; Git usa `--no-optional-locks` e una `safe.directory`
limitata alla singola invocazione sul checkout confermato (owner oufadmin,
controller root), senza cambiare configurazioni Git globali. Non legge properties,
chiavi, file ENV o altri segreti. Le unità sono lette con proprietà selezionate;
i soli file di configurazione letti per hash sono fragment/drop-in delle due
unità, non gli EnvironmentFile referenziati. I comandi systemd sono confrontati
integralmente (path, argv, ignore_errors=no), esclusi solo i contatori/timestamp
di esecuzione. Un formato non riconosciuto o più ExecStart produce HELD.
Root esplicito, NeedDaemonReload=no, WorkingDirectory comune, servizio simple
active/running con Restart uguale a `--collector-restart` (sul VPS il 2026-11-12: `always`) e probe oneshot sono obbligatori.

Ogni apply ricalcola il piano, richiede il suo hash e lo ricontrolla prima del
primo effetto. Il journal padre deve esistere root:0700. `apply-HASH` esclusivo
0700, file 0600 con fsync, claim durevole per generazione impediscono replay e
due piani diversi sulla stessa generazione. I piani completi e gli inspect
restano privati nel journal; il JSON pubblico espone digest, booleani, ID e
conteggi, senza ENV o dati incidenti. Non pubblicare i file `*.private.json`.

A conserva i byte precedenti in `operational_incidents.py.before` (0600), scrive
un temporaneo nello stesso filesystem, conserva uid/gid/mode, esegue fsync,
rename atomico e fsync della directory. Poi riavvia il collector, attende
active/running con nuova InvocationID e riavvia il probe in modo sincrono.
La verifica SQLite apre `mode=ro`, in un'unica snapshot WAL: tabella, indice,
trigger insert/update, conteggio incidenti e copertura baseline devono esistere.
La baseline è la **prima transizione per ciascun incidente**; si verifica una
prima riga per ogni incidente presente. Il totale della storia può essere
maggiore se il collector aggiorna incidenti durante la verifica. Non vengono
stampati ID, proiezioni o righe. Nessuna migrazione SQL è eseguita dal controller:
è l'apertura del writer aggiornato a creare schema/baseline.

Mantenere attivo il writer di lunga durata: `-wal` e `-shm` sono necessari al
reader nonroot. Non copiare il solo `.sqlite`, non eliminare sidecar, non forzare
checkpoint, non usare `immutable=1`. Le verifiche non cambiano permessi dello
store. L'accessibilità al reader reale dipende anche dalle autorizzazioni già
installate, conservate da B; root mode=ro non prova da sola una lettura Java.

B si ferma prima dello stop se manca la tabella: il prerequisito pubblico è solo
un booleano, letto root `mode=ro`. Il percorso host deve corrispondere al percorso
container attraverso un bind read-only osservato. Tutto il frame/API è 1.44.
CREATE conserva Config, ENV ordinato, label, user, entrypoint, Cmd, mount,
HostConfig e vincoli; il solo delta Config è Image. IP/IPAM/MAC/alias sono
trasferiti dalla rete osservata. I default dell'immagine che allargherebbero il
delta sono rifiutati **prima** dello stop. Il profilo supportato è una sola rete
nominativa, restart=no e bind read-only. Un altro profilo è HELD.

MAC legacy deve essere presente/stringa/unicast/nonzero e coincidente con
l'endpoint all'origine e nel sostituto running. Solo sul vecchio fermo/PID0 e
detached il helper ammette l'assenza del campo; altri campi/generazione devono
restare esatti. Nessuna esclusione globale MAC. Nella sola osservazione CREATE
si conserva la tolleranza storica OomKillDisable null→false; running è esatto.
L'alias generato del nuovo CID si aggiunge agli alias conservati.
Il vecchio è conservato spento, detached e rinominato
`NOME-before-incidents-HASH16`.

La readiness usa host Python via `nsenter --net`: POST senza ricevuta e senza
Authorization, corpo `{}`, verso summary e incidents. Sono richiesti **403/403**;
404, 503, altri codici o timeout non superano il gate. Non vengono inviate
richieste autenticate o azioni business. Non c'è gate USR1.
Actuator **è presente** nel `pom.xml` candidato e
`management.endpoints.web.exposure.include=health` è in `application.properties`.
GET `/actuator/health` registra soltanto codice HTTP e status se disponibile con
200; anche DOWN/403/404/irraggiungibile sono informativi e non cambiano l'esito.
403/403 prova la superficie del filtro, non discovery, lettura con ricevuta o E2E.

I test CI coprono i guard HELD e SQLite reale (byte vecchi→nuovi, vecchie tabelle
invariate, riapertura idempotente, trigger insert/update). Il ciclo nativo prova
la sostituzione atomica A con observer systemd sintetico; non attesta systemd
del VPS. Per B usa Engine29.8.1 classic/containerd, origine legacy realmente
presente nei profili esplicito ed endpoint-only, stop/detach/rename/create/start,
readiness 403/403 e fallimenti 404/503 senza rollback, replay escluso, Actuator
DOWN informativo. Zero skip ammessi. L'owner HTTP sintetico prova il controller;
la suite Maven separata prova le classi Java del candidato.

## 1. CI, download e copia del bundle

Claude fa review/commit/push (D-001), non questo task. I workflow partono sulla PR.
Se già registrati nel branch predefinito, il lancio manuale è:

```bash
gh workflow run gateway-owner-incidents-archive-20261112.yml --repo GioNob/ouf-deploy --ref sprint-01/task-10-gateway-owner-incidents-deploy
gh workflow run gateway-owner-incidents-qualify-20261112.yml --repo GioNob/ouf-deploy --ref sprint-01/task-10-gateway-owner-incidents-deploy
gh run list --repo GioNob/ouf-deploy --branch sprint-01/task-10-gateway-owner-incidents-deploy
```

Leggere i log di entrambi gli store e build/scansione. Non installare con un job
rosso o senza qualifica dello stesso commit deploy revisionato. In Bash locale:

```bash
set -euo pipefail
read -r -p 'Run ID archivio verde revisionato: ' ouf_build_run
gh run watch "$ouf_build_run" --repo GioNob/ouf-deploy --exit-status
ouf_download=$(mktemp -d /tmp/ouf-gateway-incidents.XXXXXX)
gh run download "$ouf_build_run" --repo GioNob/ouf-deploy \
  --name "gateway-owner-incidents-image-$ouf_build_run" --dir "$ouf_download"
(cd "$ouf_download" && sha256sum --check SHA256SUMS)
sha256sum "$ouf_download/manifest.json"
python3 - "$ouf_download/manifest.json" <<'PY'
import json,sys
m=json.load(open(sys.argv[1]))
print(json.dumps({k:m[k] for k in ('sourceCommit','deployCommit','imageIds','archiveSha256')},indent=2))
PY
read -r -p 'Destinazione SSH VPS (utente@host): ' ouf_ssh_host
read -r -p 'Directory upload nuova sul VPS: ' ouf_remote_upload
scp -r -- "$ouf_download" "$ouf_ssh_host:$ouf_remote_upload"
```

Il path finale dipende da scp/directory scelta; confermarlo sul VPS. Accedere
manualmente al VPS. Nessun launcher di questo task esegue SSH. In una nuova Bash:

```bash
set -euo pipefail
read -r -p 'Directory upload effettiva: ' ouf_upload
read -r -p 'Directory bundle definitiva nuova, assoluta: ' ouf_bundle
read -r -p 'SHA256 manifest approvato dai log CI: ' ouf_manifest_sha
read -r -p 'ID immagine esatto compatibile con lo store, fra imageIds: ' ouf_candidate
printf '%s  %s\n' "$ouf_manifest_sha" "$ouf_upload/manifest.json" | sha256sum --check -
(cd "$ouf_upload" && sha256sum --check SHA256SUMS)
sudo test ! -e "$ouf_bundle"
sudo install -d -o root -g root -m 0755 "$ouf_bundle"
sudo cp -R --no-preserve=ownership,mode -- "$ouf_upload/." "$ouf_bundle/"
bash "$ouf_bundle/scripts/install-gateway-owner-incidents-public-archive-20261112.sh" \
  "$ouf_bundle" "$ouf_manifest_sha" "$ouf_candidate" /usr/bin/docker /run/docker.sock
```

Il launcher verifica manifest approvato, elenco esatto e hash di tutti gli
eseguibili/helper/file collector, SHA256SUMS e archivio, poi esegue soltanto
docker load e verifica l'ID. Non cambia container o servizi. Se l'ID cambia fra
store, scegliere l'ID attestato corrispondente dal manifest; non modificare il
manifest per farlo passare. Per un ID non attestato fermarsi e revisionare la
consegna, senza import ripetuti alla cieca. Una verifica read-only dopo import:

```bash
sudo env DOCKER_API_VERSION=1.44 /usr/bin/docker --config /nonexistent \
  --host unix:///run/docker.sock image inspect "$ouf_candidate" --format '{{.Id}}'
```

## 2. A — piano collector, approvazione e apply

Le aspettative installative seguenti provengono dal task e vanno riconfermate,
non sono osservazioni correnti. Leggere solo le proprietà necessarie:

```bash
sudo /usr/bin/systemctl show ouf-gateway-operational-collector.service ouf-gateway-etcd-probe.service \
  --no-pager --property=Id --property=User --property=Type --property=Restart \
  --property=WorkingDirectory --property=ExecStart --property=ActiveState --property=SubState --property=NeedDaemonReload
```

I comandi completi contengono opzioni omesse nel brief (`…`): non ricostruirle.
Confermare e incollare **solo il contenuto argv[]** delle rispettive ExecStart,
senza `{ path=... }` e senza timestamp. La stringa è confrontata integralmente;
quoting/escaping insolito è HELD e richiede review, non una semplificazione.

```bash
read -r -p 'ExecStart argv[] collector esatto confermato: ' ouf_collector_exec
read -r -p 'ExecStart argv[] probe esatto confermato: ' ouf_probe_exec
read -r -p 'Directory journal A nuova, assoluta: ' ouf_journal_a
sudo test ! -e "$ouf_journal_a"
sudo install -d -o root -g root -m 0700 "$ouf_journal_a"
ouf_a=(--checkout /opt/ouf/gateway-r3-summary
  --candidate-file "$ouf_bundle/collector/operational_incidents.py"
  --store /var/lib/ouf-gateway-operations/gateway-operations.sqlite
  --expected-commit 1629652163edce7b3bc4c8f80bf29a3ef1b1ab8a
  --collector-unit ouf-gateway-operational-collector.service
  --probe-unit ouf-gateway-etcd-probe.service
  --collector-exec-start "$ouf_collector_exec" --probe-exec-start "$ouf_probe_exec"
  --systemctl-bin /usr/bin/systemctl --git-bin /usr/bin/git
  --journal-root "$ouf_journal_a" --timeout 60)
bash "$ouf_bundle/scripts/launch-gateway-collector-incidents-20261112.sh" --plan "${ouf_a[@]}"
```

Leggere piano/digest, verificare il perimetro; l'umano approva quel `planSha256`.
Non estrarlo automaticamente per invocare apply:

```bash
read -r -p 'planSha256 A approvato dall’umano: ' ouf_a_sha
bash "$ouf_bundle/scripts/launch-gateway-collector-incidents-20261112.sh" \
  --apply --plan-sha256 "$ouf_a_sha" "${ouf_a[@]}"
```

Richiesto `GATEWAY_COLLECTOR_INCIDENTS_READY`, collectorActive=true,
baselineCount=incidentCount; transitionCount può essere maggiore. Conservare la
ricevuta pubblica e journal privato. Verifica aggiuntiva read-only:

```bash
sudo /usr/bin/systemctl is-active ouf-gateway-operational-collector.service
sudo sha256sum /opt/ouf/gateway-r3-summary/tools/operational_incidents.py
sudo env GIT_OPTIONAL_LOCKS=0 /usr/bin/git -c safe.directory=/opt/ouf/gateway-r3-summary \
  -C /opt/ouf/gateway-r3-summary status --short
```

## 3. B — piano owner, approvazione e apply

Proseguire solo dopo la ricevuta A riuscita. Il controller impone anche il gate
tabella; non modifica store, properties o ricevute APISIX per sbloccarlo.
Confermare ID attuale e stato con output limitato, senza inspect integrale:

```bash
sudo env DOCKER_API_VERSION=1.44 /usr/bin/docker --config /nonexistent \
  --host unix:///run/docker.sock inspect ouf-gateway-operational-owner \
  --format '{{.Id}} {{.Image}} {{.State.Running}}'
read -r -p 'Directory journal B nuova, assoluta: ' ouf_journal_b
sudo test ! -e "$ouf_journal_b"
sudo install -d -o root -g root -m 0700 "$ouf_journal_b"
ouf_b=(--container ouf-gateway-operational-owner
  --expected-current-image sha256:979de5eb0a554e0adfe924969627eb62362c4165974357afcee5bf30450f8f21
  --candidate-image "$ouf_candidate" --bundle-manifest "$ouf_bundle/manifest.json" --manifest-sha256 "$ouf_manifest_sha"
  --store /var/lib/ouf-gateway-operations/gateway-operations.sqlite
  --store-target /var/lib/ouf-gateway-operations/gateway-operations.sqlite
  --docker-socket /run/docker.sock --nsenter-bin /usr/bin/nsenter
  --summary-path /api/internal/v1/gateway/operations/summary
  --incidents-path /api/internal/v1/gateway/operations/incidents
  --actuator-path /actuator/health --readiness-port 8081
  --readiness-timeout 90 --stop-timeout 30 --journal-root "$ouf_journal_b")
bash "$ouf_bundle/scripts/launch-gateway-owner-incidents-20261112.sh" --plan "${ouf_b[@]}"
read -r -p 'planSha256 B approvato dall’umano dopo review del piano: ' ouf_b_sha
bash "$ouf_bundle/scripts/launch-gateway-owner-incidents-20261112.sh" \
  --apply --plan-sha256 "$ouf_b_sha" "${ouf_b[@]}"
```

Richiesto `GATEWAY_OWNER_INCIDENTS_READY`, delta Image, 403/403, vecchio conservato
spento e binding verificati. Il codice HTTP/status Actuator è soltanto informativo.
Il container mantiene anche le vecchie label; non cambiarle per simulare provenance.

## HELD e ripristino manuale

Ogni HELD conserva parziali e intenti. `runtimeChanged=false` significa prima
degli effetti; true significa effetto osservato; null significa invio/rename con
esito non ancora provato. Non cancellare claim, journal, sidecar o container e
non rilanciare apply. Le osservazioni pubbliche dopo uno stop incerto servono
alla riconciliazione, non autorizzano replay. Nessun rollback automatico.

Per A, dopo review di ricevuta/journal e della condizione corrente, l'umano può
ripristinare **il solo file** dal backup, verificato per hash originale. Non
serve revert dello schema additivo: il vecchio codice ignora la storia, ma dopo
il ripristino questa non è una prova del funzionamento incidents. Se B è già
installato coordinare prima il ripristino owner; non dichiarare incidents pronto.
Nella stessa shell, con i parametri A già confermati:

```bash
sudo python3 -I -B - "$ouf_journal_a/apply-$ouf_a_sha/operational_incidents.py.before" \
  /opt/ouf/gateway-r3-summary/tools/operational_incidents.py <<'PY'
import hashlib,os,pathlib,stat,sys,tempfile
backup,target=map(pathlib.Path,sys.argv[1:]); raw=backup.read_bytes()
assert hashlib.sha256(raw).hexdigest()=='6afeb598905550acaceab75ef314eaf0f6de9a5f9508eb6ea71e943eb70f51d1'
s=target.lstat(); assert stat.S_ISREG(s.st_mode)
fd,name=tempfile.mkstemp(prefix='.manual-incidents-restore-',dir=target.parent)
with os.fdopen(fd,'wb') as f:
    f.write(raw); os.fchown(f.fileno(),s.st_uid,s.st_gid); os.fchmod(f.fileno(),stat.S_IMODE(s.st_mode)); f.flush(); os.fsync(f.fileno())
os.replace(name,target)
fd=os.open(target.parent,os.O_RDONLY|os.O_DIRECTORY); os.fsync(fd); os.close(fd)
PY
sudo /usr/bin/systemctl restart ouf-gateway-operational-collector.service
sudo /usr/bin/systemctl restart ouf-gateway-etcd-probe.service
sudo /usr/bin/systemctl is-active ouf-gateway-operational-collector.service
```

Per B non esiste un comando universale sicuro: il fallimento può precedere stop,
detach, rename o CREATE e perfino avere una risposta Engine persa. L'umano legge
prima gli intenti/snapshot root-only nel journal e osserva i CID esatti con API1.44.
Se il candidato esiste, fermarlo e provare PID0 prima di trasferire l'endpoint;
scollegare soltanto il suo endpoint osservato. Solo dopo rete libera, ripristinare
nome e connessione del vecchio usando **IP/IPAM/MAC/alias/link/driver options del
piano privato**, quindi avviarlo e verificarne summary. La riconnessione Engine
del vecchio deve essere confrontata con quel frame, inclusa la forma MAC legacy;
non applicare al running l'eccezione del detached e non cancellare il candidato
o vecchio. Se l'effetto di CREATE/STOP è incerto, riconciliare prima di qualsiasi
altra mutazione. Questi valori e la fase sono prodotti a runtime: nessun comando
con CID/IP storici è presentato come ripristino eseguibile. Conservare tutti gli
artefatti e richiedere una review concreta del recupero necessario.

Per il solo caso già riconciliato **CREATE riconosciuta, sostituto ancora running
con nome/rete originari, vecchio retained fermo e detached**, questa è la
procedura manuale completa. Non è chiamata dai controller e non è qualificata
dal ciclo del deploy. Il blocco si ferma se manca una precondizione; non usarlo
per risolvere un ACK perso o una fase diversa. Riutilizza le variabili della
sessione B, senza inserire CID o indirizzi storici:

```bash
sudo python3 -I -B - "$ouf_bundle" "$ouf_journal_b/apply-$ouf_b_sha" <<'PY'
import importlib.util,json,pathlib,sys,time
from types import SimpleNamespace
bundle,work=map(pathlib.Path,sys.argv[1:])
spec=importlib.util.spec_from_file_location('manual_owner',bundle/'scripts/apply-gateway-owner-incidents-20261112.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
plan=json.loads((work/'plan.private.json').read_text()); approved=work.name.removeprefix('apply-')
assert m.digest(plan)==approved
assert m.sha((bundle/'scripts/apply-gateway-owner-incidents-20261112.py').read_bytes())==plan['controllerSha256']
old,req,params=plan['old'],plan['request'],plan['parameters']
created=json.loads((work/'created-id.private.json').read_text())['containerId']
engine=m.Engine(params['docker_socket']); new=engine.inspect(created)
retained=old['Name']+'-before-incidents-'+approved[:16]
m.c.detached(m.mac_helper(),old,engine.inspect(old['Id']),retained)
assert new['Id']!=old['Id'] and new['Name']==old['Name']
m.c.verify_replacement(old,req,new,True)
net,endpoint=next(iter(req['NetworkingConfig']['EndpointsConfig'].items()))
recovery=work/'manual-restore'; recovery.mkdir(mode=0o700)
m.c.fsync_dir(work)
m.c.record(recovery,'stop-candidate-intent.private.json',{'containerId':created})
engine.api('POST','/containers/'+created+'/stop?t='+str(params['stop_timeout']))
stopped=engine.inspect(created)
assert stopped['State']['Running'] is False and stopped['State']['Pid']==0
m.c.record(recovery,'detach-candidate-intent.private.json',{'containerId':created})
engine.api('POST','/networks/'+m.quote(net,safe='')+'/disconnect',{'Container':created,'Force':False})
assert engine.inspect(created)['NetworkSettings']['Networks']=={}
m.c.record(recovery,'rename-candidate-intent.private.json',{'containerId':created})
engine.api('POST','/containers/'+created+'/rename?name='+m.quote(old['Name'][1:]+'-failed-incidents-'+approved[:16],safe=''))
m.c.record(recovery,'connect-old-intent.private.json',{'containerId':old['Id']})
engine.api('POST','/networks/'+m.quote(net,safe='')+'/connect',{'Container':old['Id'],'EndpointConfig':endpoint})
m.c.record(recovery,'rename-old-intent.private.json',{'containerId':old['Id']})
engine.api('POST','/containers/'+old['Id']+'/rename?name='+m.quote(old['Name'][1:],safe=''))
m.c.record(recovery,'start-old-intent.private.json',{'containerId':old['Id']})
engine.api('POST','/containers/'+old['Id']+'/start')
args=SimpleNamespace(**params); deadline=time.monotonic()+params['readiness_timeout']
while True:
    restored=engine.inspect(old['Id'])
    assert restored['State']['Running'] is True
    if m.http_observation(restored,args,'POST',params['summary_path'])['httpStatus']==403:break
    assert time.monotonic()<deadline
    time.sleep(.25)
assert restored['Name']==old['Name'] and restored['Image']==old['Image']
assert restored['Config']==old['Config'] and restored['HostConfig']==old['HostConfig']
assert m.c.mounts(restored)==m.c.mounts(old) and m.c.process(restored)==[old['Path']]+old['Args']
assert set(restored['NetworkSettings']['Networks'])=={net}
ep=restored['NetworkSettings']['Networks'][net]
assert ep['IPAddress']==endpoint['IPAMConfig']['IPv4Address'] and ep['MacAddress']==endpoint['MacAddress']
assert ep.get('IPAMConfig')==endpoint['IPAMConfig']
assert set(ep.get('Aliases') or [])==set(endpoint['Aliases'])|{old['Id'][:12]}
assert engine.inspect(created)['State']['Running'] is False
m.c.record(recovery,'complete.private.json',{'oldRestoredSummary403':True,'candidateRetainedStopped':True})
print('{"oldRestoredSummary403":true,"candidateRetainedStopped":true}')
PY
```

Il ripristino conserva store e storia; non annulla incidenti o transizioni. Non
richiede 403 su incidents dal predecessore: quel JAR può tornare a 404 su quella
rotta. Conservare il candidato fermo e il nuovo journal manuale. Anche un errore
del blocco manuale richiede riconciliazione dei suoi intenti, senza replay.
