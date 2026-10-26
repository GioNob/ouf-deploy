# OUF — continuazione cumulativa MCP con Memory=0 conservata — 26 ottobre 2026

## Punto esatto

Ultimo VPS: **RETAINED_MCP_HOST_POLICY_STOP_OBSERVED_NO_AUTHORITY**, complete=true, Exit0/DeliveryExit0,
[receipt](../../evidence/mcp-host-policy-zero-observed-target-20261026.json).
Nove file/120945byte, zero Engine/network/OAuth/SQL/chiavi/credenziali/acquisizioni/attivazioni/oldfilewrite.
RetainedOriginalCounts=2ownerConfigurationReads/0EngineGET/0EngineWrites;
retainedClaimsAndPinnedCodeProveNoRuntimeDispatch=true, retainedPreflightFileSetExact=true,
retainedHostPolicyCopyExact=true. currentRuntimeStateObserved=false, runtimeAuthorityIssued=false,
continuationAuthorized=false, E2E/releasefalse. Log dichiarato (non letto):
/home/oufadmin/ouf-mcp-host-policy-read-delivery.0q0y9bOT/bootstrap.log.
Scope reader /etc/ouf/deploy-snapshots/mcp-host-policy-stop-read-ff06ec1a-v1 CONSUMATO.

I tre campi conservati sono ORA provati:
AutoRemove presente/bool/false; Memory presente/int/0; OomKillDisable presente/NoneType/null.
Falliva SOLO memoryStrictlyPositive del guard9c0, non un drift del MAC.
Il reader conferma che la precedente APPLY STOP non inviò effetti; non osserva lo stato attuale del runtime.
Nessun risultato della NUOVA continuazione runtime sotto, nessuna nuova review/APPROVO/autorità ricevuti.

Leggere INTEGRALMENTE [handoff STOP e reader](OUF_MCP_HOST_POLICY_STOP_RECONCILIATION_20261026.md)
e tutti i suoi riferimenti, incluso [handoff prima APPLY](OUF_MCP_DIAGNOSTIC_UPDATE_APPLY_HANDOFF_20261026.md).
Comandi APPLY21ab e reader5fa sono ora STORICI/CONSUMATI; NON rilanciare o cancellare scope/code.
Preparazionea827/CURL5c26, catturafb4, vecchiAPPLY/recovery/installazione e pubblicazioni49/50 tutti consumati.
MCP9a candidato NON ancora provato installato; ultima installazione positiva sourcebd60...
Doppio incolla eventuale di una stessa receipt non crea una seconda esecuzione.

## Correzione e perimetro del nuovo mandato residuo

Codice **b9697462f293d7481c9fd7cdd84c549b70214eda**:
scripts/apply-mcp-diagnostic-update-20261026.py,
SHA256 **78376e1f83edfcd1651866d077347ac7e93aac25cd59c5e081f980e601d1afca**.
Consegna **11178c1ff09dd6eff18c909473a72bddd9635369**:
releases/apply-mcp-diagnostic-host-policy-continuation-20261026.sh,
SHA256 **a4760f0ff68fcf44fa4a810291a025f82338794cf339db99ec4f3154fda52f83**.
Manifest18fonti releases/mcp-diagnostic-host-policy-source-closure-20261026.json,
SHA256 **b8bae202a3222f014eab096e6e06c4f7339a655dabe351f3aea677f9acb30a50**.
CodeROOT nuovo /usr/local/lib/ouf-mcp-diagnostic-update-b8bae202a3222f01, dir0700/file0400,
fchmodFD prima fsync/checksumROOT; logruntime interno root0600 **codeROOT/operator.log**.
18fonti pubbliche pinned, nessun rebuild/relabel o vecchiaentrypoint importata.
Niente gh/timeout/installazione/riavvioDockerCLI/Registry. sudo INTERATTIVO diretto, SENZA pipe.
tee soltanto su bootstrap/copia NON interattivi. Logger conserva prima di scrivereTTY.

NUOVO child FISSO, NON riapertura del precedente journal:
**/etc/ouf/deploy-snapshots/mcp-diagnostic-update-ff06ec1afc5da65d-v1/retained-host-policy-continuation-v1**.
Il parent resta consumato con i3file originali intatti; aggiunge soltanto il nuovo child con prove proprie.
Precondizione chiusa: parent contiene ESATTAMENTE preparation-claim+2preflight-attempt e questo child,
NESSUNA review/authority/journal/dispatch/candidato. Una divergenza STOP, nessun suffisso alternativo.
Claim e massimi originali esatti; tentativi solo ownerConfigurationReads1/2.
Risultato reader root400 letto e verificato al suo SHA256 RAW:
**4975203b31db1db318aa8d81d09163153600ff2a738248ea2424fb45be6d4547**.
Schema/status/campi/contatori/noauthority/noeffects del reader devono coincidere; file originali/seals restano intatti.
Ogni nuova lettura ha claim PRIMA del dispatch; ciascuno dei4file di riconciliazione <=8KiB.

Le2 letture del vecchio preflight sono incluse da subito nei contatori del nuovo intento:
ownerConfigurationReads comincia da2, budget cumulativo resta64, non64+2.
Le9letture/120945byte del reader sono storia separata conservata nella review, NON azzerate o rieseguite.
Zero vecchiEnginewrite/import/health/signature. L’APPLY precedente non aveva review/mandato o lease900s emessi;
la nuova finestra segue SOLO il NUOVO consenso reale, nessuna autorità storica riusata.
Storie installazione306GET/22writes/3loads/83ownerConfig/2quarantena/8health/9adminGET/2PUT/3credfile,
cattura9GET/5file/65041byte e preparazione2file/1ZIP/1nativearchive rimangono in review, separate.

Conserva ESATTAMENTE Memory=0: nessun limite hard aggiunto al workload; AutoRemove=false e OomKillDisable=null conservati.
Guard distingue int0 da bool/missing/negative; per questo residuo pretende il profilo zero/null riconciliato.
Helper conserva anche profili intpositivi qualificati; NON rende equivalentiMemory0 e missing.
ResourcePolicyChanged=false esplicito. Budgets controller finiti non dipendono dal limite memoria workload.
Ammissione fresca host: almeno max(Memory,256MiB)+128MiB MemAvailable e512MiB+archive di spazio,
non modifica cgroup/limiti del MCP o degli altri processi.
Proiezione OOM null/false rinominata retainedMemoryBytes (non positiveMemoryBytes), senza riscrivere native-plan.
Prima/dopo CREATE/START/stop/detach/rename la verifica HostConfig resta esatta nei limiti nativi già qualificati.

## Input immutabili ed effetti consentiti

InputsHashfb4b7c9ae832e779192f1ff6e032e49c696752e182a57b8e9464f5a76000b3e4,
frozenPlanHashd1baf924e456bd5d2ce5a9bd3b8cb6f12ea80016feb76cde3c1556eec497a142,
nativePlanHashff06ec1afc5da65dc6b6c64edb9ab9ec87926f4a9de7aec355b69b96c4cd8653.
Nessuna ricattura o preparazione ripetuta; legge soltanto i due file pinned già preparati.
Nativeimage **sha256:9a1af5be94ff3dda4084b829e824482c5cf863525375c6f104a3fe89517e781e** containerd,
CIconfiguration **sha256:ffc78ca5e7fc1a1941cd4c4347d43e061df97d06c9fca44df0e8a5c47b5b839d**.
Source **9a374dd07745f059de3ad39757c68f02db6d29c3**, ouf-mcp-server draftPR79, ancora NON distribuito.
native.tar giàpresente nel preparatore, SHA256dafe0b0be9bf78717061923b1d1fe9feab2f01b81fd1e432a8b7a35a7677bcc3,
metadata/seals esatti. Artifact12633545900/run40284011851/ZIP6c31... custoditi nelle prove precedenti.
Non scambiare configID per nativeID. Una sola importazione tagless, nessun rebuild/relabel/tag.

Guard prima review e dopo consenso:7CID/generazioni/config/HostConfig/mounts/reti/processpins/boot,
Engine29.8.1/socketinode/peer/nativeprofilo, assenza nomeretained e unicità proprietario MAC,
authority pubblica/chiavi esistenti valide per tutta futura900+30.
Conserva IP/MAC correnti nominativi e porte host giàallocate, da snapshot dello stessoCID autenticato;
trasferimento SOLO dopo STOP/DETACH provati. Tutti altri endpoint/componenti invariati.
Mountbinding è provato, contenuti dei file montati NON attestati; nessuna fullOCI/E2E claim.

Profile pubblico esistente /etc/ouf/deploy-snapshots/semantic-creation-issuer-install-USjonf22/installation-authority-profile.json
SHA7fb7880d58e43ab40f9f53dac07a5dbad462d12e3a96f3b1287c6763b1d7ce18;
policy /etc/ouf/deploy-snapshots/semantic-trust-policy-preparation-20261004-172336/trust-policy.json
SHA21122630e52cb63c3744fee89f5c81ed926dad55231190243ca11be6d481bd42.
Ruoli installationouf-lab-netcup-01/entityouf-lab/installerouf-lab-infrastructure-installer/
attestorouf-lab-node-attestor. Nessuna nuova chiave/provisioning.
Metadatapubblici possono essere letti PRIMA consenso; chiaviprivate SOLO dopo APPROVO e fresca revalidazione.
Tre firme esistenti DEPLOYMENT_INTENT/FINAL_DEPLOYMENT_APPROVAL/CREATION_ATTESTATION,
max15dispatch lettura/verifica chiave helper+OpenSSL, non nuove chiavi/credenziali.
Firma finale verificata dentroinvocationfence PRIMA COMPLETE/result.json.

11stage invariati: VERIFY_CURRENT_ADMISSION,IMPORT_MCP,DISABLE_OLD_MCP_RESTART,STOP_OLD_MCP,
DETACH_OLD_MCP,RENAME_OLD_MCP,CREATE_MCP,START_MCP,VERIFY_MCP_READINESS,RESTORE_MCP_RESTART,VERIFY_FINAL.
Un SOLO nuovoMCP. Vecchio fermato/scollegato/rinominato/trattenuto fermo, mai riavviato o rimosso.
Quattro originali Gateway/Postgres/Ingestion/UDP e2READ preservati; Registry NON selezionato.
Zero GatewayadminGET/PUT/routechange, migrazioni, SQLbyrepair, appcredentialfile, grant, attivazioni/acquisizioni.
Normale SOLOMCP bootstrapOAuth/catalogomanifest può avvenire; richiesteworkload non contate dal repair.

## Review, budget, STOP e watchdog

Review PRIVATA nuova mostrata nel terminale; canonica VISIBILE/editabile Backspace/CtrlU.
Incollare ESCLUSIVAMENTE la riga APPROVO mostrata e premere Invio.
Hash precedente/ff06/4975 non sono l’approvazione. L’agente non inserisce consensi.
Scadenza concreta Europe/Rome e900s per input; correzione riga dentro STESSA scadenza/hash/contatori.
NoEnter/EOF/scadenza/cancellazione non autorizzano. Nessun loginIAM richiesto da questo passo.

Budget tecnici cumulativi:256EngineGET/10Enginewrite(compresi import+2negative)/1imageLoad/96readiness/
64ownerConfigurationReads(incluse2originali)/0serviceCredentialFileReads/0adminGET/0adminPUT/1quarantineStop.
DopoHUMAN900s +30sola quarantena. Startup180s,heartbeat10; health solo nuovo namespace/GET/health/ready,
64KiBbody; status401/403/sconosciuti STOP, transientonly0/502/503/504 finiti.
RisposteEngine<=2MiB/64MiBraw perpublisher, duepublisher controller+watchdog<=128MiB.
Claim/CAS prima dispatch, ricevuteRAW private prima parse/statusguard, PID nei nomi publisher per evitare collisionifork.
Effettoambiguo CLAIMED, nessun replay o rollback.
Watchdog ephemero pronto primaeffetti; perditaPID/startticks/scadenza può solo disabilitare restart e fermare
il SOLOnuovoMCP proprio configurazioneverificata, mai vecchio o6componenti/Registry.
Dopo arresto del vecchio un fallimento può lasciare MCP indisponibile fino a riconciliazione autorizzata.
SeSTOP conserva child/scope/log/contatori/ricevute e NON rilanciare; non scegliere nuovochild per aggirarlo.
Anche codeROOT esistente ferma la consegna. Se costruttorefallisce contextPath puòesserenull ma claim/log esistono.

## Qualifica finale

[Prova](../../evidence/mcp-zero-memory-continuation-qualified-20261026.json).
Push40314502686 ePR40314508940:6job ciascuno PASS/0skip, tutti12 log diretti letti.
11test rootcrypto/journal/risorse/cumulativi+6MACnegative.
Per OGNI backend Docker29.8.1 classic/containerd:5test,
4full lifecycle firmati (Memory128MiB e0, ciascuna con ConfigMAClegacy EXPLICIT eENDPOINT_COMPAT inizialmente PRESENTE),
più reale perdita controller dopoSTARTCLAIM conMemory0 e watchdogsolo nuovoMCP.
ZeroMemory verifica il childresiduo e contatorioriginali2 mantenuti; policy risorse eMAC/IP preservati,
6componenti eRegistryfixtureesterno invariati, vecchio fermo trattenuto, terzafirma primaCOMPLETE.
11casi TTY peruse_pty e!use_pty sul NUOVOprompt/logger, canonico/editabile+Enter,
log600/termios ripristinato/hash-contatoriimmutabili. InputCI sintetico+ulteriore ceiling2s,
NONconsenso production o finestra900s modificata.
Wrapper realeHTTP18fonti, PATHsenzaGH/timeout, sudoroot400/nonrootdenial e protectedmainTTYforeground;
fixtureclaim+2attempt+receipt9read esatti, poi SHA nativeplan volutamente errato STOP PRIMA HUMAN/key/Engine.
Prova consegna e guard, NONAPPLYVPS positiva.

Chiavi/identità/principal/policy/decisioni/workload CI sono ESCLUSIVAMENTE SINTETICI.
Docker/rootfilesystem/Ed25519/fork/processpins/sudo/TTY sono reali.
Workload nativo PythonHTTP, non realMCP OAuth/DBbootstrap. Prove immagini9a byte/import/unstartedconfig separate
negli handoff precedenti; non dichiarare avvio realproduct o E2E da queste fixture.
Sourceb969 inizialmente aveva probeTTY vecchia senza case/proposal del nuovo prompt: fixturecorretta11178,
runtimeimmutato; fallimentoCI conservato, nessun effettoVPS o autorizzazione.
PrimoAPPLY9c0 suVPS era il difetto Memorypositivo ora provato; vecchioverdeCI resta limitato, non riscritto.
Nessun risultato runtime della NUOVA continuazione ricevuto.

## Comando PRIMA esecuzione della NUOVA continuazione

Una volta sola come oufadmin, normale sudo; non pipeare il comando.
Nessun effetto prima della nuova review concreta e del suo APPROVO reale.

```bash
(
  set -Eeuo pipefail
  umask 077
  ouf_memory_apply_bootstrap=$(mktemp -d "$HOME/ouf-mcp-memory-continuation-bootstrap.XXXXXXXX")
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 3 --connect-timeout 15 --max-time 60 \
    "https://raw.githubusercontent.com/GioNob/ouf-deploy/11178c1ff09dd6eff18c909473a72bddd9635369/releases/apply-mcp-diagnostic-host-policy-continuation-20261026.sh" \
    -o "$ouf_memory_apply_bootstrap/run.sh"
  printf '%s  %s\n' 'a4760f0ff68fcf44fa4a810291a025f82338794cf339db99ec4f3154fda52f83' "$ouf_memory_apply_bootstrap/run.sh" | sha256sum -c -
  chmod 0400 "$ouf_memory_apply_bootstrap/run.sh"
  /usr/bin/bash "$ouf_memory_apply_bootstrap/run.sh"
)
```

Atteso MCP_DIAGNOSTIC_UPDATE_INSTALLED_E2E_NOT_ACCEPTED/complete=true/Exit0/DeliveryExit0,
source9a/nativeID9a1af5/componentReadinessProven=true/nuovi reviewHash-authorityHash/counts cumulativi.
Restituire SOLO JSONfinale/Exit/DeliveryExit/pathlog, non input/Env/config/review/logcompleti/token.
La receipt positiva del reader NON equivale ad APPLY positiva.

## Dopo una APPLY positiva realmente osservata

Registrare receipt/counters/attestazione. Policy50READ SCADUTA26ottobre09:24:50CET/08:24:50Z:
nessun rinnovo/proposta/retry automatici. Questa reviewNONautorizza acquisitioncalls.
ContestoHUMAN corrente e mandato finito per le soleDUErun esistenti:
bb2e2af4-9c0a-49ea-8ad9-a947987c1472 e a3208f2f-ebfd-415d-bddc-79ab05dea78f,
sourceIdteatri-csv-6609b245/accountouf-admin/link_6aafef96b4148191b767e9af7b756a07.
Tool ouf.ingestion.acquisition.read e urban.acquisition.read, limit100/solicursorowner/<=1MiB12s.
Nessuna terzaacquisizione. Correlare pincontratti/publication/durableACK/watermark/UDPintake/materialization/
propertyprovenance/13Teatri/11–19properties/union20IRI/8Cinema preservati entrobaseline disponibili.
Non inventare byteuguaglianza senza baseline, nuove prove502/403, causaDENY o scopeOAuth daCI.
HTTP200GEToriginaleRegistry giàprovato; E2E/G4/F5/F6 OPEN,tecnico8/8funzionale4/6.
Supervisor SOLO dopoE2E. Nessun merge/releaseacceptance/Registryrestart/reinstall/attivazione/reset.
