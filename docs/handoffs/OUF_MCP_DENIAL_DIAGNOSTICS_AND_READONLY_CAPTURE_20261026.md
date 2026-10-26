# Diagnosi MCP qualificata e nuova cattura di soli metadata — 26 ottobre 2026

> NEXT aggiornato: [nuova preparazione immagine+piano](OUF_MCP_DIAGNOSTIC_IMAGE_PLAN_PREPARATION_20261026.md), già qualificataCI. La cattura sotto resta CONSUMATA; nessun replay. Grant50READ scaduti alle09:24:50CET26ottobre.

## VPS ricevuto — cattura riuscita e scope CONSUMATO

L’operatore ha restituito MCP_DIAGNOSTIC_UPDATE_INPUTS_CAPTURED_NOT_AUTHORIZED, complete=true, Exit0/DeliveryExit0. InputsHash **fb4b7c9ae832e779192f1ff6e032e49c696752e182a57b8e9464f5a76000b3e4**; 9EngineGET/5privateMetadataReads/65041byte,4originali invariati e3componenti installati stessa generazione. Zero containerWrites/import/Gateway/OAuth/SQL/credenzialefile/chiavifirma/acquisizioni/attivazioni. Authority/continuation=false, scopesOAuth e bundleMCP NON osservati.
Prova esatta: [evidence/acquisition-mcp-denial-inputs-captured-target-20261026.json](../../evidence/acquisition-mcp-denial-inputs-captured-target-20261026.json).
Log dichiarato dall’operatore: /home/oufadmin/ouf-mcp-inputs-delivery.Rsmep8r0/bootstrap.log; il contenuto privato e inputs.json NON sono stati richiesti o letti dall’assistente.
Lo scope /etc/ouf/deploy-snapshots/mcp-denial-update-inputs-9a374dd07745f059-v1 è **CONSUMATO**. Il comando sotto è solo storia: NON rilanciare. Nessun risultato APPLY del nuovo aggiornamentoMCP esiste.
NEXT: staging dell’esatta immagine CI e identitànative classic/containerd, poi esecutore MCP-only qualificato e nuova reviewHUMAN concreta; nessun effetto autorizzato da questa receipt. Non usare vecchi controller o vecchie authority. GrantREAD50 conservano la scadenza09:24:50CET/08:24:50Z del26ottobre, senza rinnovo automatico.

## Punto di ripresa (storia prima della receipt)

La pubblicazione VPS dei descrittori è riuscita: policy49, 106 grant preservati, Exit0/DeliveryExit0. La proposta HUMAN64655de1-bf1e-4acd-aada-d2f27154539a è stata pubblicata dalla THS: policy50/hash067cb58da4e6f0278b5a81f4858646bb50222bb48e9cf63d3141621e9cfaf05f, 94grant subject (82precedenti identici +12READ vincolati),4ruoli/4assegnazioni con originali2ruoli/34permissionadmin/2assegnazioni invariati.
Le prime due READ distinte Ingestion/UDP sulla runbb2e2af4-9c0a-49ea-8ad9-a947987c1472 sono negate authorization denied/retryable=false. NON ritentate. Runa3208f2f-ebfd-415d-bddc-79ab05dea78f non invocata.
[Handoff precedente integrale](OUF_ACQUISITION_POLICY50_READ_DENIED_20261026.md) e sue prove restano vincolanti; la sua richiesta all'operatore di cercare una listaOAuth è superata: non chiedere dati non esposti senza percorso verificato.

UNA successiva capabilityouf.system.status/soloouf-admin restituisce MCP HEALTHY/actionRequiredfalse/partialfalse/PUBLIC_OPERATIONAL/redactedtrue.
Prova positiva limitata a quel percorso; NON prova scopeacquisition, bundle50 caricato o la causa dei due dinieghi. Nessun nuovo recordacquisizione ricevuto.
Nessuna lettura token/secret, nessun SQL/auditprivato/rawlog, grant ulteriore, acquisizione, attivazione, reset o restart. Le due aperture metadata OAuth PUBBLICHE tramite web non erano accessibili allo strumento: limite del lettore, non prova outage/HTTPstatus server.

Tutti i vecchi scopeAPPLY/recovery/pubblicazione e relative consegne sono CONSUMATI; mai rilanciarli. La nuova procedura sotto non esegue né importa alcuna vecchia entrypoint.

## Correzione prodotto qualificata, NON distribuita

[PR draft MCP79](https://github.com/GioNob/ouf-mcp-server/pull/79), branchfix/acquisition-denial-diagnostics-20261026, commit **9a374dd07745f059de3ad39757c68f02db6d29c3**.
Base165696a include il ripristino schemaHUMAN CAPABILITIES diPR78, anch'esso non ancora distribuito; rispetto a deployedbd60ccd cambia anche quel ramo dello schema del tool esistente. Non occultarlo in un futuro piano di aggiornamento.
MCP distribuito resta **bd60ccd092b51557b280e533c8db6b3f98842f9e**.

Il valutatore aveva già reasonCode/bundleVersion, ma Service/Kernel li riducevano al generico authorization denied. Nuovo typedAuthorizationDeniedError mantiene errors.Is(ErrUnauthorized), vecchia stringa e audit privato; SOLO due acquisitionREAD proiettano:
code originale, retryable=false, authorizationPhaseMCP_PRE_ADMISSION, reasonCode da allowlist e valutata policyversion positiva quando esiste.
Manca delega → DELEGATION_REQUIRED senza versione inventata; motivo sconosciuto → AUTHORIZATION_DENIED. Non espone subject/tenant/token/scopelist/grant/resource/bundleName/decisionRef/auditrows. Non cambia permessi, cache, ammissione, Gateway o owner.
Owner403 DOPO localALLOW resta risultatoowner, non errore locale. Nessuna nuova challengeOAuth/reautenticazione automatica o retry dal fix.
Questo è risultato ridotto del chiamante presente, non fullAuthorizationDecision congelata né capability di audit. Causa live attuale **NON provata**, SCOPE_MISSING solo ipotesi.

PEToriginali allegati hashe63df67e8817eec38a9d4b3eb736b020f693b932f3360dc02f4555330f2201ce riletti perdiagnostica: Authorization1.5§7 ALLOW/DENY+reasonCode+policyVersion,§27 logreason senza rawtoken/secret; schemaauthorization-decision-v1/policy-evaluation-evidence-v1 con scopecontrol. MCP1.4 e resilienza v3 restano vincolanti; nessuna dichiarazione di conformità totale da questa proiezione.
Read AGENTSMCPintegrale e policyv3. Nessun subagent usato. Il tipo di errore rimane permanente e non viene trasformato in retry.

Qualifica finale: push40284011794/jobs121443353291(format)+121443353576(SDK) ePR40284018756/jobs121443374131+121443373885, log diretti letti/0skip nei test selezionati.14scenari SDK per2tool, boundedprojection, metadata privati assenti,zeroAdmission/Gateway suDENY e auditcompatibili, più regressioni cache/READ.58PASSrecord/job includono ripetizioni delle regressioni, non58testdistinti.
Fullworkflow push40284011851/job121443353477 ePR40284018791/job121443373834 PASS, log diretti letti: SDK, Postgres/pairwise, Dockerbuild,staticcheck,govulncheck. Non inferire zero skip nonloggati nelle suite senza-v.
IAM/principal/policy/storia/owner CI sintetici. Non sono consenso né runtimeVPS.

Immagine push conservata come artifact **12633545900**, run40284011851/source9a374dd0.
ZIP SHA256 **6c31a1b5698942ddbb47b96ec1b49860c690c44aac8106beb1ca4b1ed7bba56a**;
image.tar.gz SHA256 **19fd036f973e52734d209d20671240f8973cd55d7183968ce605254b94cbd5bb**;
config imageID **sha256:ffc78ca5e7fc1a1941cd4c4347d43e061df97d06c9fca44df0e8a5c47b5b839d**;
manifestSHA256 **f2a6f20ff15969c068b87cbd15cf8485e5680f63123d60e90b58c7a09b7b37ae**.
ZIPdownload via connettore/zipdigestGitHub e tutti SHA256SUMS interni verificati; configdigest tar verificato,1manifest/4layer/23080448byte espansi. Nessun rebuild/relabel. Non pubblicare URLfirmate temporanee del download.
Il configdigest CI NON è automaticamente native runtimeID su Enginecontainerd. Selezione/derivazione/nativearchive/custodia sul profilo target sono ancora da preparare e qualificare, usandoimage_custody; niente falso binding o nuovaimmagine sulVPS.

## Nuovo passo necessario: catturare il MCP attuale senza modificarlo

Serve una configurazione corrente congelata per preparare una review concreta di SOLO aggiornamentoMCP. Non chiedere una conferma su un piano generico e non usare vecchi scriptrolloutconrollback automatico.
La preparazione qualificata sotto è read-only verso runtime: nessuna APPLY/APPROVO, login, chiavefirma, import, POSTEngine,stop/start/detach/rename/restart,credenzialefile,SQL/audit/logread,routePUT, fonte o acquisizione.

Runtime **6fc2aba137191411e4d22606957e0c4b24d687aa**,
scripts/prepare-mcp-denial-update-inputs-20261026.py,
SHA256 **909611450683cae6ac15cc41f2e4f86c7eaad6585830dd15961f51916446a9e4**.
Delivery **28db992823d90069192e0eb2bb1c4c90de961c8a**,
releases/prepare-mcp-denial-update-inputs-20261026.sh,
SHA256 **6e50d53c3772448e50b578817d29a46cf203250d42113975d30e37119e7e3461**.
Rootcopier fchmodFDprima fsync/checksumROOT; codice400/dir700 sotto
/usr/local/lib/ouf-mcp-denial-update-inputs-909611450683cae6/prepare.py.
Nuovo scope FISSO **/etc/ouf/deploy-snapshots/mcp-denial-update-inputs-9a374dd07745f059-v1**.
Fileclaim/risposte/inputs/result solo in questo nuovo scope root600/dir700; i Config.Env possono contenere configurazioni sensibili, mai stampati o pubblicati. I soli valori output sono contatori/hash/stati/identitàCIgiàpubbliche/percorsi.

Legge cinque file privati:
native-inputs5fa62..., capturedinputs del suo capturedInputsHash, result/review/recovery del SOLO detached-mcp-recovery-v1 installato.
Resultdigest esatto7a738f1d8b15baf7f1b9992919e348d19a60f2c54bd6a97ad6d6379c29c87045 e reviewc771... vincolano COMPLETE/16APPLIED/counter306EngineGET22writes ecc/authority6147... storica. Non riusa quell'autorità.
Hash dei byte esatti, non normalizzazione JSON; mode400/600/root/nlink1/ancestry e metadata-before-after/duplicatekeys verificati. Ogni lettura privata ha claim durevole PRIMA dell'open; originali non riscritti.
Poi soleGET al socket Engine ROOT giàpinned/peerrootesatto per/info e7CID esatti dalla storia:4originali(Gateway/Postgres/Ingestion/UDP) e3candidati installati(2READ+MCP).
Quattro originali richiedono stablebinding eprocesspin invariati;3candidati richiedono stessoCID/image/processgeneration della storia completata. Un'ultima GETMCP verifica stabilità durante cattura. Nessuna lista container, path arbitrario,logs/exec o fallback.
Nessun create/stop/detach/rename, né confronto di transizioneMAC: Config completo catturato/hashato e originali confrontati senza ignorareMAC. Un futuro lifecycle dovrà leggere docs/OUF_LEARNED_CONTAINER_MAC_INVARIANTS.md integralmente, usareprimivacomune e passare il gatelegacy completo classic/containerd; questi testdiGET non lo sostituiscono.
MCPmutableHostConfig è catturato per la FUTURA review, non già approvato per la sostituzione.

Budget NUOVO distinto per questa cattura: max10EngineGET/8filemetadata(perfile<=6MiB), perrispostaEngine2MiB/cumulativo20MiB,90scontroller. Positivo atteso9GET/5filemetadata.
Contatori installazione306GET/22writes/3loads/83ownerConfig/2quarantine/8health/9adminGET/2PUT/3fileadmin preservati ininputs, mai azzerati o trattati come budget nuovo.
Nessun nonce/scoponuovo può riaprire questi vecchi budget; nuova cattura è intento read-only specifico, non replay vecchia preparazione native5fa62... o acquisizioni.
Qualsiasi STOP/crash consuma anche questo scope. Conserva claim/response/log; niente rilancio o cambiochild.

[Qualifica](../../evidence/mcp-denial-diagnostics-capture-qualified-20261026.json):
push40287470611/job121454430366 ePR40287477086/job121454450598:9testprefix/custodia/immutabilità/counters +2native rootDockerGET/peer e copiacodice400/nonrootdenial PASS/0skip/logdirettiletti.
Docker7fixture reali/processpin reali/GET al veroEngine root, storia applicativa e workload Busybox esclusivamente sintetici. Non prova MCP/Gateway/IAM/datiVPS.
Il wrappercurl non è stato eseguito contro produzione; copier reale testato direttamente. Source/deliveryremote readback verificati.

## Comando STORICO CONSUMATO — NON eseguire

Non richiede APPROVO né loginIAM, soltanto normale sudo dell'operatore oufadmin.
Non aggiorna ilMCP o altri container. Risultato VPS positivo ricevuto sopra: scope consumato, NON eseguire di nuovo.

```bash
(
  set -Eeuo pipefail
  umask 077
  ouf_capture_bootstrap=$(mktemp -d "$HOME/ouf-mcp-capture-bootstrap.XXXXXXXX")
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 3 --connect-timeout 15 --max-time 60 \
    "https://raw.githubusercontent.com/GioNob/ouf-deploy/28db992823d90069192e0eb2bb1c4c90de961c8a/releases/prepare-mcp-denial-update-inputs-20261026.sh" \
    -o "$ouf_capture_bootstrap/run.sh"
  printf '%s  %s\n' '6e50d53c3772448e50b578817d29a46cf203250d42113975d30e37119e7e3461' "$ouf_capture_bootstrap/run.sh" | sha256sum -c -
  chmod 0400 "$ouf_capture_bootstrap/run.sh"
  /usr/bin/bash "$ouf_capture_bootstrap/run.sh"
)
```

Atteso **MCP_DIAGNOSTIC_UPDATE_INPUTS_CAPTURED_NOT_AUTHORIZED**,complete=true,Exit0/DeliveryExit0,
inputsHash/contextPath/counts; runtimeAuthorityIssued=false/continuationAuthorized=false/containerWrites0.
Restituire SOLO JSONfinale/Exit/DeliveryExit/percorsilog, non inputs.json/review/config/operator.log completi.
Se STOP: conservare e non rilanciare.

## Passi seguenti, senza anticipare autorità

Dopo receipt positiva e inputsHash: compilare stagingimmagine CI autenticata/nativeidentity per Engineprofilo e piano di SOLOMCPupdate su generazione osservata. Preparare/qualificare esecutore chiuso, backupfermo senza rollbackautomatico,1manager,networkbindingMAC esatto e vecchiworker/2READ/Gateway/Registry invariati. Nuovo scope e reviewHUMANconcreta con APPROVOhashFRESCO su riga VISIBILE/editabile, firmeinstallazione live solo dopo consenso, watchdog sui soli propri candidati, counters/lease fini e perdita/ambiguoCLAIMED senza replay. Nessun vecchiocontroller o suo budget riaperto.
**Non esiste ancora una consegna APPLY di questo aggiornamento**. Questa cattura non autorizza a crearne una saltando qualifica legacy/runtime/owner.
Non ritentare automaticamente le due READ negate per ottenere il nuovo messaggio; l'eventuale passo diagnostico successivo deve essere delimitato nella nuova review/mandato e verificare l'autorità corrente, senza grant o OAuthfittizi.

GrantHUMANREAD validi solo fino **26ottobre09:24:50CET (08:24:50Z)**. Non allungarli o ricreare proposta automaticamente se il tempo scade. Policy50 non è autorità permanente: controllare la finestra al momento delle future letture.
Scope/token effettivi e bundlelocale restano NON osservati; nessuna causaSCOPE_MISSING o cachevecchia retroprovata dalle CI.
Dopo eventuali letture positive:2runESISTENTI/sourceTeatri,contratti/CSV/publication/ACK/watermark/UDPintake/materialization/propertyprovenance/13identità/11–19property/unione20,8Cinema preservati nei limiti baseline. Niente terzaacquisizione o nuovaattivazione.
E2E/G4/F5/F6 OPEN; tecnico8/8funzionale4/6; Supervisor solo dopoE2E; nessun merge o releaseacceptance.
