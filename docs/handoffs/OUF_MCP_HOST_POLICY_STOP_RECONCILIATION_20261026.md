# OUF — STOP prima della review del MCP: riconciliazione dei soli file conservati — 26 ottobre 2026

## Ultimo VPS e punto esatto

[Receipt](../../evidence/mcp-diagnostic-update-host-policy-stop-target-20261026.json):
STOP_RECONCILE / FINITE_RETAINED_MCP_HOST_POLICY_REQUIRED, complete=false, contextPath=null,
Exit2/DeliveryExit2. SourceClosure OK18, copie root0400.
Delivery /home/oufadmin/ouf-mcp-diagnostic-apply-delivery.eauzc3XE,
log /usr/local/lib/ouf-mcp-diagnostic-update-1c9bc1010621eb15/operator.log,
bootstrap /home/oufadmin/ouf-mcp-diagnostic-apply-delivery.eauzc3XE/bootstrap.log.
Sono percorsi riportati dall’operatore; l’assistente NON ha letto questi log privati.

La prima APPLY codice9c0/delivery21ab è stata eseguita ed è CONSUMATA, così il codeROOT e lo scopeFISSO
/etc/ouf/deploy-snapshots/mcp-diagnostic-update-ff06ec1afc5da65d-v1.
NON rilanciare il comando, NON cambiare path/suffisso, cancellare claim, azzerare contatori o fare rollback.
Nessuna review, APPROVO o nuova autorità runtime ricevuta; nessun risultato di installazione del candidato9a.

Il sorgente esatto eseguito, context.py:70, pretende:
AutoRemove esattamente False, Memory di tipo int e strettamente positiva.
La failure avviene dentro il costruttore Context, DOPO claim e due letture metadata,
PRIMA di creare il client Engine, validare autorità pubblica, preparare la review o firmare.
ctx=None in main spiega contextPath=null; NON dimostra assenza della directory/claim.
runtimeEffectsMayBePartial=true è il default generico del catch; NON una prova di effetti inviati.
Da ordine codice l’invocazione non può aver inviato Engine/OAuth/signature, ma questo NON osserva lo stato attuale del runtime.

Il test precedente imponeva128MiB: non qualificava Memory zero/default del profilo conservato.
NON è ancora provato quale congiunto del guard abbia fallito sul VPS. Non dichiarare Memory=0 come fatto.
Non aggiungere un limite memoria nuovo, normalizzare AutoRemove o togliere guard a tentativi.
Non rifare cattura/preparazione o IMPORT/CREATE per compensare.

Leggere integralmente [handoff APPLY precedente](OUF_MCP_DIAGNOSTIC_UPDATE_APPLY_HANDOFF_20261026.md)
e TUTTI suoi riferimenti; il comando APPLY lì è ora STORICO/CONSUMATO.
Rimangono i pin fb4(inputs), d1ba(frozenplan), ff06(nativeplan), nativeID9a1af5/source9a374dd0;
preparazione/CURL5c26/capturefb4/vecchia installazione306GET/22write e pubblicazioni49/50 tutti consumati.

## Passo concreto: solo riconciliazione delle prove conservate

NUOVO reader, non riavvio o continuazione del vecchio executor:
scripts/read-mcp-host-policy-stop-20261026.py, codice736a8d26bea92cef1af707f686da536970273529,
SHA256 e558c0c2ff2b80b1db91d24323e2c57af8126ab8fc1193fd245b6f2cf46d37ad.
Delivery5fa01d3fd0fa8ad1bb2970a2e0fb280d2f8c1079,
releases/read-mcp-host-policy-stop-20261026.sh,
SHA256 1b0301ac64da8108688c9342fc7d900d7b938ef5df9dda761ddebdbafa960f9a.
Source/codeROOT fisso /usr/local/lib/ouf-mcp-host-policy-stop-read-e558c0c2ff2b80b1/read.py,
root0400/dir0700/checksum ROOT/fchmod FD prima fsync.
Scope NUOVO e FISSO di SOLA lettura:
**/etc/ouf/deploy-snapshots/mcp-host-policy-stop-read-ff06ec1a-v1**.
Esistenza di scope/codeROOT => STOP, non cambiare directory o riprovare.
Scrive solo claim/readattempt/result propri; originali immutabili, nessun vecchio scope riscritto.

Limite30secondi, max9file e13MiB cumulativi:
3 sorgenti PUBBLICHE installate pinned (entry/context/manifest),
operator.log giàconservato <=64KiB,
preparation-claim e2file preflight-attempt (4KiB ciascuno),
native-plan.json rawSHAff06 e inputs.json rawSHAfb4 (<=6MiB ciascuno).
Elenco vecchio scope deve essere ESATTAMENTE claim+2attempt; qualsiasi review/authority/journal/dispatch o file aggiuntivo => STOP.
Le due sole attempt devono essere ownerConfigurationReads1 e2, non completion inventate.
Ogni nuova lettura ha claim prima del dispatch; rootancestry/nosymlink/nlink1/protectedmode/bytehashes/statseals verificati.
Unica uscita config: presenza/tipo/valore dei SOLI AutoRemove, Memory, OomKillDisable;
prova uguaglianza copia HostConfig rispetto a input/oldNative, senza stampare restoHostConfig, Env, pathmount o segreti.
Non trasferire logcompleti, plan, inputs, review, token o file privati.
Il checksum sorgenti e la forma dei retained claim confermano il percorso prima di effetti del codice esatto.
Non fanno Engineinspect e NON provano lo stato corrente di alcun container.

ZERO Engine/Gateway/owner/OAuth/IAM/SQL/credenziali/chiavifirma/acquisizioni/attivazioni/grant.
Non legge il contenuto di file applicativi montati, non riusa authority6147 o istanzia il vecchiocontroller.
Nessun login/review/APPROVO richiesto: normale sudo per leggere metadata protetti.
Nessuna nuova autorità o permesso di prosecuzione; E2E e release false.
Log non interattivo conservato da tee nel bootstraplog privato600; nessun gateHUMAN su pipe.

## Qualifica del reader (non risultato server)

[Prova](../../evidence/mcp-host-policy-stop-read-qualified-20261026.json).
Push40311327583/job121532950988 ePR40311337476/job121532986178:12test ciascuno PASS/0skip, log diretti letti.
Fixture filesystem ROOT con record ESCLUSIVAMENTE sintetici:
Memory zero/missing/bool/positive, AutoRemove, copiehost/immutabilitàoriginali/nessuna fugaBinds,
replay/bytehash/mode/symlink/duplicatedkey/journalmarker.
Wrapper effettivo scarica sorgente viaHTTPS pubblico pinned, esegue sudo/copiaroot400/verificaROOT/mainprotetto;
fixture volutamente priva di vecchia directory provocaSTOP PRIMA letture conservate.
Non prova che i nove file VPS abbiano la forma attesa o che il runtime sia immutato.
PrimoCI736a falliva perché fixture era nella checkout dell’utente runner; guardroot corretto,
spostata SOLOfixture sotto/var/lib rootowned, reader eguardimmutati. ErroreCI conservato, non serverSTOP.
Nessuna prima esecuzione VPS del nuovo reader ancora ricevuta.

## Comando prima esecuzione del SOLO reader

```bash
(
  set -Eeuo pipefail
  umask 077
  ouf_host_read_bootstrap=$(mktemp -d "$HOME/ouf-mcp-host-policy-read-bootstrap.XXXXXXXX")
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 3 --connect-timeout 15 --max-time 60 \
    "https://raw.githubusercontent.com/GioNob/ouf-deploy/5fa01d3fd0fa8ad1bb2970a2e0fb280d2f8c1079/releases/read-mcp-host-policy-stop-20261026.sh" \
    -o "$ouf_host_read_bootstrap/run.sh"
  printf '%s  %s\n' '1b0301ac64da8108688c9342fc7d900d7b938ef5df9dda761ddebdbafa960f9a' "$ouf_host_read_bootstrap/run.sh" | sha256sum -c -
  chmod 0400 "$ouf_host_read_bootstrap/run.sh"
  /usr/bin/bash "$ouf_host_read_bootstrap/run.sh"
)
```

Atteso: RETAINED_MCP_HOST_POLICY_STOP_OBSERVED_NO_AUTHORITY,complete=true,Exit0/DeliveryExit0,
hostPolicy/failedGuardChecks/retainedOriginalCounts=2metadata,0EngineGET,0write;
currentRuntimeStateObserved=false,continuationAuthorized=false.
Restituire SOLO JSONfinale/Exit/DeliveryExit/pathlog. STOP conserva prove, nessun rilancio.

## Dopo la lettura

Correggere solo sulla condizione osservata, conservare tutti i vecchi input/plan/hash/counters e lo scope consumato.
Memory zero(default senza limite) non significa budget del controller illimitato;
un eventuale limite MCP nuovo è modifica di policy e richiede review esplicita, mai un valore inventato dal test.
Se AutoRemove diverso o Memory non tipata, trattarlo come profilo distinto con prove/policy, non permissive fallback.
Ogni residuo runtime futuro richiede NUOVO mandato cumulativo e review concreta fresca dell’operatore;
nessuna esecuzione è autorizzata da questa riconciliazione e nessun nuovo comando APPLY è consegnato qui.

Qualificare il profilo esatto attraverso preparatore→executor→create/start→stop/detach→rename→replacement,
i backend classic/containerd e i frame MAC legacy inizialmente presenti; usare shared retained_mac.py.
Leggere integralmente docs/OUF_LEARNED_CONTAINER_MAC_INVARIANTS.md; non aggiungere ignore/null/empty globali.
Prima di consegnare, coprire l’esatto HostConfig conservato in CI e distinguere fixture da osservazioni VPS.

Policy50READ SCADUTA 26ottobre09:24:50CET/08:24:50Z, nessun rinnovo/proposta/retry automatico.
MCPsource bd60... resta ultima distribuzione positiva; candidato9a non provato installato.
Solo DUE acquisizioni esistenti bb2e2af4-9c0a-49ea-8ad9-a947987c1472 e a3208f2f-ebfd-415d-bddc-79ab05dea78f,
sourceIdteatri-csv-6609b245/accountouf-admin/link_6aafef96b4148191b767e9af7b756a07.
Nessuna nuovaREAD per diagnosticare DENY senza contestoHUMAN corrente e mandato finito.
E2E/G4/F5/F6 OPEN, Supervisor dopoE2E. Niente terzaacquisizione/attivazione/reset/Registryrestart/reinstall/merge/releaseacceptance.
