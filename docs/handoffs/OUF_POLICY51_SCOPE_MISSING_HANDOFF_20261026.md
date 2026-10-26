# OUF — policy51 HUMAN pubblicata; primo READ nega SCOPE_MISSING con versione51 — 26 ottobre 2026

## Stato preciso

La proposta **c1908145-5aa5-4dc4-a2fb-e8bf7ba5daf5**, revision1, è **PUBLISHED**,
finalPolicyRef **ouf-lab-authorization:51**, confermata da proposal.read STESSOID dopo la dichiarazione dell’owner.
PolicyHash **sha256:449d5629097730226841ca73a43c0d8cfa8068be5fcdbabc85e9b749f996ecea**.
[Prova completa delle verifiche e del diniego](../../evidence/acquisition-policy51-scope-missing-target-20261026.json).

ROLES/GRANTSfreschi verificati PRIMA READ:
4ruoli ESATTAMENTE come proposal,6assegnazioni, vecchie4 conservate integralmente incluse scadute,
nuove2nominali sugli stessi2ruoli e due runesatte.
106subjectconfiguredgrant/nextAfternull=94precedenti ESATTI+12nuovi6READ×2run, nessun altrogrant nuovo.
Constraints/subject/tenant/dates dei12nuovi verificati singolarmente contro i ruoli approvati.
Validità **26ottobre13:14:26→15:14:26Europe/Rome(CET)** =12:14:26→14:14:26Z.
Nessun reset/rinnovo dei vecchi grant o budgetfonte. Proposta consumata/pubblicata: NONriproporla.

UNA prima chiamata nel contesto51:
ouf.ingestion.acquisition.read/sourceIdteatri-csv-6609b245/runbb2e2af4-9c0a-49ea-8ad9-a947987c1472/
limit100/accountouf-admin/link_6aafef96b4148191b767e9af7b756a07.
Esito reale:
```json
{"code":"authorization denied","retryable":false,"authorizationPhase":"MCP_PRE_ADMISSION","reasonCode":"SCOPE_MISSING","evaluatedPolicyVersion":51}
```
ToolisErrortrue/connectorINVALID_ARGUMENT. NON HTTP403owner o nuova prova502.
Dopo primoDENY l’agente si è fermato: ZERO retry, ZERO UDPread, ZERO lettura seconda run.
Tre iniziali residue del piano4READ NON invocate. Nessun record acquisizione ottenuto.
Nessuna nuovaacquisizione/attivazione/grantproposal/RuntimeEngine/SQL/credenziale/Registrytouch in conseguenza del diniego.
Wirecounts interni non osservati; la fase pre-admission e il codice provano il guardprima dispatchowner, non un suo404/403.
Vecchie dueREAD negate a policy50 restano storia distinta, non sono state riaperte o confuse con questa nuova chiamata.

## Causa ora provata e limiti della diagnosi

MCP source9a374dd07745f059de3ad39757c68f02db6d29c3 è realmente installato con receiptpositivaVPS.
La diagnostica nuova funziona: la cache del guard ha valutato **51**, quindi NON affermare
che questa chiamata sia stata negata perché valutava ancora50.
SCOPE_MISSING è ora fatto live, non l’ipotesi dei vecchi handoff.
Da fonte PINNED primaria:
- internal/kernel/acquisition_read.go: preflightIngestion usa capability **ingestion.lineage.read**;
  preflightUDP sarebbe lineage.object.read, ma NON è stato eseguito;
- internal/authorization/cache.go:evaluate confronta principal.Scopes con descriptor.RequiredScope;
  SCOPE_MISSING precede l’esamegrant e admission/dispatch.
Descriptor ingestion.lineage.read pubblicato negli handoff49 ha requiredScopeomonimo.
Non dedurre assenza di tutti6scope da UNguard: è provata l’assenza dello scope richiesto dal guard Ingestion
nell’identità che arriva alMCP. Non è stato letto l’elenco scope completo o il JWT.
Non è noto se omissione avvenga nell’assegnazione/requestclient, emissione token, connessione ancora vecchia
o proiezioneGateway della delega. ClientID/configIAM/token attuali NON osservati.
Configuredgrant validi non sostituiscono OAuthscope, e scope non sostituisce ownergrant.

## Correzione minima preparata, NON applicata

[Piano concreto IAM/OAuth](../../evidence/acquisition-policy51-oauth-scope-correction-plan-20261026.json):
solo i6READ ingestion.run.read/ingestion.contract.read/ingestion.lineage.read/
urban.object.read/lineage.object.read/lineage.property.read sul clientHUMAN effettivo del connettore.
Nessuna nuova permissionadmin, nessunGrantOUF ulteriore, nessun intervento workload/Registry/Gatewayconfig.

Fonte di binding consultata integralmente: ouf-mcp-server9a
docs/INSTALLAZIONE_KEYCLOAK_CHATGPT.md (runbook aggiornato19settembre2026, STORICO).
Indica console https://auth.ouf-lab.it/admin/, realmouf, clientHUMANouf-chatgpt,
clientworkloadouf-mcp-server e deviceclientouf-human-admin DISTINTI.
**ouf-chatgpt è storico, NONdefault attuale**: verificare il client OAuth realmente configurato
nella connessioneouf-admin prima di leggere/modificare scope.
Non modificare il clientworkload odevice per aggiustare il tokenHUMAN.
Amministratore consoleIAM eouf-admin applicativo sono ruoli distinti; niente accountswitch implicito.

ContrattoKeycloak primario consultato:
https://www.keycloak.org/docs/26.5.7/server_admin/index.html
sezioni ClientScopes/Include in token scope/LinkclientScopes.
Verificare SOLO per i6nomi:
- esistenza nel realm e Include in token scope=On;
- assegnazione al solo clientHUMAN effettivo (Default applica al rilascio,
  Optional richiede scope esplicitamente richiesto dalla connessione);
- eventuali restrizioniRoleScopeMappings esistenti senza rimuoverle;
- mantenere audience/mappers/scopes/roles/security esistenti; niente RealmDefault o privilegiadmin.
Se serve aggiunta, solo delta READ mancante con reviewconcreta IAM.
Poi normale NUOVA autenticazioneHUMAN della connessione conouf-admin, mai bearer/secret/JWT incollato inchat.
Non assumere che il solo refresh di un vecchio token aggiunga scope.

Capacità disponibili: connettoreOUF espone ROLES/GRANTS/proposal, NON amministrazione clientKeycloak
o introspezionetoken. Una ricercaPluginManagement “Keycloak IAM OAuth administration”
non ha restituito integrazioniKeycloak pertinenti; non suggerire BigQuery/IAM noncorrelati.
PluginManagementget_app_permissions escludeOAuth: non usarlo come elenco ambiti o patch IAM.
Nessun browser inizializzato, nessuna credenziale letta e nessuna mutazioneIAM eseguita.
Passare alla consoleIAM nelbrowser richiede autorizzazione esplicita al fallback dal connettore.
Piano già concreto e pubblicato; non chiedere all’owner di cercare scope in una lista nonesposta.

## Ripresa dopo effettivo cambiamento contesto

Confermare deltaIAM/clientbind preciso e nuova autenticazioneHUMAN, senza esportare token.
Verificare che finestra51 sia ANCORA valida fino15:14:26CET, poi considerare UNA nuova
lettura bounded Ingestion per stessa run in contesto genuinamente cambiato.
Non ritentare semplicemente dopo attesa/cache-refresh/restart né chiamareUDP per aggirare il primoDENY.
Se scaduta, nessuna estensione/proposta automatica: nuovo mandatoHUMAN necessario.
Se nuovoSCOPE_MISSING: conservare reason/versione eSTOP, non reiterare reauth o allargare scope a caso.
Nessuna letturaapp/protected SQL/audit/rawlog/token come bypass del guard.
CAPABILITIES400 precedente resta NONritentato e origine nonprovata.

Solo quando letture permesse: DUErun esistenti bb2e2af4-9c0a-49ea-8ad9-a947987c1472
e a3208f2f-ebfd-415d-bddc-79ab05dea78f/sourceIdteatri-csv-6609b245/accountouf-admin.
Due toolacquisitionREAD,limit100/ownerCursor/<=1MiB12s.
Chiudere pincontratti/publication/ACKdurabile/watermark/intake/materializzazione/proprietàprovenienza,
13Teatri/11–19properties/union20IRI/8Cinema preservati secondo baseline disponibili.
Nessuna terzaacquisizione. E2E/G4/F5/F6 OPEN,SupervisorDOPOE2E,tecnico8/8funzionale4/6.
HTTP200GETRegistryoriginale resta prova precedente; non inventare chiusura502/403 o tokenconfig daCI.
Nessunmerge/releaseacceptance/attivazione/reset/Registryrestart/reinstall/bypass.

Leggere integralmente [handoff proposta ora pubblicata](OUF_POST_MCP_HUMAN_READ_PENDING_20261026.md)
e riferimenti precedenti: installazioneMCPpositiva,Memory0,scopeconsumati,PET/baseline.
Tutti comandiVPS/APPLY/capture/prep/recovery/reader consumati, nessun nuovo comandoVPS consegnato.
